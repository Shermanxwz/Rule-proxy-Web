from contextlib import contextmanager
import ctypes
import json
import os
from pathlib import Path
import secrets
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock
import uuid

from ruleproxy import launcher
from ruleproxy import windows_app_process as app_process
from ruleproxy import windows_appcontainer as container
from ruleproxy import windows_global_guard as G
from ruleproxy import windows_proxy_policy as policy
from ruleproxy import windows_proxy_service as service


OWNER = "S-1-5-21-1-2-3-1001"
PACKAGE = "S-1-15-2-1-2-3-4-5-6-7"
OTHER = "S-1-15-2-9-9-9-9-9-9-9"
NAME = container.container_name("app-1")


def owner_profile_diagnostics(api, name, expected_sid, owner_sid):
    """Only target-SID facts; these observations never grant admission."""
    rows = [(profile_name, owner) for profile_name, sid, owner in api.profiles() if sid == expected_sid]
    owned = [profile_name for profile_name, owner in rows if owner == owner_sid]
    return {'sid_seen': bool(rows), 'owner_matches': bool(owned),
            'name_exact': any(profile_name == name for profile_name in owned),
            'name_casefold': any(isinstance(profile_name, str) and profile_name.casefold() == name.casefold()
                                 for profile_name in owned),
            'derive_matches': any(isinstance(profile_name, str) and api.derive(profile_name) == expected_sid
                                  for profile_name in owned)}


class OwnerDiagnosticTests(unittest.TestCase):
    def test_case_only_observation_does_not_become_owner_qualification(self):
        api = mock.Mock()
        api.profiles.return_value = [(NAME.lower(), PACKAGE, OWNER), ('unrelated', OTHER, OWNER)]
        api.derive.return_value = PACKAGE
        facts = owner_profile_diagnostics(api, NAME, PACKAGE, OWNER)
        self.assertEqual(facts, {'sid_seen': True, 'owner_matches': True, 'name_exact': False,
                                 'name_casefold': True, 'derive_matches': True})
        self.assertTrue(all(type(value) is bool for value in facts.values()))
        api.profiles.return_value = [(NAME, PACKAGE, OWNER + '1')]
        self.assertEqual(owner_profile_diagnostics(api, NAME, PACKAGE, OWNER), {
            'sid_seen': True, 'owner_matches': False, 'name_exact': False, 'name_casefold': False, 'derive_matches': False})

    @unittest.skipUnless(os.name == 'nt' and os.environ.get('GITHUB_ACTIONS') == 'true',
                         'native profile diagnostic only on disposable Windows Actions')
    def test_native_own_profile_enumeration_diagnostic_without_network_changes(self):
        from ruleproxy.windows_proxy_client import current_user_sid
        api = container._get_api()
        name = 'RuleProxy.' + secrets.token_hex(10)
        created = False
        try:
            code, sid = api._owned_sid(api.userenv.CreateAppContainerProfile, name, name,
                                       'RuleProxy CI owner diagnostic', None, 0)
            self.assertEqual(code, 0, 'Only a newly created profile may be deleted by this diagnostic')
            created = True
            self.assertRegex(sid, container.PACKAGE_SID_RE)
            self.assertEqual(api.derive(name), sid)
            facts = owner_profile_diagnostics(api, name, sid, current_user_sid())
            self.assertEqual(set(facts), {'sid_seen', 'owner_matches', 'name_exact', 'name_casefold', 'derive_matches'})
            self.assertTrue(all(type(value) is bool for value in facts.values()))
            self.assertIn(sid, container.owner_profile_sids(current_user_sid(), api=api))
            print('::notice title=AppContainer owner diagnostic::' + json.dumps(facts, ensure_ascii=True, sort_keys=True),
                  flush=True)
        finally:
            if created:
                self.assertIsNone(api.delete(name))


class FakeEngine:
    def __init__(self, events, *, drop_filters=False):
        self.events, self.drop_filters = events, drop_filters
        self.filters = {}
        self.handle = None
        self.api = SimpleNamespace(FwpmProviderAdd0=self._provider, FwpmSubLayerAdd0=self._sublayer,
                                   FwpmFilterAdd0=self._add, FwpmFilterDeleteByKey0=self._delete)

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return None

    @contextmanager
    def transaction(self):
        self.events.append("begin")
        yield
        self.events.append("commit")

    @contextmanager
    def get(self, kind, key, _structure):
        yield self.filters.get(str(key)) if kind == "Filter" else None

    def _provider(self, _handle, value, _reserved):
        self.events.append("provider")
        return 0

    def _sublayer(self, _handle, value, _reserved):
        self.events.append("sublayer")
        return 0

    def _add(self, _handle, value, _reserved, _ident):
        rule = value._obj
        conditions = (G._Condition * rule.count)()
        keep = []
        for index in range(rule.count):
            conditions[index] = rule.conditions[index]
            if conditions[index].value.type == 11:
                data = ctypes.create_string_buffer(ctypes.string_at(conditions[index].value.value.pointer, 16))
                keep.append(data)
                conditions[index].value.value.pointer = ctypes.cast(data, ctypes.c_void_p)
        provider = G._GUID.of(rule.provider.contents.text())
        record = SimpleNamespace(display=SimpleNamespace(description=rule.display.description),
                                 key=G._GUID.of(rule.key.text()), provider=ctypes.pointer(provider),
                                 sublayer=G._GUID.of(rule.sublayer.text()), flags=rule.flags,
                                 action=SimpleNamespace(type=rule.action.type), weight=rule.weight,
                                 count=rule.count, conditions=conditions, layer=G._GUID.of(rule.layer.text()),
                                 _keep=keep)
        if not self.drop_filters:
            self.filters[rule.key.text()] = record
        self.events.append(("add", rule.action.type, rule.layer.text()))
        return 0

    def _delete(self, _handle, key):
        self.filters.pop(key._obj.text(), None)
        self.events.append("delete")
        return 0


class FakeAPI:
    def __init__(self, events, exempt=()):
        self.events = events
        self.exempt = list(exempt)
        self.stuck = False
        self.kernel = mock.Mock()

    def derive(self, name):
        self.events.append(("derive", name))
        return PACKAGE

    def profiles(self):
        return [(NAME, PACKAGE, OWNER)]

    def sid_text(self, _pointer):
        return PACKAGE

    def binary_sid(self, _sid):
        return ctypes.c_void_p(1234)

    def exemptions(self):
        return list(self.exempt)

    def set_exemptions(self, sids):
        self.events.append(("exempt", list(sids)))
        if not self.stuck:
            self.exempt = list(sids)


class GateTests(unittest.TestCase):
    def gate(self, *, drop_filters=False, exempt=()):
        self.events = []
        self.engine = FakeEngine(self.events, drop_filters=drop_filters)
        self.api = FakeAPI(self.events, exempt)
        patch = mock.patch.object(container, '_enum_filters', lambda engine: iter(engine.filters.values()))
        patch.start()
        self.addCleanup(patch.stop)
        return container.ContainerGate({"owner_sid": OWNER, "root": r"C:\RuleProxy"}, api=self.api,
                                       engine_factory=lambda: self.engine)

    def test_allow_commits_filters_before_loopback_exemption(self):
        gate = self.gate(exempt=[OTHER])
        result = gate.allow(NAME, 7890)
        self.assertEqual(result, {"container": NAME, "sid": PACKAGE, "proxy_port": 7890, "active": True})
        commit = self.events.index("commit")
        exempt = next(index for index, item in enumerate(self.events) if item[0] == "exempt")
        self.assertLess(commit, exempt)
        self.assertEqual(self.api.exempt, [OTHER, PACKAGE])
        actions = sorted((item[1], item[2]) for item in self.events if item[0] == "add")
        self.assertEqual(actions, sorted([(G._PERMIT, G._LAYERS[4]), (G._PERMIT, G._LAYERS[6]),
                                          (G._BLOCK, G._LAYERS[4]), (G._BLOCK, G._LAYERS[6])]))
        for record in self.engine.filters.values():
            self.assertEqual(record.flags, G._PERSISTENT)
            conditions = [(record.conditions[index].field.text(), record.conditions[index].value.type)
                          for index in range(record.count)]
            self.assertEqual(conditions[0], (container.PACKAGE_FIELD, 13))
            if record.action.type == G._BLOCK:
                self.assertEqual(record.count, 1)
                self.assertEqual(record.weight.value.u8, 0)
            else:
                fields = {field for field, _kind in conditions}
                self.assertEqual(fields, {container.PACKAGE_FIELD, G._FIELDS["protocol"],
                                          G._FIELDS["remote"], G._FIELDS["remote_port"]})
                self.assertEqual(record.weight.value.u8, 15)

    def test_allow_replaces_previous_rules_for_the_same_package(self):
        gate = self.gate()
        gate.allow(NAME, 7890)
        gate.allow(NAME, 7891)
        self.assertEqual(len(self.engine.filters), 4)
        self.assertEqual(self.events.count("delete"), 4)
        self.assertEqual(self.api.exempt, [PACKAGE])

    def test_incomplete_readback_never_opens_loopback(self):
        gate = self.gate(drop_filters=True)
        with self.assertRaises(policy.ProxyError):
            gate.allow(NAME, 7890)
        self.assertFalse([item for item in self.events if item[0] == "exempt"])

    def test_revoke_removes_exemption_before_filters_and_keeps_others(self):
        gate = self.gate(exempt=[OTHER])
        gate.allow(NAME, 7890)
        self.events.clear()
        gate.revoke(NAME)
        self.assertEqual(self.api.exempt, [OTHER])
        exempt = next(index for index, item in enumerate(self.events) if item[0] == "exempt")
        self.assertLess(exempt, self.events.index("delete"))
        self.assertEqual(self.engine.filters, {})

    def test_stuck_exemption_keeps_block_rules(self):
        gate = self.gate()
        gate.allow(NAME, 7890)
        self.api.stuck = True
        with self.assertRaises(policy.ProxyError):
            gate.revoke(NAME)
        self.assertEqual(len(self.engine.filters), 4)

    def test_foreign_rule_with_our_key_is_not_touched(self):
        gate = self.gate()
        key = str(gate._key(PACKAGE, 4, "block"))
        self.engine.filters[key] = SimpleNamespace(display=SimpleNamespace(description="other"),
                                                   key=G._GUID.of(key), provider=None,
                                                   sublayer=G._GUID.of(gate.sublayer), flags=G._PERSISTENT)
        with self.assertRaises(policy.ProxyError):
            gate.allow(NAME, 7890)
        self.assertIn(key, self.engine.filters)
        self.assertNotIn("commit", self.events)
        self.assertFalse([item for item in self.events if item[0] == "exempt"])

    def test_invalid_name_or_port_has_no_side_effects(self):
        gate = self.gate()
        for name, port in (("RuleProxy.bad", 7890), ("Other." + "0" * 20, 7890), (NAME, 80), (NAME, True)):
            with self.assertRaises(policy.ProxyError):
                gate.allow(name, port)
        self.assertEqual(self.events, [])

    def test_identity_requires_trusted_deployment(self):
        for metadata in ({}, {"owner_sid": "x", "root": "C:\\R"}, {"owner_sid": OWNER, "root": ""}):
            with self.assertRaises(policy.ProxyError):
                container.ContainerGate(metadata, api=mock.Mock())

    def test_profile_owner_is_verified_before_any_network_change(self):
        gate = self.gate()
        self.api.profiles = lambda: [(NAME, PACKAGE, OWNER + '1')]
        with self.assertRaises(policy.ProxyError):
            gate.allow(NAME, 7890)
        self.assertFalse(self.engine.filters)
        self.assertFalse(self.api.exempt)

    def test_purge_recovers_orphan_filters_without_a_remaining_profile(self):
        gate = self.gate(exempt=[OTHER])
        gate.allow(NAME, 7890)
        self.api.profiles = lambda: []
        result = gate.purge()
        self.assertEqual(result, {'active': False, 'purged_sids': [PACKAGE]})
        self.assertEqual(self.api.exempt, [OTHER])
        self.assertFalse(self.engine.filters)
        self.assertEqual(gate.purge(), {'active': False, 'purged_sids': []})

    def test_purge_keeps_foreign_filters_and_unproved_exemptions(self):
        gate = self.gate(exempt=[OTHER, PACKAGE])
        foreign = SimpleNamespace(provider=ctypes.pointer(G._GUID.of(uuid.uuid4())))
        self.engine.filters['foreign'] = foreign
        self.assertEqual(gate.purge(), {'active': False, 'purged_sids': []})
        self.assertEqual(self.api.exempt, [OTHER, PACKAGE])
        self.assertIs(self.engine.filters['foreign'], foreign)

    def test_changed_own_filter_aborts_purge_before_touching_exemptions(self):
        gate = self.gate(exempt=[OTHER])
        gate.allow(NAME, 7890)
        record = self.engine.filters[str(gate._key(PACKAGE, 4, 'proxy'))]
        record.conditions[1].value.value.u8 = 17
        before = list(self.api.exempt)
        with self.assertRaises(policy.ProxyError):
            gate.purge()
        self.assertEqual(self.api.exempt, before)
        self.assertEqual(len(self.engine.filters), 4)

    def test_stuck_exemption_purge_keeps_rules_and_can_be_retried(self):
        gate = self.gate()
        gate.allow(NAME, 7890)
        self.api.stuck = True
        with self.assertRaises(policy.ProxyError):
            gate.purge()
        self.assertEqual(len(self.engine.filters), 4)
        self.api.stuck = False
        self.assertFalse(gate.purge()['active'])
        self.assertFalse(self.engine.filters)

    def test_revoke_does_not_remove_a_foreign_exemption_without_own_rules(self):
        gate = self.gate(exempt=[PACKAGE, OTHER])
        self.assertFalse(gate.revoke(NAME)['active'])
        self.assertEqual(self.api.exempt, [PACKAGE, OTHER])


class NameAndEnvironmentTests(unittest.TestCase):
    def test_container_name_is_stable_opaque_and_valid(self):
        self.assertEqual(container.container_name("app-1"), NAME)
        self.assertNotEqual(container.container_name("app-2"), NAME)
        self.assertRegex(NAME, container.NAME_RE)
        with self.assertRaises(ValueError):
            container.container_name("")

    def test_environment_redirects_user_data_case_insensitively(self):
        with tempfile.TemporaryDirectory() as directory:
            env = container.container_environment(
                {"AppData": r"C:\Users\u\AppData\Roaming", "temp": r"C:\T", "PATH": r"C:\Windows"}, Path(directory))
            self.assertNotIn("AppData", env)
            self.assertNotIn("temp", env)
            self.assertEqual(env["PATH"], r"C:\Windows")
            self.assertEqual(env["APPDATA"], str(Path(directory) / "APPDATA"))
            self.assertEqual(env["TEMP"], env["TMP"])
            self.assertTrue(Path(env["LOCALAPPDATA"]).is_dir())

    def test_profile_candidates_require_actual_owner_name_and_derived_sid(self):
        api = mock.Mock()
        api.profiles.return_value = [(NAME, PACKAGE, OWNER), (NAME, OTHER, OWNER),
                                     (NAME, PACKAGE, OWNER + '1'), ('Other', PACKAGE, OWNER)]
        api.derive.return_value = PACKAGE
        self.assertEqual(container.owner_profile_sids(OWNER, api=api), {PACKAGE})
        with self.assertRaises(policy.ProxyError):
            container.owner_profile_sids('not-a-sid', api=api)

    def test_os_profile_name_accepts_only_ascii_case_equivalence(self):
        api = mock.Mock()
        api.derive.return_value = PACKAGE
        for name in (NAME, NAME.lower(), NAME.upper(), 'rUlEpRoXy.' + NAME.split('.')[1].upper()):
            api.profiles.return_value = [(name, PACKAGE, OWNER)]
            with self.subTest(name=name):
                self.assertEqual(container.owner_profile_sids(OWNER, api=api), {PACKAGE})
                api.derive.assert_called_with(name)
        # The request namespace remains strict even though OS readback differs.
        with self.assertRaises(policy.ProxyError):
            container._check_name(NAME.lower())

    def test_owner_sid_derived_sid_and_profile_boundaries_are_not_relaxed(self):
        api = mock.Mock()
        api.derive.return_value = PACKAGE
        for name, sid, owner in ((NAME.lower(), PACKAGE, OWNER + '1'),
                                  (NAME.lower(), 'S-1-5-18', OWNER),
                                  ('prefix' + NAME.lower(), PACKAGE, OWNER),
                                  (NAME.lower() + '.suffix', PACKAGE, OWNER),
                                  (NAME.lower() + '\0', PACKAGE, OWNER),
                                  ('RuleProx\u0443.' + 'a' * 20, PACKAGE, OWNER),
                                  ('RuleProxy.' + '\uff21' * 20, PACKAGE, OWNER)):
            api.profiles.return_value = [(name, sid, owner)]
            api.derive.reset_mock()
            with self.subTest(name=name, sid=sid, owner=owner):
                self.assertEqual(container.owner_profile_sids(OWNER, api=api), set())
                api.derive.assert_not_called()
        api.profiles.return_value = [(NAME.lower(), PACKAGE, OWNER)]
        api.derive.return_value = OTHER
        self.assertEqual(container.owner_profile_sids(OWNER, api=api), set())


class RequestTests(unittest.TestCase):
    def raw(self, **fields):
        request = {"schema_version": 1, "request_id": uuid.uuid4().hex, "client_pid": 101, **fields}
        return json.dumps(request).encode()

    def test_container_requests_are_strictly_validated(self):
        self.assertEqual(policy.decode_request(self.raw(op="container_allow", container=NAME,
                                                        proxy_port=7890))["proxy_port"], 7890)
        policy.decode_request(self.raw(op="container_revoke", container=NAME))
        for fields in ({"op": "container_allow", "container": NAME},
                       {"op": "container_allow", "container": NAME, "proxy_port": True},
                       {"op": "container_allow", "container": NAME, "proxy_port": 53},
                       {"op": "container_allow", "container": "Microsoft.Edge", "proxy_port": 7890},
                       {"op": "container_revoke", "container": NAME, "proxy_port": 7890}):
            with self.assertRaises(policy.ProxyError):
                policy.decode_request(self.raw(**fields))

    def test_broker_dispatches_only_for_the_installed_owner(self):
        gate = mock.Mock()
        gate.allow.return_value = {"active": True}
        gate.revoke.return_value = {"active": False}
        factory = mock.Mock(return_value=gate)
        broker = service.Broker({"root": r"C:\RuleProxy", "owner_sid": OWNER}, mock.Mock(),
                                mock.Mock(), mock.Mock(), container_factory=factory)
        request = {"op": "container_allow", "client_pid": 101, "container": NAME, "proxy_port": 7890}
        for pid, sid in ((102, OWNER), (101, OWNER + "1")):
            with self.assertRaises(policy.ProxyError):
                broker.handle(request, pid, sid)
        factory.assert_not_called()
        broker.panel = mock.Mock(pid=101)
        broker.core = mock.Mock(pid=102)
        broker.port = 7890
        self.assertEqual(broker.handle(request, 101, OWNER), {"active": True})
        gate.allow.assert_called_once_with(NAME, 7890)
        broker.handle({"op": "container_revoke", "client_pid": 101, "container": NAME}, 101, OWNER)
        gate.revoke.assert_called_once_with(NAME)
        factory.assert_called_once()


class LaunchFlowTests(unittest.TestCase):
    def run_flow(self, *, launch_error=None, read_grant_error=False, write_grant_error=False):
        events = self.events = []
        backend = mock.Mock()
        backend.container_allow.side_effect = lambda *args: events.append(("allow", *args))
        backend.container_revoke.side_effect = lambda *args: events.append(("revoke", *args))

        def grant(sid, path, *, write):
            events.append(("grant", write))
            if (write and write_grant_error) or (not write and read_grant_error):
                raise policy.ProxyError("appcontainer_access", "denied")

        def launch(command, env, cwd, **options):
            events.append(("launch", cwd, options))
            if launch_error:
                raise launch_error
            return "process"

        with tempfile.TemporaryDirectory() as directory, \
                mock.patch.object(container, "ensure_profile", return_value=PACKAGE), \
                mock.patch.object(container, "grant_access", side_effect=grant):
            command = [str(Path(directory) / "app" / "app.exe")]
            result = container.start_contained(backend, "app-1", command, {"PATH": "x"},
                                               profile=Path(directory) / "profile", proxy_port=7890, launch=launch)
        return events, result

    def test_gate_opens_before_confined_launch(self):
        events, (process, lease) = self.run_flow()
        self.assertEqual(process, "process")
        self.assertEqual([item[0] for item in events], ["grant", "grant", "allow", "launch"])
        self.assertEqual(events[2], ("allow", NAME, 7890))
        self.assertEqual(events[3][2], {"native_proxy_port": 7890, "container_sid": PACKAGE})
        lease.close()
        lease.close()
        self.assertEqual(events[-1], ("revoke", NAME))
        self.assertEqual(sum(1 for item in events if item[0] == "revoke"), 1)

    def test_failed_launch_closes_the_gate(self):
        with self.assertRaises(OSError):
            self.run_flow(launch_error=OSError("denied"))
        self.assertEqual([item[0] for item in self.events][-2:], ["launch", "revoke"])

    def test_failed_revoke_retains_lease_for_a_real_retry(self):
        backend = mock.Mock()
        backend.container_revoke.side_effect = [OSError('service unavailable'), {'active': False}]
        lease = container.ContainerLease(backend, NAME)
        with self.assertRaises(OSError):
            lease.close()
        self.assertEqual(lease.name, NAME)
        lease.close()
        lease.close()
        self.assertIsNone(lease.name)
        self.assertEqual(backend.container_revoke.call_count, 2)

    def test_system_program_directory_needs_no_grant(self):
        events, _result = self.run_flow(read_grant_error=True)
        self.assertIn("launch", [item[0] for item in events])

    def test_profile_grant_failure_never_opens_the_gate(self):
        with self.assertRaises(policy.ProxyError):
            self.run_flow(write_grant_error=True)
        self.assertEqual([item[0] for item in self.events], ["grant", "grant"])


class ValidationTests(unittest.TestCase):
    def app(self, **extra):
        return {"label": "App", "path": r"C:\Apps\app.exe" if launcher.sys.platform == "win32" else "/opt/app",
                "adapter": "environment", **extra}

    def test_windows_container_flag_is_boolean_and_exclusive(self):
        self.assertTrue(launcher.validate_app(self.app(windows_container=True), check_exists=False)["windows_container"])
        self.assertNotIn("windows_container", launcher.validate_app(self.app(), check_exists=False))
        with self.assertRaises(ValueError):
            launcher.validate_app(self.app(windows_container="yes"), check_exists=False)


class NativeBindingTests(unittest.TestCase):
    def test_profile_enumeration_always_releases_os_memory(self):
        api = object.__new__(container._ContainerAPI)
        api.firewall = mock.Mock()
        entries = (container._AppContainer * 1)()
        entries[0].name, entries[0].sid, entries[0].user = NAME, 1, 2
        def enumerate_profiles(_flags, count, result):
            ctypes.cast(count, ctypes.POINTER(ctypes.c_uint32))[0] = 1
            ctypes.cast(result, ctypes.POINTER(ctypes.POINTER(container._AppContainer)))[0] = entries
            return 0
        api.firewall.NetworkIsolationEnumAppContainers.side_effect = enumerate_profiles
        api.sid_text = lambda sid: {1: PACKAGE, 2: OWNER}[sid]
        self.assertEqual(api.profiles(), [(NAME, PACKAGE, OWNER)])
        api.firewall.NetworkIsolationFreeAppContainers.assert_called_once()
        api.sid_text = mock.Mock(side_effect=ValueError('invalid SID'))
        with self.assertRaises(ValueError):
            api.profiles()
        self.assertEqual(api.firewall.NetworkIsolationFreeAppContainers.call_count, 2)

    def native_filter_enumeration(self, count):
        api = mock.Mock()
        record = G._Filter()
        entries = (ctypes.POINTER(G._Filter) * 1)(ctypes.pointer(record))
        def create(_engine, _template, result):
            ctypes.cast(result, ctypes.POINTER(ctypes.c_void_p))[0] = 23
            return 0
        def enumerate_filters(_engine, _handle, _limit, result, length):
            ctypes.cast(length, ctypes.POINTER(ctypes.c_uint32))[0] = count
            ctypes.cast(result, ctypes.POINTER(ctypes.POINTER(ctypes.POINTER(G._Filter))))[0] = entries
            return 0
        api.FwpmFilterCreateEnumHandle0.side_effect = create
        api.FwpmFilterEnum0.side_effect = enumerate_filters
        api.FwpmFilterDestroyEnumHandle0.return_value = 0
        return SimpleNamespace(api=api, handle=11), entries

    def test_filter_enum_releases_page_and_handle_when_consumer_stops(self):
        engine, _entries = self.native_filter_enumeration(1)
        iterator = container._enum_filters(engine)
        self.assertIsInstance(next(iterator), G._Filter)
        iterator.close()
        engine.api.FwpmFreeMemory0.assert_called_once()
        engine.api.FwpmFilterDestroyEnumHandle0.assert_called_once()

    def test_filter_enum_rejects_oversize_page_before_dereferencing_entries(self):
        engine, _entries = self.native_filter_enumeration(257)
        with self.assertRaises(policy.ProxyError):
            list(container._enum_filters(engine))
        engine.api.FwpmFreeMemory0.assert_called_once()
        engine.api.FwpmFilterDestroyEnumHandle0.assert_called_once()

    def test_contained_create_process_uses_zero_capability_attribute(self):
        with mock.patch.object(ctypes, "WinDLL", create=True) as loader:
            kernel, advapi = mock.Mock(), mock.Mock()
            loader.side_effect = [kernel, advapi]
            api = app_process._KernelAPI()
        for function in (advapi.ConvertStringSidToSidW, kernel.InitializeProcThreadAttributeList,
                         kernel.UpdateProcThreadAttribute, kernel.CreateProcessW):
            function.return_value = 1
        api.create_process([r"C:\Apps\app.exe"], "A=b\0\0", r"C:\Apps", app_process._ProcessInfo(), PACKAGE)
        self.assertEqual(advapi.ConvertStringSidToSidW.call_args.args[0], PACKAGE)
        update = kernel.UpdateProcThreadAttribute.call_args.args
        self.assertEqual(update[2], 0x20009)
        capabilities = ctypes.cast(update[3], ctypes.POINTER(app_process._SecurityCapabilities)).contents
        self.assertEqual(capabilities.CapabilityCount, 0)
        self.assertFalse(capabilities.Capabilities)
        args = kernel.CreateProcessW.call_args.args
        self.assertFalse(args[4])
        self.assertEqual(args[5], app_process._CREATE_SUSPENDED | app_process._CREATE_UNICODE_ENVIRONMENT
                         | app_process._EXTENDED_STARTUPINFO_PRESENT)
        startup = ctypes.cast(args[8], ctypes.POINTER(app_process._StartupInfoEx)).contents
        self.assertEqual(startup.StartupInfo.cb, ctypes.sizeof(app_process._StartupInfoEx))
        self.assertTrue(startup.lpAttributeList)
        kernel.DeleteProcThreadAttributeList.assert_called_once()
        kernel.LocalFree.assert_called_once()

    def test_launch_rejects_non_package_sid_before_any_api(self):
        with mock.patch.object(app_process, "_get_api") as get_api:
            for sid in ("S-1-5-18", OWNER, PACKAGE + "\0", 5):
                with self.assertRaises(ValueError):
                    app_process.launch(["C:\\a.exe"], {}, container_sid=sid)
        get_api.assert_not_called()


if __name__ == "__main__":
    unittest.main()
