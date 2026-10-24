"""Work-only held-token LPAC semantics. No process launch or impersonation.

This module has no runtime CLI. NativeAPI is constructed only explicitly. An
external owner must hold the process/primary token, bind its image and Job,
enforce the original absolute deadline, and retain partial/unknown resources.
No TokenInformationClass46 query, network operation, or OS policy edit exists.
"""
from __future__ import annotations
import ctypes as C
import hashlib
import json
import os

PROFILE = 'chromium-four-descriptor-lpac-v1'
PIN = dict(repository='chromium/chromium', commit='fedbb89ecd801ed0ad1d34eb5784c3bb03a8534e',
    path='sandbox/win/src/app_container_test.cc', git_blob='d899e19da24b8f69ab1ffc1edcfb1e7b75ec9eb3',
    sha256='16968f8bb72d1fbc74c053dcb2f19de3c594a17b763cb56b47faab1cd496bda0')
WORLD, AAP, ARAP, SYSTEM = 'S-1-1-0', 'S-1-15-2-1', 'S-1-15-2-2', 'S-1-5-18'
LABELS = ('combined', 'world', 'aap', 'arap')
AC_ACES = ((WORLD, 3), (AAP, 1), (ARAP, 2))
ACES = dict(combined=AC_ACES, world=((WORLD, 3),), aap=((WORLD, 3), (AAP, 1)), arap=((WORLD, 3), (ARAP, 2)))
SDDLS = {k: 'O:SYG:SYD:' + ''.join('(A;;0x%x;;;%s)' % (mask, sid) for sid, mask in v) for k, v in ACES.items()}
EXPECTED = dict(ac=(3, 0, 1, 2), lpac=(2, 0, 0, 2))
IDENTITY_KEYS = {'sid', 'session_id', 'token_type', 'impersonation_level', 'appcontainer', 'appcontainer_sid',
    'integrity_rid', 'elevated', 'ui_access', 'capabilities', 'token_id', 'authentication_id'}
RESOURCE_KEYS = {'name', 'kind', 'attempted', 'creation_returned', 'returned', 'close_attempted', 'close_confirmed', 'close_uncertain', 'alias'}
CALL_KEYS = {'label', 'descriptor', 'descriptor_verified', 'attempted', 'api_success', 'win32_error', 'access_status',
    'granted_access', 'privilege_count', 'start_qpc', 'end_qpc', 'within_deadline'}
FAILURES = {'input', 'clock', 'process', 'open_token', 'source_identity', 'duplicate_token', 'duplicate_identity',
    'descriptor', 'access_check', 'mask', 'close', 'unexpected'}
MAXIMUM_ALLOWED = 0x02000000
TOKEN_QUERY, TOKEN_DUPLICATE = 8, 2
sha = lambda b: hashlib.sha256(b).hexdigest()
encode = lambda v: (json.dumps(v, sort_keys=True, separators=(',', ':'), ensure_ascii=True) + '\n').encode('ascii')


def require(ok, code):
    if not ok:
        raise ValueError(code)


def integer(v, lo=0, hi=0xffffffff):
    return type(v) is int and lo <= v <= hi


def digest(v):
    return type(v) is str and len(v) == 64 and all(c in '0123456789abcdef' for c in v)


def descriptor_expected(label):
    require(label in LABELS, 'descriptor')
    return dict(revision=1, control=0x8004, owner=SYSTEM, group=SYSTEM,
        owner_defaulted=False, group_defaulted=False, dacl_present=True, dacl_defaulted=False,
        aces=[dict(type=0, flags=0, mask=mask, sid=sid) for sid, mask in ACES[label]])


def identity(value, *, primary):
    identity_shape(value)
    require(type(value['sid']) is str and value['sid'].startswith('S-1-') and integer(value['session_id'])
        and type(value['appcontainer']) is bool and type(value['elevated']) is bool and type(value['ui_access']) is bool
        and integer(value['integrity_rid']) and integer(value['token_id'], 0, 0xffffffffffffffff)
        and integer(value['authentication_id'], 0, 0xffffffffffffffff), 'identity')
    require(value['appcontainer'] is True and type(value['appcontainer_sid']) is str
        and value['appcontainer_sid'].startswith('S-1-15-2-') and value['elevated'] is False
        and value['ui_access'] is False and value['integrity_rid'] == 4096, 'container_identity')
    require(value['token_type'] == (1 if primary else 2) and value['impersonation_level'] == (None if primary else 1), 'token_kind')
    caps = value['capabilities']
    require(type(caps) is list and len(caps) == 2 and all(type(e) is dict and set(e) == {'sid', 'attributes'}
        and type(e['sid']) is str and e['sid'].startswith('S-1-15-3-') and type(e['attributes']) is int
        and e['attributes'] == 4 for e in caps) and len({e['sid'] for e in caps}) == 2, 'capabilities')
    require(caps == sorted(caps, key=lambda e: e['sid']), 'capability_order')
    return value


def identity_shape(value):
    """Retain typed mismatches without treating them as a qualified identity."""
    require(type(value) is dict and set(value) == IDENTITY_KEYS, 'identity')
    require(type(value['sid']) is str and integer(value['session_id']) and integer(value['token_type'], 1, 2)
        and (value['impersonation_level'] is None or integer(value['impersonation_level'], 0, 3))
        and all(type(value[k]) is bool for k in ('appcontainer', 'elevated', 'ui_access'))
        and (value['appcontainer_sid'] is None or type(value['appcontainer_sid']) is str)
        and integer(value['integrity_rid']) and integer(value['token_id'], 0, 0xffffffffffffffff)
        and integer(value['authentication_id'], 0, 0xffffffffffffffff), 'identity_shape')
    require(type(value['capabilities']) is list and len(value['capabilities']) <= 64
        and all(type(e) is dict and set(e) == {'sid', 'attributes'} and type(e['sid']) is str
            and integer(e['attributes']) for e in value['capabilities']), 'identity_shape')
    return value


def duplicate_matches(source, duplicate):
    identity(source, primary=True)
    identity(duplicate, primary=False)
    return all(source[k] == duplicate[k] for k in IDENTITY_KEYS - {'token_type', 'impersonation_level', 'token_id'})


class ApiError(Exception):
    def __init__(self, operation, code):
        self.operation, self.code = operation, int(code)
        super().__init__(operation)


class _Owned:
    def __init__(self, api, name, kind, rows, live):
        self.api, self.value, self.live = api, None, live
        self.row = dict(name=name, kind=kind, attempted=False, creation_returned=False, returned=False,
            close_attempted=False, close_confirmed=False, close_uncertain=False, alias=False)
        rows.append(self.row)

    def begin(self):
        self.row['attempted'] = True

    def returned(self, value):
        self.row['creation_returned'] = True
        if value:
            self.value = int(value)
            self.row['returned'] = True
            key = (self.row['kind'], self.value)
            if key in self.live:
                self.row['alias'] = self.row['close_uncertain'] = True
            else:
                self.live.add(key)

    def close(self):
        if not self.row['creation_returned'] and self.row['attempted']:
            self.row['close_uncertain'] = True
        if self.value and not self.row['close_attempted'] and not self.row['alias']:
            self.row['close_attempted'] = True
            value, self.value = self.value, None  # consume before the API; never retry uncertain close
            try:
                ok = self.api.close_token(value) if self.row['kind'] == 'token' else self.api.free_descriptor(value)
                self.row['close_confirmed'] = ok is True
            except BaseException:
                self.row['close_confirmed'] = False
            self.row['close_uncertain'] |= not self.row['close_confirmed']
            self.live.discard((self.row['kind'], value))


def resources_clean(rows):
    return all(not r['close_uncertain'] and not r['alias'] and (not r['attempted'] or r['creation_returned'])
        and (not r['returned'] or r['close_attempted'] and r['close_confirmed']) for r in rows)


def observe_held(api, process, expected_primary_identity, *, expected_pid, expected_creation,
                 expected_role, frequency, deadline):
    """Read and duplicate ONLY an independently held process's primary token.

    expected_primary_identity is the owner's prior primary-token snapshot,
    including TokenStatistics.TokenId/AuthenticationId. It is not adapted to
    observed results. No token is assigned to a process/thread by this module.
    """
    r = dict(schema_version=1, stage='held-appcontainer-accesscheck', profile=PROFILE, source_pin=PIN.copy(),
        expected_role=expected_role, expected_primary_identity_sha256=sha(encode(expected_primary_identity)),
        process_id=expected_pid, process_creation=expected_creation, frequency=frequency, deadline_qpc=deadline,
        start_qpc=None, end_qpc=None, generation_before=False, generation_after=False,
        source_primary=None, duplicate=None, source_identity_bound=False, duplicate_identity_bound=False,
        calls=[], resources=[], resource_cleanup_verified=False, observation_complete=False,
        qualified=False, classification='unknown', failure=None, error=None,
        token_class46_queried=False, process_or_thread_impersonation_applied=False, network_tested=False,
        dns_tested=False, product_acceptance=False)
    live = set()
    source = _Owned(api, 'source-primary', 'token', r['resources'], live)
    duplicate = _Owned(api, 'duplicate-identification', 'token', r['resources'], live)
    phase = 'input'

    def tick():
        v = api.qpc()
        require(integer(v, 1, 0x7fffffffffffffff) and v < deadline, 'clock')
        return v

    try:
        identity(expected_primary_identity, primary=True)
        require(expected_role in EXPECTED and integer(process, 1, 0xffffffffffffffff)
            and integer(expected_pid, 1) and integer(expected_creation, 1, 0x7fffffffffffffff)
            and integer(frequency, 1, 1000000000) and integer(deadline, 1, 0x7fffffffffffffff), 'input')
        phase = 'clock'
        require(api.frequency() == frequency, 'clock')
        r['start_qpc'] = tick()
        require(deadline - r['start_qpc'] <= 120 * frequency, 'clock')
        phase = 'process'
        require(api.verify_process(process, expected_pid, expected_creation) is True, 'process')
        r['generation_before'] = True
        phase = 'open_token'; tick(); source.begin()
        ok, handle, error = api.open_token(process, TOKEN_QUERY | TOKEN_DUPLICATE)
        source.returned(handle)
        if not ok or not handle:
            raise ApiError('OpenProcessToken', error)
        phase = 'source_identity'; tick()
        r['source_primary'] = api.identity(handle)
        identity(r['source_primary'], primary=True)
        require(r['source_primary'] == expected_primary_identity, 'source_identity')
        r['source_identity_bound'] = True
        phase = 'duplicate_token'; tick(); duplicate.begin()
        ok, handle, error = api.duplicate_token(source.value, TOKEN_QUERY, 1, 2)
        duplicate.returned(handle)
        if not ok or not handle:
            raise ApiError('DuplicateTokenEx', error)
        require(not duplicate.row['alias'], 'duplicate_token')
        phase = 'duplicate_identity'; tick()
        r['duplicate'] = api.identity(handle)
        require(duplicate_matches(r['source_primary'], r['duplicate']), 'duplicate_identity')
        r['duplicate_identity_bound'] = True
        for label, expected in zip(LABELS, EXPECTED[expected_role]):
            phase = 'descriptor'
            call = dict(label=label, descriptor=None, descriptor_verified=False, attempted=False,
                api_success=None, win32_error=None, access_status=None, granted_access=None, privilege_count=None,
                start_qpc=None, end_qpc=None, within_deadline=False)
            r['calls'].append(call)
            sd = _Owned(api, 'descriptor-' + label, 'descriptor', r['resources'], live)
            try:
                tick(); sd.begin()
                ok, pointer, error = api.create_descriptor(SDDLS[label])
                sd.returned(pointer)
                if not ok or not pointer:
                    raise ApiError('ConvertStringSecurityDescriptorToSecurityDescriptorW', error)
                require(not sd.row['alias'], 'descriptor')
                call['descriptor'] = api.describe_descriptor(pointer)
                observed = {k: v for k, v in call['descriptor'].items() if k not in ('bytes', 'sha256')}
                require(observed == descriptor_expected(label) and integer(call['descriptor']['bytes'], 20, 4096)
                    and digest(call['descriptor']['sha256']), 'descriptor')
                call['descriptor_verified'] = True
                phase = 'access_check'; call['start_qpc'] = tick(); call['attempted'] = True
                ok, status, granted, privileges, error = api.access_check(pointer, duplicate.value, MAXIMUM_ALLOWED, (0, 0, 0, 0))
                require(type(ok) is bool, 'access_check')
                call['api_success'] = ok
                if ok:
                    require(type(status) is bool and integer(granted) and integer(privileges, 0, 64), 'access_check')
                    call.update(access_status=status, granted_access=granted, privilege_count=privileges)
                else:
                    require(integer(error), 'access_check')
                    call['win32_error'] = error  # other output bytes are INVALID on API failure
                call['end_qpc'] = api.qpc()
                call['within_deadline'] = (integer(call['end_qpc'], 1, 0x7fffffffffffffff)
                    and call['start_qpc'] <= call['end_qpc'] < deadline)
                if not ok:
                    raise ApiError('AccessCheck', error)
                require(call['within_deadline'], 'clock')
                require(privileges == 0 and granted == expected and status is bool(expected), 'mask')
            finally:
                sd.close()
            require(not sd.row['close_uncertain'], 'close')
        phase = 'process'; tick()
        require(api.verify_process(process, expected_pid, expected_creation) is True, 'process')
        r['generation_after'] = True
        phase = 'source_identity'; tick()
        require(api.identity(source.value) == expected_primary_identity, 'source_identity')
    except BaseException as exc:
        code = str(exc) if type(exc) is ValueError else phase
        r['failure'] = code if code in FAILURES else phase if phase in FAILURES else 'unexpected'
        if isinstance(exc, ApiError):
            r['error'] = dict(operation=exc.operation, win32_error=exc.code)
    finally:
        duplicate.close(); source.close()
        r['resource_cleanup_verified'] = resources_clean(r['resources'])
        if not r['resource_cleanup_verified']:
            r['failure'] = r['failure'] or 'close'
        try:
            r['end_qpc'] = api.qpc()
        except BaseException:
            r['end_qpc'] = None
        if r['start_qpc'] is None or not integer(r['end_qpc'], r['start_qpc'] or 1, deadline - 1):
            r['failure'] = r['failure'] or 'clock'
    r['observation_complete'] = (len(r['calls']) == 4 and all(c['descriptor_verified'] and c['api_success'] is True
        and c['within_deadline'] for c in r['calls']) and r['generation_before'] and r['generation_after']
        and r['source_identity_bound'] and r['duplicate_identity_bound'] and r['resource_cleanup_verified'])
    r['qualified'] = r['observation_complete'] and r['failure'] is None
    if r['qualified']:
        r['classification'] = expected_role + '-semantic-match'
    validate_proof(r, expected_primary_identity=expected_primary_identity, expected_role=expected_role,
        expected_pid=expected_pid, expected_creation=expected_creation, frequency=frequency, deadline=deadline)
    return r


def validate_proof(r, *, expected_primary_identity, expected_role, expected_pid, expected_creation, frequency, deadline):
    keys = {'schema_version', 'stage', 'profile', 'source_pin', 'expected_role', 'expected_primary_identity_sha256',
        'process_id', 'process_creation', 'frequency', 'deadline_qpc', 'start_qpc', 'end_qpc', 'generation_before', 'generation_after',
        'source_primary', 'duplicate', 'source_identity_bound', 'duplicate_identity_bound', 'calls', 'resources',
        'resource_cleanup_verified', 'observation_complete', 'qualified', 'classification', 'failure', 'error',
        'token_class46_queried', 'process_or_thread_impersonation_applied', 'network_tested', 'dns_tested', 'product_acceptance'}
    require(type(r) is dict and set(r) == keys and type(r['schema_version']) is int and r['schema_version'] == 1
        and r['stage'] == 'held-appcontainer-accesscheck' and r['profile'] == PROFILE and r['source_pin'] == PIN, 'proof_schema')
    require(r['expected_role'] == expected_role and r['expected_primary_identity_sha256'] == sha(encode(expected_primary_identity))
        and r['process_id'] == expected_pid and r['process_creation'] == expected_creation and r['frequency'] == frequency
        and r['deadline_qpc'] == deadline, 'proof_binding')
    for k in ('generation_before', 'generation_after', 'source_identity_bound', 'duplicate_identity_bound', 'resource_cleanup_verified',
              'observation_complete', 'qualified', 'token_class46_queried', 'process_or_thread_impersonation_applied', 'network_tested', 'dns_tested', 'product_acceptance'):
        require(type(r[k]) is bool, 'proof_boolean')
    require(not any(r[k] for k in ('token_class46_queried', 'process_or_thread_impersonation_applied', 'network_tested', 'dns_tested', 'product_acceptance')), 'proof_scope')
    require(r['failure'] is None or r['failure'] in FAILURES, 'proof_failure')
    require(r['classification'] in ('unknown', 'ac-semantic-match', 'lpac-semantic-match'), 'classification')
    if r['source_primary'] is not None:
        identity_shape(r['source_primary'])
    require(not r['source_identity_bound'] or r['source_primary'] == expected_primary_identity and r['generation_before'], 'source_binding')
    if r['duplicate'] is not None:
        # Invalid duplicate observations remain failure evidence; they cannot qualify.
        identity_shape(r['duplicate'])
    require(not r['duplicate_identity_bound'] or r['source_identity_bound'] and duplicate_matches(r['source_primary'], r['duplicate']), 'duplicate_binding')
    resources = r['resources']
    require(type(resources) is list and 2 <= len(resources) <= 6 and [x['name'] for x in resources[:2]] == ['source-primary', 'duplicate-identification'], 'resources')
    require([x['name'] for x in resources[2:]] == ['descriptor-' + k for k in LABELS[:len(resources) - 2]], 'resource_order')
    for i, x in enumerate(resources):
        require(type(x) is dict and set(x) == RESOURCE_KEYS and x['kind'] == ('token' if i < 2 else 'descriptor')
            and all(type(x[k]) is bool for k in RESOURCE_KEYS - {'name', 'kind'}), 'resource_schema')
        require(not x['returned'] or x['attempted'] and x['creation_returned'], 'resource_returned')
        require(not x['close_confirmed'] or x['returned'] and x['close_attempted'] and not x['close_uncertain'] and not x['alias'], 'resource_closed')
        require(not x['close_attempted'] or x['returned'] and not x['alias'], 'resource_close')
    require(r['resource_cleanup_verified'] == resources_clean(resources), 'resource_cleanup')
    calls = r['calls']; require(type(calls) is list and len(calls) <= 4 and [c['label'] for c in calls] == list(LABELS[:len(calls)]), 'call_order')
    require(len(resources) == 2 + len(calls), 'call_resource_count')
    require(not r['source_identity_bound'] or all(resources[0][k] for k in ('attempted', 'creation_returned', 'returned')), 'source_resource')
    require(not r['duplicate_identity_bound'] or all(resources[1][k] for k in ('attempted', 'creation_returned', 'returned')), 'duplicate_resource')
    for i, c in enumerate(calls):
        require(type(c) is dict and set(c) == CALL_KEYS and all(type(c[k]) is bool for k in ('descriptor_verified', 'attempted', 'within_deadline')), 'call_schema')
        require(c['api_success'] is None or type(c['api_success']) is bool, 'call_api')
        if c['descriptor_verified']:
            d = c['descriptor']; require(type(d) is dict and set(d) == {*descriptor_expected(c['label']), 'bytes', 'sha256'}
                and {k: v for k, v in d.items() if k not in ('bytes', 'sha256')} == descriptor_expected(c['label'])
                and integer(d['bytes'], 20, 4096) and digest(d['sha256']), 'descriptor_proof')
            require(all(resources[i + 2][k] for k in ('attempted', 'creation_returned', 'returned')), 'descriptor_resource')
        require(not c['attempted'] or c['descriptor_verified'] and r['duplicate_identity_bound'], 'access_check_admission')
        if c['api_success'] is True:
            require(c['attempted'] and c['descriptor_verified'] and c['win32_error'] is None
                and type(c['access_status']) is bool and integer(c['granted_access']) and integer(c['privilege_count'], 0, 64)
                and (c['access_status'] or c['granted_access'] == 0), 'valid_api_outputs')
        else:
            require(c['access_status'] is c['granted_access'] is c['privilege_count'] is None, 'invalid_api_outputs')
        if c['api_success'] is False:
            require(c['attempted'] and integer(c['win32_error']), 'failed_api_error')
        if c['within_deadline']:
            require(integer(c['start_qpc'], r['start_qpc'], deadline - 1)
                and integer(c['end_qpc'], c['start_qpc'], deadline - 1), 'call_clock')
    complete = (len(calls) == 4 and all(c['descriptor_verified'] and c['api_success'] is True and c['within_deadline'] for c in calls)
        and r['generation_before'] and r['generation_after'] and r['source_identity_bound'] and r['duplicate_identity_bound'] and r['resource_cleanup_verified'])
    require(r['observation_complete'] == complete, 'complete')
    qualified = (complete and r['failure'] is None and integer(r['start_qpc'], 1, deadline - 1)
        and integer(r['end_qpc'], r['start_qpc'], deadline - 1) and expected_role in EXPECTED
        and all(c['granted_access'] == mask and c['access_status'] is bool(mask) and c['privilege_count'] == 0
            for c, mask in zip(calls, EXPECTED.get(expected_role, ()))))
    require(r['qualified'] == qualified and r['classification'] == (expected_role + '-semantic-match' if qualified else 'unknown'), 'qualification')
    if r['error'] is not None:
        require(type(r['error']) is dict and set(r['error']) == {'operation', 'win32_error'} and type(r['error']['operation']) is str
            and len(r['error']['operation']) <= 96 and integer(r['error']['win32_error']) and r['failure'] is not None, 'api_error')
    return r


class LUID(C.Structure):
    _fields_ = [('LowPart', C.c_uint32), ('HighPart', C.c_int32)]


class TOKEN_STATISTICS(C.Structure):
    _fields_ = [('TokenId', LUID), ('AuthenticationId', LUID), ('ExpirationTime', C.c_int64),
        ('TokenType', C.c_uint32), ('ImpersonationLevel', C.c_uint32), ('DynamicCharged', C.c_uint32),
        ('DynamicAvailable', C.c_uint32), ('GroupCount', C.c_uint32), ('PrivilegeCount', C.c_uint32), ('ModifiedId', LUID)]


class SID_AND_ATTRIBUTES(C.Structure):
    _fields_ = [('Sid', C.c_void_p), ('Attributes', C.c_uint32)]


class TOKEN_GROUPS(C.Structure):
    _fields_ = [('GroupCount', C.c_uint32), ('Groups', SID_AND_ATTRIBUTES * 1)]


class GENERIC_MAPPING(C.Structure):
    _fields_ = [('GenericRead', C.c_uint32), ('GenericWrite', C.c_uint32), ('GenericExecute', C.c_uint32), ('GenericAll', C.c_uint32)]


class NativeAPI:
    """SDK adapter; never instantiated on import and never installs identity.

    This adapter is NOT an execution supervisor. A caller must provide a held
    process and prior full primary-token snapshot, with an outer Job deadline.
    """
    def __init__(self):
        require(os.name == 'nt' and C.sizeof(C.c_void_p) == 8, 'platform')
        self.k = C.WinDLL('kernel32.dll', use_last_error=True, winmode=0x800)
        self.k.GetSystemDirectoryW.argtypes = [C.c_wchar_p, C.c_uint32]; self.k.GetSystemDirectoryW.restype = C.c_uint32
        buf = C.create_unicode_buffer(32768); n = self.k.GetSystemDirectoryW(buf, len(buf))
        require(0 < n < len(buf), 'system_directory')
        self.a = C.WinDLL(buf.value + '\\advapi32.dll', use_last_error=True, winmode=0x800)
        H, U, P = C.c_void_p, C.c_uint32, C.c_void_p
        def bind(dll, name, args, result):
            f = getattr(dll, name); f.argtypes = args; f.restype = result
        for name, args, result in (
            ('OpenProcessToken', [H, U, C.POINTER(H)], C.c_int),
            ('DuplicateTokenEx', [H, U, P, U, U, C.POINTER(H)], C.c_int),
            ('GetTokenInformation', [H, U, P, U, C.POINTER(U)], C.c_int),
            ('IsValidSid', [P], C.c_int), ('GetLengthSid', [P], U),
            ('ConvertStringSecurityDescriptorToSecurityDescriptorW', [C.c_wchar_p, U, C.POINTER(P), C.POINTER(U)], C.c_int),
            ('IsValidSecurityDescriptor', [P], C.c_int), ('GetSecurityDescriptorLength', [P], U),
            ('GetSecurityDescriptorControl', [P, C.POINTER(C.c_uint16), C.POINTER(U)], C.c_int),
            ('GetSecurityDescriptorOwner', [P, C.POINTER(P), C.POINTER(C.c_int)], C.c_int),
            ('GetSecurityDescriptorGroup', [P, C.POINTER(P), C.POINTER(C.c_int)], C.c_int),
            ('GetSecurityDescriptorDacl', [P, C.POINTER(C.c_int), C.POINTER(P), C.POINTER(C.c_int)], C.c_int),
            ('GetAce', [P, U, C.POINTER(P)], C.c_int),
            ('AccessCheck', [P, H, U, C.POINTER(GENERIC_MAPPING), P, C.POINTER(U), C.POINTER(U), C.POINTER(C.c_int)], C.c_int)):
            bind(self.a, name, args, result)
        for name, args, result in (
            ('CloseHandle', [H], C.c_int), ('LocalFree', [P], P),
            ('GetProcessId', [H], U), ('GetProcessTimes', [H, P, P, P, P], C.c_int),
            ('WaitForSingleObject', [H, U], U), ('QueryPerformanceCounter', [C.POINTER(C.c_int64)], C.c_int),
            ('QueryPerformanceFrequency', [C.POINTER(C.c_int64)], C.c_int)):
            bind(self.k, name, args, result)

    @staticmethod
    def _check(ok, operation):
        if not ok:
            raise ApiError(operation, C.get_last_error())

    def qpc(self):
        x = C.c_int64(); self._check(self.k.QueryPerformanceCounter(C.byref(x)), 'QueryPerformanceCounter'); return x.value

    def frequency(self):
        x = C.c_int64(); self._check(self.k.QueryPerformanceFrequency(C.byref(x)), 'QueryPerformanceFrequency'); return x.value

    def verify_process(self, process, pid, creation):
        values = [C.c_uint64() for _ in range(4)]
        self._check(self.k.GetProcessTimes(process, *(C.byref(x) for x in values)), 'GetProcessTimes')
        return self.k.GetProcessId(process) == pid and values[0].value == creation and self.k.WaitForSingleObject(process, 0) == 258

    def open_token(self, process, rights):
        value = C.c_void_p(); ok = bool(self.a.OpenProcessToken(process, rights, C.byref(value)))
        return ok, value.value, None if ok else C.get_last_error()

    def duplicate_token(self, token, rights, level, kind):
        value = C.c_void_p(); ok = bool(self.a.DuplicateTokenEx(token, rights, None, level, kind, C.byref(value)))
        return ok, value.value, None if ok else C.get_last_error()

    def close_token(self, value):
        return bool(self.k.CloseHandle(value))

    def free_descriptor(self, value):
        return self.k.LocalFree(value) is None

    def _information(self, token, kind):
        n = C.c_uint32(); ok = self.a.GetTokenInformation(token, kind, None, 0, C.byref(n)); error = C.get_last_error()
        require(not ok and error == 122 and 0 < n.value <= 262144, 'token_information_size')
        buf = C.create_string_buffer(n.value); actual = C.c_uint32()
        self._check(self.a.GetTokenInformation(token, kind, buf, len(buf), C.byref(actual)), 'GetTokenInformation')
        require(0 < actual.value <= len(buf), 'token_information_length')
        return buf, actual.value

    def _scalar(self, token, kind):
        buf, n = self._information(token, kind); require(n == 4, 'token_scalar_length')
        return C.cast(buf, C.POINTER(C.c_uint32))[0]

    def _sid(self, pointer, base, size):
        require(pointer and base <= pointer <= base + size - 8, 'sid_bounds')
        head = C.string_at(pointer, 8); count = head[1]
        require(head[0] == 1 and count <= 15 and pointer + 8 + count * 4 <= base + size, 'sid_bounds')
        self._check(self.a.IsValidSid(pointer), 'IsValidSid')
        require(self.a.GetLengthSid(pointer) == 8 + count * 4, 'sid_length')
        raw = C.string_at(pointer, 8 + count * 4)
        return 'S-1-' + str(int.from_bytes(raw[2:8], 'big')) + ''.join('-' + str(int.from_bytes(raw[8+i*4:12+i*4], 'little')) for i in range(count))

    def identity(self, token):
        def token_sid(kind):
            buf, n = self._information(token, kind)
            require(n >= C.sizeof(C.c_void_p), 'token_sid_length')
            p = C.cast(buf, C.POINTER(C.c_void_p))[0]
            return self._sid(p, C.addressof(buf), n) if p else None
        buf, n = self._information(token, 30)
        count = C.cast(buf, C.POINTER(C.c_uint32))[0]
        require(count <= 64 and TOKEN_GROUPS.Groups.offset + count * C.sizeof(SID_AND_ATTRIBUTES) <= n, 'capability_buffer')
        entries = C.cast(C.addressof(buf) + TOKEN_GROUPS.Groups.offset, C.POINTER(SID_AND_ATTRIBUTES))
        caps = [dict(sid=self._sid(entries[i].Sid, C.addressof(buf), n), attributes=entries[i].Attributes) for i in range(count)]
        stats, n = self._information(token, 10); require(n == C.sizeof(TOKEN_STATISTICS), 'token_statistics_length')
        st = C.cast(stats, C.POINTER(TOKEN_STATISTICS))[0]
        luid = lambda x: x.LowPart | ((x.HighPart & 0xffffffff) << 32)
        kind = self._scalar(token, 8)
        require(kind == st.TokenType and kind in (1, 2), 'token_statistics_kind')
        level = self._scalar(token, 9) if kind == 2 else None
        require(level is None or level == st.ImpersonationLevel, 'token_statistics_level')
        integrity = token_sid(25)
        is_ac, elevation, ui = (self._scalar(token, k) for k in (29, 20, 26))
        require(all(x in (0, 1) for x in (is_ac, elevation, ui)) and integrity is not None, 'token_boolean')
        return dict(sid=token_sid(1), session_id=self._scalar(token, 12), token_type=kind, impersonation_level=level,
            appcontainer=bool(is_ac), appcontainer_sid=token_sid(31), integrity_rid=int(integrity.rsplit('-', 1)[1]),
            elevated=bool(elevation), ui_access=bool(ui), capabilities=sorted(caps, key=lambda e: e['sid']),
            token_id=luid(st.TokenId), authentication_id=luid(st.AuthenticationId))

    def create_descriptor(self, sddl):
        require(sddl in SDDLS.values(), 'descriptor_input')
        p, n = C.c_void_p(), C.c_uint32()
        ok = bool(self.a.ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, 1, C.byref(p), C.byref(n)))
        return ok, p.value, None if ok else C.get_last_error()

    def describe_descriptor(self, pointer):
        self._check(self.a.IsValidSecurityDescriptor(pointer), 'IsValidSecurityDescriptor')
        size = self.a.GetSecurityDescriptorLength(pointer); require(20 <= size <= 4096, 'descriptor_length')
        require(C.string_at(pointer, 2) == b'\x01\x00', 'descriptor_header')
        revision, control = C.c_uint32(), C.c_uint16()
        self._check(self.a.GetSecurityDescriptorControl(pointer, C.byref(control), C.byref(revision)), 'GetSecurityDescriptorControl')
        owner, group, acl = C.c_void_p(), C.c_void_p(), C.c_void_p()
        od, gd, present, dd = C.c_int(), C.c_int(), C.c_int(), C.c_int()
        self._check(self.a.GetSecurityDescriptorOwner(pointer, C.byref(owner), C.byref(od)), 'GetSecurityDescriptorOwner')
        self._check(self.a.GetSecurityDescriptorGroup(pointer, C.byref(group), C.byref(gd)), 'GetSecurityDescriptorGroup')
        self._check(self.a.GetSecurityDescriptorDacl(pointer, C.byref(present), C.byref(acl), C.byref(dd)), 'GetSecurityDescriptorDacl')
        require(present.value == 1 and acl.value and pointer <= acl.value <= pointer + size - 8, 'dacl_bounds')
        header = C.string_at(acl.value, 8); acl_size, count = int.from_bytes(header[2:4], 'little'), int.from_bytes(header[4:6], 'little')
        require(header[0] == 2 and header[1] == 0 and header[6:8] == b'\0\0'
            and 8 <= acl_size <= size and acl.value + acl_size <= pointer + size and count <= 3, 'dacl_bounds')
        aces = []
        for i in range(count):
            p = C.c_void_p(); self._check(self.a.GetAce(acl, i, C.byref(p)), 'GetAce')
            require(p.value and acl.value + 8 <= p.value <= acl.value + acl_size - 8, 'ace_bounds')
            raw = C.string_at(p.value, 8); n = int.from_bytes(raw[2:4], 'little')
            require(16 <= n and p.value + n <= acl.value + acl_size, 'ace_bounds')
            sid = self._sid(p.value + 8, p.value, n)
            require(self.a.GetLengthSid(p.value + 8) + 8 == n, 'ace_sid_length')
            aces.append(dict(type=raw[0], flags=raw[1], mask=int.from_bytes(raw[4:8], 'little'), sid=sid))
        return dict(revision=revision.value, control=control.value, owner=self._sid(owner.value, pointer, size), group=self._sid(group.value, pointer, size),
            owner_defaulted=bool(od.value), group_defaulted=bool(gd.value), dacl_present=bool(present.value), dacl_defaulted=bool(dd.value),
            aces=aces, bytes=size, sha256=sha(C.string_at(pointer, size)))

    def access_check(self, descriptor, token, desired, mapping):
        require(desired == MAXIMUM_ALLOWED and mapping == (0, 0, 0, 0), 'access_check_input')
        generic = GENERIC_MAPPING(*mapping); privileges = C.create_string_buffer(65536); n = C.c_uint32(len(privileges))
        granted, status = C.c_uint32(0xa5a5a5a5), C.c_int(-1)
        ok = bool(self.a.AccessCheck(descriptor, token, desired, C.byref(generic), privileges, C.byref(n), C.byref(granted), C.byref(status)))
        if not ok:
            return False, None, None, None, C.get_last_error()
        require(status.value in (0, 1) and 8 <= n.value <= len(privileges), 'access_check_output')
        count = C.cast(privileges, C.POINTER(C.c_uint32))[0]
        require(count <= 64 and 8 + count * 12 <= n.value, 'privilege_buffer')
        return True, bool(status.value), granted.value, count, None
