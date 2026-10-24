"""Per-application WFP egress guard for the Windows compatibility mode.

ProxiFyre redirects the selected executables' traffic to the local Mihomo
endpoint, but it is a redirector, not a boundary: a program that ignores it,
or a backend failure, can restore direct connectivity. This guard adds the
missing default-deny layer for exactly the broker's currently routed path
set. Persistent filters live in an owned sublayer at ALE_AUTH_CONNECT_V4/V6.
For every selected executable identity the sublayer permits only loopback
connections to the broker-held proxy port and hard-blocks every other
outbound connection attempt (direct Internet, LAN, other loopback ports,
direct DNS, UDP and IPv6 alike). Unselected programs match no filter here
and keep their normal firewall treatment.

Following the global guard's lifecycle, crashes never delete filters: the
broker exit path and the lease watcher retain them, and only an explicit
panel stop, a mode transition purge, or uninstall removes them. System DNS
resolution performed by OS services on an application's behalf is not the
application's own connection and remains outside this guard; that and the
other residual gaps are reported in APP_GUARD_LIMITATIONS. Native packet
qualification has not been performed, so status never claims strict
isolation.

The WFP object plumbing is shared with windows_global_guard; this module
owns only its identity namespace, rule plan and lifecycle.

Sources checked for this implementation:
https://learn.microsoft.com/windows/win32/fwp/filtering-conditions-available-at-each-filtering-layer
https://learn.microsoft.com/windows/win32/fwp/filter-arbitration
https://learn.microsoft.com/windows/win32/fwp/ale-re-authorization
"""
from __future__ import annotations

import hashlib
from pathlib import Path
import threading
import uuid

from . import windows_global_guard as _shared
from .windows_global_guard import (
    _BLOCK, _FIELDS, _GUID, _INDEXED, _LAYERS, _PERMIT, _PERSISTENT,
    _Condition, _Display, _Engine, _Filter, _Provider, _Rule, _Sublayer,
    _data, _error, _value,
)
from .windows_proxy_policy import MAX_PATHS, SID_RE, ProxyError


_NAMESPACE = uuid.UUID('3f7c2b1e-9d4a-4e8b-b5c6-1a2d3e4f5a6b')
_SUBLAYER_WEIGHT = 65534  # Below the global guard's sublayer, above defaults.
_PERMIT_WEIGHT, _BLOCK_WEIGHT = 12, 11
_KINDS = ('permit', 'block')


def _plan(app_ids, proxy_port) -> tuple[_Rule, ...]:
    """One permit/block pair per application identity and address family.

    The permit is deliberately narrow: the application's own connections may
    only reach the loopback proxy endpoint. Everything else the application
    attempts is decided by its block rule inside this sublayer.
    """
    if (not isinstance(app_ids, (list, tuple)) or not 1 <= len(app_ids) <= MAX_PATHS
            or any(not isinstance(item, bytes) or not 1 <= len(item) <= 65536 for item in app_ids)
            or len(set(app_ids)) != len(app_ids)):
        raise ValueError('Invalid guard application identities')
    if type(proxy_port) is not int or not 1025 <= proxy_port <= 65535:
        raise ValueError('Invalid guard proxy port')
    rules = []
    for family in (4, 6):
        for index, app_id in enumerate(app_ids):
            rules.append(_Rule('permit-' + str(index), family, _PERMIT, _PERMIT_WEIGHT,
                (('app', 0, 12, app_id), ('flags', 6, 3, 1), ('remote_port', 0, 2, proxy_port))))
            rules.append(_Rule('block-' + str(index), family, _BLOCK, _BLOCK_WEIGHT,
                (('app', 0, 12, app_id),)))
    return tuple(rules)


class AppGuard:
    def __init__(self, metadata):
        if (not isinstance(metadata, dict) or not isinstance(metadata.get('root'), str)
                or not metadata['root'] or '\0' in metadata['root']
                or not isinstance(metadata.get('owner_sid'), str) or not SID_RE.fullmatch(metadata['owner_sid'])):
            raise ProxyError('invalid_deployment', '出站守卫缺少可信安装身份。')
        self.metadata = metadata
        self.root = Path(metadata['root'])
        self.identity = hashlib.sha256(
            (metadata['owner_sid'] + '\0' + str(self.root).casefold() + '\0app-guard').encode()).hexdigest()
        self.provider = self._key('provider')
        self.sublayer = self._key('sublayer')
        self.marker = 'RuleProxyAppGuard-v1:' + self.identity
        self.lock = threading.RLock()

    def _key(self, name):
        return uuid.uuid5(_NAMESPACE, self.identity + '/' + name)

    def _rule_key(self, family, name):
        return self._key(str(family) + '/' + name)

    @staticmethod
    def _system_only():
        _shared.Guard._system_only()

    @staticmethod
    def _restore_authority():
        _shared.Guard._restore_authority()

    # -- owned-object readback -------------------------------------------------

    def _owned_provider(self, engine):
        with engine.get('Provider', self.provider, _Provider) as value:
            if value is None:
                return False
            if (value.display.description != self.marker or not value.flags & _PERSISTENT
                    or value.service != _shared.SERVICE_NAME):
                raise ProxyError('app_guard_conflict', '出站守卫 WFP 提供程序身份冲突，未修改现有规则。')
        return True

    def _owned_sublayer(self, engine):
        with engine.get('SubLayer', self.sublayer, _Sublayer) as value:
            if value is None:
                return False
            if (value.display.description != self.marker or not value.flags & _PERSISTENT
                    or not value.provider or value.provider.contents.text() != str(self.provider)
                    or value.weight != _SUBLAYER_WEIGHT):
                raise ProxyError('app_guard_conflict', '出站守卫 WFP 子层身份冲突，未修改现有规则。')
        return True

    def _read_filter(self, engine, family, name):
        with engine.get('Filter', self._rule_key(family, name), _Filter) as value:
            if value is None:
                return None
            if (value.display.description != self.marker or not value.provider
                    or value.provider.contents.text() != str(self.provider)
                    or value.sublayer.text() != str(self.sublayer)
                    or value.layer.text() != _LAYERS[family]
                    or (value.flags & ~_INDEXED) != _PERSISTENT or value.count > 16):
                raise ProxyError('app_guard_conflict', '出站守卫 WFP 规则身份冲突，未修改现有规则。')
            conditions = tuple((value.conditions[index].field.text(), value.conditions[index].match,
                value.conditions[index].value.type, _data(value.conditions[index].value))
                for index in range(value.count))
            return (value.action.type, value.weight.type, _data(value.weight), conditions)

    def _scan(self, engine):
        """Read every owned filter. Rule indexes are dense per family/kind."""
        result = {}
        for family in (4, 6):
            for kind in _KINDS:
                for index in range(MAX_PATHS):
                    name = kind + '-' + str(index)
                    parsed = self._read_filter(engine, family, name)
                    if parsed is None:
                        break
                    result[(family, name)] = parsed
        return result

    @staticmethod
    def _consistent(filters):
        """Return (app_count, proxy_port) for an intact set, else raise.

        Both families must carry the same identities in the same order, every
        permit must point at one shared loopback proxy port, and every block
        must carry exactly its permit's application identity.
        """
        if not filters:
            return 0, None
        ports, identities, family_indexes = set(), {}, {}
        for family in (4, 6):
            indexes = sorted({int(name.split('-')[1]) for item_family, name in filters
                              if item_family == family})
            if indexes != list(range(len(indexes))) or not indexes:
                raise ProxyError('app_guard_changed', '出站守卫规则不完整，不能确认故障后阻断。')
            family_indexes[family] = indexes
            for index in indexes:
                permit = filters.get((family, 'permit-' + str(index)))
                block = filters.get((family, 'block-' + str(index)))
                if permit is None or block is None:
                    raise ProxyError('app_guard_changed', '出站守卫规则不完整，不能确认故障后阻断。')
                if permit[:3] != (_PERMIT, 1, _PERMIT_WEIGHT) or block[:3] != (_BLOCK, 1, _BLOCK_WEIGHT):
                    raise ProxyError('app_guard_changed', '出站守卫规则动作或权重已改变。')
                fields = {(field, match, kind): data for field, match, kind, data in permit[3]}
                if set(fields) != {(_FIELDS['app'], 0, 12), (_FIELDS['flags'], 6, 3),
                                   (_FIELDS['remote_port'], 0, 2)} or fields[(_FIELDS['flags'], 6, 3)] != 1:
                    raise ProxyError('app_guard_changed', '出站守卫放行规则已改变。')
                if block[3] != ((_FIELDS['app'], 0, 12, fields[(_FIELDS['app'], 0, 12)]),):
                    raise ProxyError('app_guard_changed', '出站守卫阻断规则已改变。')
                ports.add(fields[(_FIELDS['remote_port'], 0, 2)])
                identities.setdefault(index, set()).add(fields[(_FIELDS['app'], 0, 12)])
        if (family_indexes[4] != family_indexes[6] or len(ports) != 1
                or any(len(values) != 1 for values in identities.values())):
            raise ProxyError('app_guard_changed', '出站守卫规则跨地址族不一致。')
        return len(identities), ports.pop()

    @staticmethod
    def _expected(rules):
        return {(rule.family, rule.name): (rule.action, 1, rule.weight,
            tuple((_FIELDS[name], match, kind, data) for name, match, kind, data in rule.conditions))
            for rule in rules}

    # -- mutation ---------------------------------------------------------------

    def _ensure_objects(self, engine):
        provider = _GUID.of(self.provider)
        if not self._owned_provider(engine):
            value = _Provider()
            value.key, value.display, value.flags = provider, _Display('RuleProxy app egress guard', self.marker), _PERSISTENT
            value.service = _shared.SERVICE_NAME
            _error(engine.api.FwpmProviderAdd0(engine.handle, _shared.C.byref(value), None), '添加自有提供程序')
        if not self._owned_sublayer(engine):
            value = _Sublayer()
            value.key, value.display, value.flags = _GUID.of(self.sublayer), _Display('RuleProxy app egress guard', self.marker), _PERSISTENT
            value.provider, value.weight = _shared.C.pointer(provider), _SUBLAYER_WEIGHT
            _error(engine.api.FwpmSubLayerAdd0(engine.handle, _shared.C.byref(value), None), '添加自有子层')

    def _replace(self, engine, rules):
        # Identity checks precede any delete. Only exact owned keys are touched.
        previous = self._scan(engine)
        self._ensure_objects(engine)
        for family, name in previous:
            _error(engine.api.FwpmFilterDeleteByKey0(engine.handle,
                _shared.C.byref(_GUID.of(self._rule_key(family, name)))), '替换自有规则')
        for rule in rules:
            keep, provider = [], _GUID.of(self.provider)
            conditions = (_Condition * len(rule.conditions))()
            for index, (name, match, kind, data) in enumerate(rule.conditions):
                conditions[index] = _Condition(_GUID.of(_FIELDS[name]), match, _value(kind, data, keep))
            value = _Filter()
            value.key = _GUID.of(self._rule_key(rule.family, rule.name))
            value.display = _Display('RuleProxy app ' + rule.name + ' IPv' + str(rule.family), self.marker)
            value.flags, value.provider = _PERSISTENT, _shared.C.pointer(provider)
            value.layer, value.sublayer = _GUID.of(_LAYERS[rule.family]), _GUID.of(self.sublayer)
            value.weight = _value(1, rule.weight, keep)
            value.count, value.conditions = len(rule.conditions), conditions if rule.conditions else None
            value.action.type = rule.action
            ident = _shared.C.c_uint64()
            _error(engine.api.FwpmFilterAdd0(engine.handle, _shared.C.byref(value), None,
                _shared.C.byref(ident)), '添加自有规则')

    # -- lifecycle ----------------------------------------------------------------

    def _snapshot(self, engine):
        provider, sublayer = self._owned_provider(engine), self._owned_sublayer(engine)
        filters = self._scan(engine)
        count, port = self._consistent(filters)
        active = bool(filters)
        if active and (not provider or not sublayer):
            raise ProxyError('app_guard_changed', '出站守卫归属对象缺失，不能确认故障后阻断。')
        return {'supported': True, 'active': active, 'persistent': active,
            'strict_isolation': False, 'native_qualified': False,
            'state': 'active' if active else 'idle',
            'app_count': count, 'proxy_port': port, 'rule_count': len(filters),
            'detail': ('所选应用仅可连接本机代理端口，其他出站已被持久 WFP 规则阻断；'
                       '尚未通过 Windows 原生不泄漏验收。' if active else '出站守卫未启用。'),
            'exceptions': ['loopback_proxy_endpoint_for_selected_apps'],
            'limitations': ['系统服务代办的 DNS 解析不是应用自身连接，仍可能从网卡外发。',
                '规则按程序路径身份匹配；异名子进程仍需登记其路径才会纳入守卫。',
                '启用前已建立的连接需要重启应用后才受守卫约束。']}

    def apply(self, paths, proxy_port) -> dict:
        self._system_only()
        from .windows_proxy_policy import normalize_paths
        selected = normalize_paths(list(paths) if isinstance(paths, (list, tuple)) else paths,
            root=str(self.root))
        if type(proxy_port) is not int or not 1025 <= proxy_port <= 65535:
            raise ProxyError('invalid_policy', '出站守卫代理端口无效。')
        with self.lock, _Engine() as engine:
            engine.capability()
            app_ids = []
            for path in selected:
                identity = engine.app_id(Path(path))
                if identity not in app_ids:
                    app_ids.append(identity)
            rules = _plan(app_ids, proxy_port)
            with engine.transaction():
                self._replace(engine, rules)
            snapshot = self._snapshot(engine)
            if (snapshot['app_count'] != len(app_ids) or snapshot['proxy_port'] != proxy_port
                    or self._scan(engine) != self._expected(rules)):
                raise ProxyError('app_guard_changed', '出站守卫回读与计划不一致。')
            return snapshot

    def status(self) -> dict:
        with self.lock:
            try:
                with _Engine() as engine:
                    engine.capability()
                    return self._snapshot(engine)
            except (OSError, ValueError, ProxyError) as error:
                return {'supported': False, 'active': False, 'persistent': False,
                    'strict_isolation': False, 'native_qualified': False,
                    'state': 'unavailable', 'code': getattr(error, 'code', 'app_guard_failed'),
                    'detail': str(error)}

    def normal_stop(self) -> dict:
        """Explicit stop: remove only this installation's exact filters."""
        self._restore_authority()
        with self.lock, _Engine() as engine:
            filters = self._scan(engine)
            if filters and (not self._owned_provider(engine) or not self._owned_sublayer(engine)):
                raise ProxyError('app_guard_conflict', '出站守卫归属无法验证，未删除现有规则。')
            with engine.transaction():
                for family, name in filters:
                    _error(engine.api.FwpmFilterDeleteByKey0(engine.handle,
                        _shared.C.byref(_GUID.of(self._rule_key(family, name)))), '撤销自有规则')
            result = self._snapshot(engine)
            result['stopped'] = True
            return result

    def purge(self) -> dict:
        return self.normal_stop()

    def crash_keep(self) -> dict:
        """Never delete/recreate filters on a crash; BFE owns their lifetime."""
        result = self.status()
        result['retained_after_failure'] = result.get('active') is True
        return result
