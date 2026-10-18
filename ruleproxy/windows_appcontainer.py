"""Experimental Windows strong per-app isolation through AppContainer.

An application started inside an AppContainer with *no* capabilities has no
network access at all; Windows enforces that from the process token, and every
child inherits it. The SYSTEM service then opens exactly one path for that
package SID: TCP to 127.0.0.1/::1 on the panel's proxy port. Everything else
from the package is hard-blocked in our own persistent WFP sublayer, so the
result does not depend on Windows Firewall being enabled. Applications must
support an explicit proxy; arbitrary GUI compatibility is not established.

Ordering is fail-closed. ``allow`` commits the persistent filters before it
adds the loopback exemption; ``revoke`` removes the exemption before deleting
the filters. A container with neither has no network at all.

Native evidence: .github/windows_appcontainer_lab.py (Windows Server 2025),
including with all firewall profiles disabled and after the proxy stops.
That CLI experiment does not qualify arbitrary browsers or Windows builds.

Sources checked for this implementation:
https://learn.microsoft.com/windows/win32/secauthp/implementing-an-appcontainer
https://learn.microsoft.com/windows/win32/api/userenv/nf-userenv-createappcontainerprofile
https://learn.microsoft.com/windows/win32/api/netfw/nf-netfw-networkisolationsetappcontainerconfig
https://learn.microsoft.com/windows/win32/fwp/filtering-conditions-available-at-each-filtering-layer
https://projectzero.google/2021/08/understanding-network-access-windows-app.html
"""
from __future__ import annotations

import ctypes as C
import hashlib
import ipaddress
import os
from pathlib import Path
import re
import subprocess
import threading
import uuid

from .windows_proxy_policy import SID_RE, SERVICE_NAME, ProxyError


NAME_RE = re.compile(r'RuleProxy\.[0-9a-f]{20}')
# Windows enumeration canonicalizes profile names to lower case. Only this
# OS readback accepts ASCII case equivalence; requests retain NAME_RE exactly.
_ENUM_NAME_RE = re.compile(r'ruleproxy\.[0-9a-f]{20}', re.ASCII)
PACKAGE_SID_RE = re.compile(r'S-1-15-2(?:-[0-9]{1,10}){7}')
# FWPM_CONDITION_ALE_PACKAGE_ID; FWP_SID value type.
PACKAGE_FIELD = '71bc78fa-f17c-4997-a602-6abb261f351c'
_FWP_SID = 13
_ALREADY_EXISTS = 0x800700B7
_NAMESPACE = uuid.UUID('0d6f4c1e-5a51-4d3f-9b5e-7c3f61f0a8a2')
_RULES = ((4, 'proxy'), (6, 'proxy'), (4, 'block'), (6, 'block'))
_REDIRECTED = ('APPDATA', 'LOCALAPPDATA', 'TEMP', 'TMP')


def container_name(ident: str) -> str:
    """A stable, opaque profile name; app labels and paths never reach the OS."""
    if not isinstance(ident, str) or not ident or '\0' in ident:
        raise ValueError('应用标识无效。')
    return 'RuleProxy.' + hashlib.sha256(('appcontainer\0' + ident).encode()).hexdigest()[:20]


def _check_name(name):
    if not isinstance(name, str) or not NAME_RE.fullmatch(name):
        raise ProxyError('invalid_request', 'AppContainer 名称无效。')
    return name


def _check_port(port):
    if type(port) is not int or not 1025 <= port <= 65535:
        raise ProxyError('invalid_request', '代理端口无效。')
    return port


class _SidAndAttributes(C.Structure):
    _fields_ = [('sid', C.c_void_p), ('attributes', C.c_uint32)]


class _Capabilities(C.Structure):
    _fields_ = [('count', C.c_uint32), ('entries', C.POINTER(_SidAndAttributes))]


class _Binaries(C.Structure):
    _fields_ = [('count', C.c_uint32), ('entries', C.POINTER(C.c_wchar_p))]


class _AppContainer(C.Structure):
    _fields_ = [('sid', C.c_void_p), ('user', C.c_void_p), ('name', C.c_wchar_p),
               ('display', C.c_wchar_p), ('description', C.c_wchar_p),
               ('capabilities', _Capabilities), ('binaries', _Binaries),
               ('directory', C.c_wchar_p), ('package', C.c_wchar_p)]


class _ContainerAPI:
    """Load userenv/firewallapi only when an AppContainer is really used."""

    def __init__(self):
        if os.name != 'nt' or C.sizeof(C.c_void_p) != 8:
            raise ProxyError('appcontainer_unsupported', 'AppContainer 强隔离仅支持原生 64 位 Windows。')
        self.userenv = C.WinDLL('userenv', use_last_error=True)
        self.advapi = C.WinDLL('advapi32', use_last_error=True)
        self.kernel = C.WinDLL('kernel32', use_last_error=True)
        self.firewall = C.WinDLL('firewallapi', use_last_error=True)
        P, U32 = C.c_void_p, C.c_uint32
        for owner, name, arguments, result in (
                (self.userenv, 'CreateAppContainerProfile',
                 [C.c_wchar_p, C.c_wchar_p, C.c_wchar_p, P, U32, C.POINTER(P)], C.c_long),
                (self.userenv, 'DeriveAppContainerSidFromAppContainerName', [C.c_wchar_p, C.POINTER(P)], C.c_long),
                (self.userenv, 'DeleteAppContainerProfile', [C.c_wchar_p], C.c_long),
                (self.advapi, 'FreeSid', [P], P),
                (self.advapi, 'ConvertSidToStringSidW', [P, C.POINTER(C.c_wchar_p)], C.c_int),
                (self.advapi, 'ConvertStringSidToSidW', [C.c_wchar_p, C.POINTER(P)], C.c_int),
                (self.kernel, 'LocalFree', [P], P),
                (self.firewall, 'NetworkIsolationGetAppContainerConfig',
                 [C.POINTER(U32), C.POINTER(C.POINTER(_SidAndAttributes))], U32),
                (self.firewall, 'NetworkIsolationSetAppContainerConfig',
                 [U32, C.POINTER(_SidAndAttributes)], U32),
                (self.firewall, 'NetworkIsolationEnumAppContainers',
                 [U32, C.POINTER(U32), C.POINTER(C.POINTER(_AppContainer))], U32),
                (self.firewall, 'NetworkIsolationFreeAppContainers', [C.POINTER(_AppContainer)], U32)):
            function = getattr(owner, name)
            function.argtypes, function.restype = arguments, result

    def sid_text(self, sid):
        text = C.c_wchar_p()
        if not self.advapi.ConvertSidToStringSidW(sid, C.byref(text)):
            raise C.WinError(C.get_last_error())
        try:
            return text.value
        finally:
            self.kernel.LocalFree(C.cast(text, C.c_void_p))

    def _owned_sid(self, function, *arguments):
        sid = C.c_void_p()
        code = function(*arguments, C.byref(sid)) & 0xFFFFFFFF
        if code:
            return code, None
        try:
            return 0, self.sid_text(sid)
        finally:
            self.advapi.FreeSid(sid)

    def derive(self, name):
        code, sid = self._owned_sid(self.userenv.DeriveAppContainerSidFromAppContainerName, name)
        if code:
            raise ProxyError('appcontainer_failed', f'无法计算 AppContainer 身份（0x{code:08x}）。')
        return sid

    def create(self, name):
        code, sid = self._owned_sid(self.userenv.CreateAppContainerProfile, name, name,
                                    'RuleProxy isolated application', None, 0)
        if code == _ALREADY_EXISTS:
            return self.derive(name)
        if code:
            raise ProxyError('appcontainer_failed', f'无法创建 AppContainer 配置（0x{code:08x}）。')
        return sid

    def delete(self, name):
        code = self.userenv.DeleteAppContainerProfile(name) & 0xFFFFFFFF
        if code not in (0, 0x80070002):
            raise ProxyError('appcontainer_failed', f'无法删除 AppContainer 配置（0x{code:08x}）。')

    def binary_sid(self, text):
        """Return a LocalAlloc'd binary SID; the caller releases it with LocalFree."""
        sid = C.c_void_p()
        if not self.advapi.ConvertStringSidToSidW(text, C.byref(sid)):
            raise C.WinError(C.get_last_error())
        return sid

    def exemptions(self):
        count, entries = C.c_uint32(), C.POINTER(_SidAndAttributes)()
        code = self.firewall.NetworkIsolationGetAppContainerConfig(C.byref(count), C.byref(entries))
        if code:
            raise ProxyError('appcontainer_failed', f'无法读取回环豁免列表（{code}）。')
        # The small OS-allocated list is deliberately not freed: its documented
        # release routine differs across releases and a wrong free is fatal.
        return [self.sid_text(entries[index].sid) for index in range(count.value)]

    def set_exemptions(self, sids):
        owned = []
        try:
            for sid in sids:
                owned.append(self.binary_sid(sid))
            array = (_SidAndAttributes * max(1, len(owned)))(*[_SidAndAttributes(sid.value, 0) for sid in owned])
            code = self.firewall.NetworkIsolationSetAppContainerConfig(len(owned), array)
            if code:
                raise ProxyError('appcontainer_failed', f'无法修改回环豁免列表（{code}）。')
        finally:
            for sid in owned:
                self.kernel.LocalFree(sid)

    def profiles(self):
        count, entries = C.c_uint32(), C.POINTER(_AppContainer)()
        code = self.firewall.NetworkIsolationEnumAppContainers(0, C.byref(count), C.byref(entries))
        if code:
            raise ProxyError('appcontainer_failed', f'无法枚举 AppContainer 配置（{code}）。')
        try:
            if count.value > 65536 or (count.value and not entries):
                raise ProxyError('appcontainer_failed', 'AppContainer 配置数量异常。')
            return [(item.name, self.sid_text(item.sid), self.sid_text(item.user))
                    for item in (entries[index] for index in range(count.value))]
        finally:
            if entries:
                self.firewall.NetworkIsolationFreeAppContainers(entries)


_api = None
_api_lock = threading.Lock()


def _get_api():
    global _api
    with _api_lock:
        if _api is None:
            _api = _ContainerAPI()
        return _api


# ---------------------------------------------------------------- panel side (ordinary user)

def ensure_profile(name: str) -> str:
    """Create or reuse the per-app profile; returns its package SID string."""
    sid = _get_api().create(_check_name(name))
    if not PACKAGE_SID_RE.fullmatch(sid):
        raise ProxyError('appcontainer_failed', 'AppContainer 身份格式异常。')
    return sid


def delete_profile(name: str) -> None:
    _get_api().delete(_check_name(name))


def owner_profile_sids(owner_sid: str, *, api=None) -> set[str]:
    """Return OS profiles whose actual owner, name and derived SID agree.

    These are candidates, not proof that this installation owns a WFP rule or
    exemption. Cleanup must additionally verify its installation marker.
    """
    if not isinstance(owner_sid, str) or not SID_RE.fullmatch(owner_sid):
        raise ProxyError('invalid_deployment', 'AppContainer 配置所有者无效。')
    api = api or _get_api()
    result = set()
    for name, sid, owner in api.profiles():
        if (owner == owner_sid and isinstance(name, str) and name.isascii()
                and _ENUM_NAME_RE.fullmatch(name.lower())
                and isinstance(sid, str) and PACKAGE_SID_RE.fullmatch(sid)
                and api.derive(name) == sid):
            result.add(sid)
    return result


def grant_access(sid: str, path: Path, *, write: bool) -> None:
    """Grant the package SID inheritable access to one directory tree.

    Only paths the desktop user already controls can be changed; system
    directories already allow ALL APPLICATION PACKAGES to read and execute.
    """
    if not isinstance(sid, str) or not PACKAGE_SID_RE.fullmatch(sid):
        raise ValueError('AppContainer 身份无效。')
    path = Path(path)
    if not path.is_absolute() or not path.is_dir():
        raise ValueError('授权目录必须是已存在的绝对路径。')
    rights = '(OI)(CI)(M)' if write else '(OI)(CI)(RX)'
    system = Path(os.environ.get('SystemRoot', r'C:\Windows'))
    result = subprocess.run([str(system / 'System32' / 'icacls.exe'), str(path), '/grant', f'*{sid}:{rights}', '/C', '/Q'],
                            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL, timeout=300,
                            creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
    if result.returncode:
        raise ProxyError('appcontainer_access', '无法为隔离应用授权目录：' + str(path))


def container_environment(env: dict[str, str], data: Path) -> dict[str, str]:
    """Point per-user data locations at the app's own writable profile."""
    data = Path(data)
    result = dict(env)
    for folded in _REDIRECTED:
        for key in [key for key in result if key.upper() == folded]:
            del result[key]
    for name in _REDIRECTED:
        target = data / ('Temp' if name in ('TEMP', 'TMP') else name)
        target.mkdir(parents=True, exist_ok=True)
        result[name] = str(target)
    return result


def _enum_filters(engine):
    """Yield native filters while their OS allocation is alive; always free it."""
    from . import windows_global_guard as G
    P, U32 = C.c_void_p, C.c_uint32
    signatures = {
        'FwpmFilterCreateEnumHandle0': ([P, P, C.POINTER(P)], U32),
        'FwpmFilterEnum0': ([P, P, U32, C.POINTER(C.POINTER(C.POINTER(G._Filter))), C.POINTER(U32)], U32),
        'FwpmFilterDestroyEnumHandle0': ([P, P], U32),
    }
    for name, (arguments, result) in signatures.items():
        function = getattr(engine.api, name)
        function.argtypes, function.restype = arguments, result
    handle = P()
    G._error(engine.api.FwpmFilterCreateEnumHandle0(engine.handle, None, C.byref(handle)), '枚举隔离规则')
    try:
        total = 0
        while True:
            entries, count = C.POINTER(C.POINTER(G._Filter))(), U32()
            G._error(engine.api.FwpmFilterEnum0(engine.handle, handle, 256, C.byref(entries), C.byref(count)),
                     '读取隔离规则列表')
            try:
                total += count.value
                if count.value > 256 or total > 65536 or (count.value and not entries):
                    raise ProxyError('appcontainer_failed', 'WFP 规则枚举超过安全上限。')
                for index in range(count.value):
                    if not entries[index]:
                        raise ProxyError('appcontainer_failed', 'WFP 规则枚举含空指针。')
                    yield entries[index].contents
                if count.value < 256:
                    break
            finally:
                if entries:
                    pointer = C.cast(entries, P)
                    engine.api.FwpmFreeMemory0(C.byref(pointer))
    finally:
        engine.api.FwpmFilterDestroyEnumHandle0(engine.handle, handle)


# ---------------------------------------------------------------- SYSTEM service side

class ContainerGate:
    """Persistent package-SID filters plus the loopback exemption."""

    def __init__(self, metadata, api=None, engine_factory=None):
        if (not isinstance(metadata, dict) or not isinstance(metadata.get('root'), str)
                or not metadata['root'] or '\0' in metadata['root']
                or not isinstance(metadata.get('owner_sid'), str) or not SID_RE.fullmatch(metadata['owner_sid'])):
            raise ProxyError('invalid_deployment', 'AppContainer 保护缺少可信安装身份。')
        self.identity = hashlib.sha256((metadata['owner_sid'] + '\0' + metadata['root'].casefold()
                                        + '\0appcontainer').encode()).hexdigest()
        self.provider = uuid.uuid5(_NAMESPACE, self.identity + '/provider')
        self.sublayer = uuid.uuid5(_NAMESPACE, self.identity + '/sublayer')
        self.marker = 'RuleProxyAppContainer-v1:' + self.identity
        self.owner_sid = metadata['owner_sid']
        self._api = api
        self._engine_factory = engine_factory
        self.lock = threading.RLock()

    @property
    def api(self):
        if self._api is None:
            self._api = _get_api()
        return self._api

    def _engine(self):
        if self._engine_factory is not None:
            return self._engine_factory()
        from .windows_global_guard import _Engine
        return _Engine()

    def _key(self, sid, family, name):
        return uuid.uuid5(_NAMESPACE, f'{self.identity}/{sid}/{family}/{name}')

    def _sid(self, name):
        sid = self.api.derive(_check_name(name))
        if not PACKAGE_SID_RE.fullmatch(sid):
            raise ProxyError('appcontainer_failed', 'AppContainer 身份格式异常。')
        return sid

    def _ensure_objects(self, engine):
        from . import windows_global_guard as G
        provider = G._GUID.of(self.provider)
        with engine.get('Provider', self.provider, G._Provider) as value:
            if value is not None and value.display.description != self.marker:
                raise ProxyError('appcontainer_conflict', '自有 WFP 提供程序身份冲突。')
            present = value is not None
        if not present:
            value = G._Provider()
            value.key, value.display, value.flags = provider, G._Display('RuleProxy AppContainer', self.marker), G._PERSISTENT
            value.service = SERVICE_NAME
            G._error(engine.api.FwpmProviderAdd0(engine.handle, C.byref(value), None), '添加隔离提供程序')
        with engine.get('SubLayer', self.sublayer, G._Sublayer) as value:
            if value is not None and (value.display.description != self.marker or value.weight != 65535):
                raise ProxyError('appcontainer_conflict', '自有 WFP 子层身份冲突。')
            present = value is not None
        if not present:
            value = G._Sublayer()
            value.key, value.display = G._GUID.of(self.sublayer), G._Display('RuleProxy AppContainer', self.marker)
            value.flags, value.provider, value.weight = G._PERSISTENT, C.pointer(provider), 65535
            G._error(engine.api.FwpmSubLayerAdd0(engine.handle, C.byref(value), None), '添加隔离子层')

    def _present(self, engine, sid):
        from . import windows_global_guard as G
        found = []
        for family, name in _RULES:
            with engine.get('Filter', self._key(sid, family, name), G._Filter) as value:
                if value is None:
                    continue
                self._validate_filter(value, sid, family, name)
                found.append((family, name))
        return found

    def _validate_filter(self, value, sid, family, name):
        from . import windows_global_guard as G
        valid = (value.key.text() == str(self._key(sid, family, name))
                 and value.display.description == self.marker
                 and value.provider and value.provider.contents.text() == str(self.provider)
                 and value.sublayer.text() == str(self.sublayer)
                 and value.layer.text() == G._LAYERS[family]
                 and (value.flags & ~G._INDEXED) == G._PERSISTENT
                 and value.weight.type == 1 and value.weight.value.u8 == (15 if name == 'proxy' else 0)
                 and value.action.type == (G._PERMIT if name == 'proxy' else G._BLOCK)
                 and value.count == (4 if name == 'proxy' else 1) and value.conditions)
        if not valid:
            raise ProxyError('appcontainer_conflict', '自有 AppContainer 规则身份冲突。')
        fields = {}
        for index in range(value.count):
            condition = value.conditions[index]
            key = condition.field.text()
            if condition.match != 0 or key in fields:
                raise ProxyError('appcontainer_conflict', '自有 AppContainer 条件已改变。')
            if key == PACKAGE_FIELD:
                if condition.value.type != _FWP_SID or not condition.value.value.pointer:
                    raise ProxyError('appcontainer_conflict', '自有 AppContainer 包身份已改变。')
                fields[key] = self.api.sid_text(condition.value.value.pointer)
            else:
                fields[key] = (condition.value.type, G._data(condition.value))
        expected = {PACKAGE_FIELD: sid}
        if name == 'proxy':
            port = fields.get(G._FIELDS['remote_port'])
            if not port or port[0] != 2 or type(port[1]) is not int or not 1025 <= port[1] <= 65535:
                raise ProxyError('appcontainer_conflict', '自有 AppContainer 代理端口已改变。')
            expected.update({G._FIELDS['protocol']: (1, 6), G._FIELDS['remote_port']: port,
                             G._FIELDS['remote']: ((3, 0x7F000001) if family == 4 else
                                                  (11, ipaddress.IPv6Address('::1').packed))})
        if fields != expected:
            raise ProxyError('appcontainer_conflict', '自有 AppContainer 条件已改变。')

    def _owned_sids(self, engine):
        """Discover only exact installation-owned filters, including orphan SIDs."""
        from . import windows_global_guard as G
        result = set()
        for value in _enum_filters(engine):
            if not value.provider or value.provider.contents.text() != str(self.provider):
                continue
            if value.count > 16 or not value.conditions:
                raise ProxyError('appcontainer_conflict', '自有 AppContainer 规则无法安全识别。')
            packages = [value.conditions[index] for index in range(value.count)
                        if value.conditions[index].field.text() == PACKAGE_FIELD]
            if (len(packages) != 1 or packages[0].value.type != _FWP_SID
                    or not packages[0].value.value.pointer):
                raise ProxyError('appcontainer_conflict', '自有 AppContainer 规则缺少包身份。')
            sid = self.api.sid_text(packages[0].value.value.pointer)
            if not isinstance(sid, str) or not PACKAGE_SID_RE.fullmatch(sid):
                raise ProxyError('appcontainer_conflict', '自有 AppContainer 包身份异常。')
            matches = [(family, name) for family, name in _RULES
                       if value.key.text() == str(self._key(sid, family, name))]
            if len(matches) != 1:
                raise ProxyError('appcontainer_conflict', '自有 AppContainer 规则键已改变。')
            self._validate_filter(value, sid, *matches[0])
            result.add(sid)
        return result

    def _delete(self, engine, sid):
        from . import windows_global_guard as G
        for family, name in self._present(engine, sid):
            G._error(engine.api.FwpmFilterDeleteByKey0(engine.handle, C.byref(G._GUID.of(self._key(sid, family, name)))),
                     '删除隔离规则')

    def _add(self, engine, sid, binary, family, name, port):
        from . import windows_global_guard as G
        keep = []
        package = G._Condition()
        package.field, package.match = G._GUID.of(PACKAGE_FIELD), 0
        package.value.type, package.value.value.pointer = _FWP_SID, binary.value
        conditions = [package]
        if name == 'proxy':
            loopback = ((3, 0x7F000001) if family == 4 else (11, ipaddress.IPv6Address('::1').packed))
            for field, kind, data in (('protocol', 1, 6), ('remote', *loopback), ('remote_port', 2, port)):
                conditions.append(G._Condition(G._GUID.of(G._FIELDS[field]), 0, G._value(kind, data, keep)))
        array = (G._Condition * len(conditions))(*conditions)
        provider = G._GUID.of(self.provider)
        value = G._Filter()
        value.key = G._GUID.of(self._key(sid, family, name))
        value.display = G._Display(f'RuleProxy AppContainer {name} IPv{family}', self.marker)
        value.flags, value.provider = G._PERSISTENT, C.pointer(provider)
        value.layer, value.sublayer = G._GUID.of(G._LAYERS[family]), G._GUID.of(self.sublayer)
        value.weight = G._value(1, 15 if name == 'proxy' else 0, keep)
        value.count, value.conditions = len(conditions), C.cast(array, C.POINTER(G._Condition))
        value.action.type = G._PERMIT if name == 'proxy' else G._BLOCK
        ident = G._U64()
        G._error(engine.api.FwpmFilterAdd0(engine.handle, C.byref(value), None, C.byref(ident)), '添加隔离规则')

    def allow(self, name: str, proxy_port: int) -> dict:
        """Filters first (committed, read back), then the loopback exemption."""
        port = _check_port(proxy_port)
        with self.lock:
            sid = self._sid(name)
            if sid not in owner_profile_sids(self.owner_sid, api=self.api):
                raise ProxyError('access_denied', 'AppContainer 配置不属于安装用户。')
            binary = self.api.binary_sid(sid)
            try:
                with self._engine() as engine:
                    with engine.transaction():
                        self._ensure_objects(engine)
                        self._delete(engine, sid)
                        for family, rule in _RULES:
                            self._add(engine, sid, binary, family, rule, port)
                    if len(self._present(engine, sid)) != len(_RULES):
                        raise ProxyError('appcontainer_failed', 'AppContainer 规则回读不完整，未开放回环。')
            finally:
                self.api.kernel.LocalFree(binary)
            current = self.api.exemptions()
            if sid not in current:
                self.api.set_exemptions([*current, sid])
            if sid not in self.api.exemptions():
                raise ProxyError('appcontainer_failed', '回环豁免未生效。')
            return {'container': name, 'sid': sid, 'proxy_port': port, 'active': True}

    def revoke(self, name: str) -> dict:
        """Exemption first (back to no network at all), then the filters."""
        with self.lock:
            sid = self._sid(name)
            with self._engine() as engine:
                present = self._present(engine, sid)
            if not present:
                return {'container': name, 'sid': sid, 'active': False}
            self._revoke_sid(sid)
            return {'container': name, 'sid': sid, 'active': False}

    def _revoke_sid(self, sid):
        with self.lock:
            current = self.api.exemptions()
            if sid in current:
                self.api.set_exemptions([item for item in current if item != sid])
            if sid in self.api.exemptions():
                raise ProxyError('appcontainer_failed', '回环豁免未能撤销，保留阻断规则。')
            with self._engine() as engine:
                with engine.transaction():
                    self._delete(engine, sid)
                if self._present(engine, sid):
                    raise ProxyError('appcontainer_failed', 'AppContainer 规则清理未能确认。')

    def purge(self) -> dict:
        """Recover this installation's orphan gates; never adopt a prefix alone."""
        with self.lock:
            with self._engine() as engine:
                sids = self._owned_sids(engine)
                # Validate all discovered rules before changing any exemptions.
                for sid in sids:
                    self._present(engine, sid)
            for sid in sorted(sids):
                self._revoke_sid(sid)
            with self._engine() as engine:
                if self._owned_sids(engine):
                    raise ProxyError('appcontainer_failed', 'AppContainer 遗留规则尚未清理完成。')
            return {'active': False, 'purged_sids': sorted(sids)}


# ---------------------------------------------------------------- panel launch flow

class ContainerLease:
    """Closes the service gate once the panel no longer owns the app."""

    def __init__(self, backend, name):
        self.backend, self.name = backend, name

    def close(self):
        if self.name:
            self.backend.container_revoke(self.name)
            self.name = None


def start_contained(backend, ident, command, env, *, profile: Path, proxy_port: int, launch):
    """Prepare the profile and ACLs, open the gate, then launch confined."""
    name = container_name(ident)
    sid = ensure_profile(name)
    program = Path(command[0]).parent
    try:
        grant_access(sid, program, write=False)
    except ProxyError:
        # Program Files and Windows already allow ALL APPLICATION PACKAGES to
        # read and execute; the user cannot (and need not) change them.
        pass
    profile = Path(profile)
    profile.mkdir(parents=True, exist_ok=True)
    grant_access(sid, profile, write=True)
    env = container_environment(env, profile / 'AppContainer')
    backend.container_allow(name, proxy_port)
    lease = ContainerLease(backend, name)
    try:
        process = launch(command, env, str(program), native_proxy_port=proxy_port, container_sid=sid)
    except BaseException:
        lease.close()
        raise
    return process, lease
