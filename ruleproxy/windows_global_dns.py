"""An exact, persistent NRPT lease for the fixed global TUN DNS peers.

No adapter DNS is changed. The lease never changes/deletes another NRPT rule;
foreign or unobservable effective policy prevents startup. Successful policy
read-back is not packet-level Windows DNS qualification.

API sources:
https://learn.microsoft.com/powershell/module/dnsclient/add-dnsclientnrptrule
https://learn.microsoft.com/powershell/module/dnsclient/get-dnsclientnrptpolicy
https://learn.microsoft.com/powershell/module/dnsclient/remove-dnsclientnrptrule
"""
from __future__ import annotations

import base64
from contextlib import contextmanager
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import subprocess
import threading
import time

from .windows_proxy_policy import SID_RE, ProxyError
from .windows_global_qualification import load_qualification

PEERS = ("198.18.0.2", "fdfe:dcba:8879::2")
MAX_OUTPUT = 256 * 1024
MAX_RULES = 256
_GUID = re.compile(r"\{?[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}\}?\Z")

# Only a hash-derived marker and a closed operation name are substituted.
# Cmdlet output is captured, reduced and bounded before writing UTF-8 JSON.
_SCRIPT = r'''
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$WarningPreference = 'SilentlyContinue'
$InformationPreference = 'SilentlyContinue'
$env:PSModulePath = Join-Path $PSHOME 'Modules'
[Console]::OutputEncoding = New-Object Text.UTF8Encoding($false)
$marker = '__MARKER__'
$display = '__DISPLAY__'
$operation = '__OPERATION__'
$peers = @('198.18.0.2','fdfe:dcba:8879::2')
$failure = 'global_dns_unavailable'
function Addresses($values) {
    $result = @()
    foreach ($value in @($values)) {
        foreach ($part in ([string]$value -split '[,;\s]+')) {
            if (-not $part) { continue }
            $address = $null
            if (-not [Net.IPAddress]::TryParse($part,[ref]$address)) { throw 'Invalid NRPT IP' }
            $result += $address.ToString().ToLowerInvariant()
        }
    }
    return @($result | Sort-Object -Unique)
}
function RootNamespace($rule) {
    $names = @($rule.Namespace)
    return $names.Count -eq 1 -and [string]$names[0] -ceq '.'
}
function FixedServers($rule) {
    $actual = @(Addresses $rule.NameServers)
    return $actual.Count -eq 2 -and ($actual -contains $peers[0]) -and ($actual -contains $peers[1])
}
function NoOverrides($rule) {
    foreach ($name in @('DirectAccessEnabled','DnsSecEnable','DnsSecValidationRequired','DnsSecIPsecRequired','DnsSecQueryIPsecRequired')) {
        if ($rule.$name -eq $true) { return $false }
    }
    if (@($rule.DirectAccessDnsServers | Where-Object { [string]$_ }).Count) { return $false }
    if ([string]$rule.DirectAccessProxyName) { return $false }
    $proxy = [string]$rule.DirectAccessProxyType
    return -not $proxy -or $proxy -eq 'NoProxy'
}
function Owned($rule) {
    return ([string]$rule.Comment -ceq $marker) -and ([string]$rule.DisplayName -ceq $display)
}
function FixedRule($rule) {
    return (RootNamespace $rule) -and (FixedServers $rule) -and (NoOverrides $rule)
}
function ReadRules {
    $value = @(Get-DnsClientNrptRule -ErrorAction Stop)
    if ($value.Count -gt 256) { throw 'NRPT rule bound exceeded' }
    return $value
}
function ReadEffective {
    # Query the whole effective policy: filtering only '.' hides more-specific
    # GPO/domain rules that could bypass this root resolver.
    $value = @(Get-DnsClientNrptPolicy -Effective -ErrorAction Stop)
    if ($value.Count -gt 256) { throw 'NRPT effective bound exceeded' }
    return $value
}
function SnapshotRule($rule,$local) {
    $entry = [ordered]@{namespace=@($rule.Namespace | ForEach-Object { [string]$_ });
        nameservers=@(Addresses $rule.NameServers); overrides=(-not (NoOverrides $rule))}
    if ($local) {
        $entry['name'] = [string]$rule.Name
        $entry['comment'] = [string]$rule.Comment
        $entry['display_name'] = [string]$rule.DisplayName
    }
    return $entry
}
try {
    Import-Module (Join-Path $PSHOME 'Modules\DnsClient\DnsClient.psd1') -ErrorAction Stop
    $rules = @(ReadRules)
    $effective = @(ReadEffective)
    $own = @($rules | Where-Object { Owned $_ })
    $partial = @($rules | Where-Object { (([string]$_.Comment -ceq $marker) -or ([string]$_.DisplayName -ceq $display)) -and -not (Owned $_) })
    if ($own.Count -gt 1 -or $partial.Count) {
        $failure = 'global_dns_conflict'; throw 'Ambiguous NRPT identity'
    }
    if ($own.Count -eq 1 -and -not (FixedRule $own[0])) {
        $failure = 'global_dns_changed'; throw 'Changed owned rule'
    }
    if ($own.Count -eq 1 -and [string]$own[0].Name -notmatch '^\{?[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}\}?$') {
        $failure = 'global_dns_changed'; throw 'Invalid owned unique name'
    }
    if ($operation -eq 'apply') {
        $foreign = @($rules | Where-Object { -not (Owned $_) })
        if ($foreign.Count -or ($own.Count -eq 0 -and $effective.Count) -or
            ($own.Count -eq 1 -and ($effective.Count -ne 1 -or -not (FixedRule $effective[0])))) {
            $failure = 'global_dns_conflict'; throw 'Existing DNS policy conflict'
        }
        if ($own.Count -eq 0) {
            $created = Add-DnsClientNrptRule -Namespace '.' -NameServers $peers -DisplayName $display -Comment $marker -PassThru -ErrorAction Stop
            if (-not [string]$created.Name) { throw 'Missing new NRPT identity' }
        }
        # Re-read both policy layers after creation. Do not undo the lease on
        # failure: startup's independent guard must remain fail-closed.
        $rules = @(ReadRules)
        $own = @($rules | Where-Object { Owned $_ })
        $failure = 'global_dns_not_effective'
        if ($rules.Count -ne 1 -or $own.Count -ne 1 -or -not (FixedRule $own[0])) { throw 'Unconfirmed owned rule' }
        for ($attempt = 0; $attempt -lt 5; $attempt++) {
            $effective = @(ReadEffective)
            if ($effective.Count -eq 1 -and (FixedRule $effective[0])) { break }
            if ($attempt -lt 4) { Start-Sleep -Milliseconds 100 }
        }
        if ($effective.Count -ne 1 -or -not (FixedRule $effective[0])) { throw 'Unconfirmed effective DNS' }
    } elseif ($operation -eq 'remove') {
        if ($own.Count -eq 1) {
            # Remove the exact CIM Name obtained from our fully checked rule.
            Remove-DnsClientNrptRule -Name ([string]$own[0].Name) -Force -ErrorAction Stop
        }
        $rules = @(ReadRules)
        $effective = @(ReadEffective)
        if (@($rules | Where-Object { Owned $_ }).Count) {
            $failure = 'global_dns_restore_incomplete'; throw 'Owned NRPT remains'
        }
        foreach ($policy in $effective) {
            foreach ($server in @(Addresses $policy.NameServers)) {
                if ($peers -contains $server) {
                    $failure = 'global_dns_restore_incomplete'; throw 'Virtual DNS remains effective'
                }
            }
        }
    } elseif ($operation -ne 'inspect') { throw 'Closed operation required' }
    $output = [ordered]@{ok=$true; rules=@($rules | ForEach-Object { SnapshotRule $_ $true });
        effective=@($effective | ForEach-Object { SnapshotRule $_ $false })}
} catch {
    # Do not echo arbitrary policy contents or PowerShell exception text.
    $output = [ordered]@{ok=$false; code=$failure}
}
$json = $output | ConvertTo-Json -Depth 8 -Compress
if ([Text.Encoding]::UTF8.GetByteCount($json) -gt 262144) {
    $json = '{"ok":false,"code":"global_dns_output_too_large"}'
}
[Console]::Out.Write($json)
'''


def _servers(value):
    if not isinstance(value, (list, str)):
        raise ProxyError("global_dns_invalid_response", "无法核对 NRPT DNS 服务器。")
    values = [value] if isinstance(value, str) else value
    result = []
    for item in values:
        if not isinstance(item, str) or len(item) > 4096:
            raise ProxyError("global_dns_invalid_response", "NRPT DNS 服务器无效。")
        try:
            result.extend(str(ipaddress.ip_address(part)) for part in re.split(r"[,;\s]+", item) if part)
        except ValueError as exc:
            raise ProxyError("global_dns_invalid_response", "NRPT DNS 服务器不是 IP 地址。") from exc
    return sorted(set(result))


class DnsLease:
    def __init__(self, metadata, *, runner=None, clock=None):
        if (not isinstance(metadata, dict) or not isinstance(metadata.get("root"), str)
                or not metadata["root"] or "\0" in metadata["root"]
                or not isinstance(metadata.get("owner_sid"), str) or not SID_RE.fullmatch(metadata["owner_sid"])):
            raise ProxyError("invalid_deployment", "DNS 接管缺少可信安装身份。")
        identity = hashlib.sha256((metadata["owner_sid"] + "\0" + metadata["root"].casefold()).encode()).hexdigest()
        self.marker = "RuleProxyDNS-v1:" + identity
        self.metadata = metadata
        self.display = "RuleProxy global DNS " + identity[:16]
        self._runner, self._clock = runner or self._run, clock or time.monotonic
        self.qualification = load_qualification(metadata)
        self._component_hint = runner is not None or os.name == "nt"
        self._cached, self._checked = None, 0
        self._lock = threading.RLock()
        self._query_lock = threading.Lock()
        self._sequence = 0
        self._refreshing = self._busy = False

    def refresh_qualification(self):
        self.qualification = load_qualification(self.metadata)

    @staticmethod
    def _authority(*, restore=False):
        if restore:
            from .windows_global_guard import Guard
            Guard._restore_authority()
        else:
            from .windows_proxy_client import current_user_sid
            if os.name != "nt" or current_user_sid() != "S-1-5-18":
                raise ProxyError("global_dns_access_denied", "DNS 接管仅允许已安装的 SYSTEM 服务执行。")

    def _run(self, operation):
        if os.name != "nt" or operation not in {"inspect", "apply", "remove"}:
            raise ProxyError("global_dns_unavailable", "NRPT 接管需要原生 Windows DNSClient。")
        root = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32/WindowsPowerShell/v1.0"
        executable = root / "powershell.exe"
        from .windows_proxy_service import protected_path
        for path in (root, executable, root / "Modules/DnsClient/DnsClient.psd1"):
            protected_path(path)
        script = (_SCRIPT.replace("__MARKER__", self.marker).replace("__DISPLAY__", self.display)
                  .replace("__OPERATION__", operation))
        encoded = base64.b64encode(script.encode("utf-16-le")).decode("ascii")
        if len(encoded) > 30000:
            raise ProxyError("global_dns_unavailable", "固定 DNS 控制程序超过命令长度上限。")
        try:
            result = subprocess.run([str(executable), "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
                "-EncodedCommand", encoded], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL, timeout=8, cwd=str(root),
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise ProxyError("global_dns_unavailable", "核对 Windows DNS 策略超时或失败。") from exc
        if result.returncode or not result.stdout or len(result.stdout) > MAX_OUTPUT:
            raise ProxyError("global_dns_unavailable", "Windows DNS 策略控制未返回有界结果。")
        try:
            value = json.loads(result.stdout.decode("utf-8-sig"))
        except (ValueError, UnicodeError, RecursionError) as exc:
            raise ProxyError("global_dns_invalid_response", "Windows DNS 策略结果无效。") from exc
        if not isinstance(value, dict) or value.get("ok") is not True:
            codes = {"global_dns_conflict", "global_dns_changed", "global_dns_not_effective",
                     "global_dns_restore_incomplete", "global_dns_output_too_large"}
            code = value.get("code") if isinstance(value, dict) else None
            raise ProxyError(code if code in codes else "global_dns_unavailable",
                             "NRPT 存在冲突、无法确认有效策略或恢复未完成；未修改其他 DNS 规则。")
        return value

    def _snapshot(self, value):
        rules, effective = value.get("rules"), value.get("effective")
        if (not isinstance(rules, list) or not isinstance(effective, list)
                or len(rules) > MAX_RULES or len(effective) > MAX_RULES):
            raise ProxyError("global_dns_invalid_response", "NRPT 策略清单无效。")
        own, foreign = [], []
        for rule in rules:
            if not isinstance(rule, dict):
                raise ProxyError("global_dns_invalid_response", "NRPT 规则无效。")
            tagged = rule.get("comment") == self.marker or rule.get("display_name") == self.display
            if tagged:
                if (rule.get("comment") != self.marker or rule.get("display_name") != self.display
                        or not isinstance(rule.get("name"), str) or not _GUID.fullmatch(rule["name"])
                        or not self._fixed(rule)):
                    raise ProxyError("global_dns_changed", "本工具 DNS 规则身份或内容已改变，未接管或删除。")
                own.append(rule)
            else:
                foreign.append(rule)
        if len(own) > 1:
            raise ProxyError("global_dns_conflict", "发现多个同身份 DNS 规则，未接管或删除。")
        good_effective = len(effective) == 1 and self._fixed(effective[0])
        virtual = False
        for rule in effective:
            if not isinstance(rule, dict):
                raise ProxyError("global_dns_invalid_response", "有效 NRPT 规则无效。")
            virtual = virtual or bool(set(_servers(rule.get("nameservers"))) & set(PEERS))
        conflict = bool(foreign) or (bool(effective) and not (own and good_effective))
        detail = ("已有非自有 NRPT 或有效策略冲突，拒绝全局接管；其他 DNS 规则保持原样。" if conflict else
                  "自有 NRPT 尚未确认生效，拒绝启动全局核心。" if own and not good_effective else
                  "自有根 NRPT 已回读生效；实际双栈 DNS 转发尚未通过 Windows 原生资格验证。" if own else
                  "NRPT 只读预检通过；尚未启用本工具的 DNS 接管。")
        return {"supported": True, "component_available": True, "active": bool(own),
                "effective": bool(own) and good_effective and not conflict,
                "persistent": bool(own), "native_qualified": self.qualification["native_qualified"],
                "qualification": dict(self.qualification), "strict_isolation": False,
                "state": "conflict" if conflict else "candidate_active" if own and good_effective else
                         "not_effective" if own else "idle",
                "owned_rule_names": [item["name"] for item in own], "namespace": ".", "nameservers": list(PEERS),
                "foreign_rule_count": len(foreign), "effective_rule_count": len(effective),
                "virtual_dns_in_effective": virtual,
                "detail": detail,
                "limitations": ["已有任意非自有 NRPT 或冲突生效策略时拒绝启动，保留其他 DNS 配置。",
                                "不修改网卡 DNS；核心或面板故障保留规则，显式停止后才精确删除。"]}

    @staticmethod
    def _fixed(rule):
        if not isinstance(rule, dict) or rule.get("namespace") != ["."] or rule.get("overrides") is not False:
            return False
        return _servers(rule.get("nameservers")) == sorted(PEERS)

    @contextmanager
    def _exclusive(self):
        # The subprocess has an 8s deadline; another explicit operation may
        # wait for at most that one in-flight query, never an unbounded queue.
        if not self._query_lock.acquire(timeout=9):
            raise ProxyError("global_dns_busy", "DNS 策略仍在核验，请稍后重试。")
        with self._lock:
            self._busy = True
        try:
            yield
        finally:
            with self._lock:
                self._busy = False
            self._query_lock.release()

    def _store(self, result):
        # Qualification is capability, while strict requires this fresh native
        # inspection. Cached/checking/unknown observations never become strict.
        result = {**result, "native_qualified": self.qualification["native_qualified"],
                  "qualification": dict(self.qualification),
                  "strict_isolation": self.qualification["native_qualified"] is True
                  and all(result.get(key) is True for key in ("supported", "active", "effective", "persistent"))
                  and result.get("state") == "candidate_active"}
        if result["strict_isolation"]:
            result["detail"] = "运行期 DNS 资格与自有 NRPT 当前有效策略已核对；不保证系统早期启动。"
        with self._lock:
            self._cached, self._checked = dict(result), self._clock()
            self._sequence += 1
        return {**result, "fresh": True, "verification_pending": False, "last_verified_age_seconds": 0}

    def _inspect(self, before):
        with self._exclusive():
            with self._lock:
                if self._sequence != before and self._cached is not None:
                    return {**self._cached, "fresh": True, "verification_pending": False,
                            "last_verified_age_seconds": max(0, self._clock() - self._checked)}
            try:
                result = self._snapshot(self._runner("inspect"))
            except (OSError, ValueError, ProxyError) as exc:
                result = {"supported": False, "component_available": self._component_hint,
                    "active": None, "effective": False, "persistent": None,
                    "native_qualified": False, "strict_isolation": False, "state": "unavailable",
                    "code": getattr(exc, "code", "global_dns_unavailable"), "detail": str(exc),
                    "namespace": ".", "nameservers": list(PEERS), "owned_rule_names": []}
            return self._store(result)

    def _background(self, before):
        try:
            self._inspect(before)
        except (OSError, ValueError, ProxyError) as exc:
            self._store({"supported": False, "component_available": self._component_hint,
                "active": None, "effective": False, "persistent": None, "native_qualified": False,
                "strict_isolation": False, "state": "unavailable", "code": getattr(exc, "code", "global_dns_unavailable"),
                "detail": "后台 DNS 策略核验尚未完成，当前有效性未知。", "namespace": ".",
                "nameservers": list(PEERS), "owned_rule_names": []})
        finally:
            with self._lock:
                self._refreshing = False

    def status(self, *, refresh=False):
        with self._lock:
            before = self._sequence
            age = max(0, self._clock() - self._checked) if self._cached is not None else None
            if not refresh and age is not None and age < 2:
                return {**self._cached, "fresh": True, "verification_pending": False,
                        "last_verified_age_seconds": age}
            if not refresh:
                result = {"supported": self._component_hint, "component_available": self._component_hint,
                    "active": None, "effective": False, "persistent": None,
                    "native_qualified": self.qualification["native_qualified"],
                    "qualification": dict(self.qualification), "strict_isolation": False, "state": "checking",
                    "fresh": False, "verification_pending": True, "last_verified_age_seconds": age,
                    "last_observed_active": self._cached.get("active") if self._cached else None,
                    "namespace": ".", "nameservers": list(PEERS), "owned_rule_names": [],
                    "detail": "DNS 策略正在核验，当前有效性尚未确认；启动时会同步校验。"}
                if not self._refreshing and not self._busy:
                    self._refreshing = True
                    threading.Thread(target=self._background, args=(before,), daemon=True).start()
                return result
        return self._inspect(before)

    def apply(self):
        self._authority()
        with self._exclusive():
            self.refresh_qualification()
            with self._lock:
                self._cached = None
            result = self._snapshot(self._runner("apply"))
            if not result["active"] or not result["effective"] or result["state"] == "conflict":
                raise ProxyError("global_dns_not_effective", "无法核对本工具 DNS 接管已生效，拒绝启动全局核心。")
            return self._store(result)

    def normal_stop(self):
        self._authority(restore=True)
        with self._exclusive():
            with self._lock:
                self._cached = None
            result = self._snapshot(self._runner("remove"))
            if result["active"] or result["virtual_dns_in_effective"]:
                raise ProxyError("global_dns_restore_incomplete", "本工具 DNS 规则仍在，未撤销独立保护。")
            return {**self._store(result), "stopped": True}

    def crash_keep(self):
        # Shutdown/crash handling never creates a new PowerShell child or waits
        # for an in-flight query. In particular, an SCM stop must stay bounded
        # even when DNSClient/WMI is unavailable.
        with self._lock:
            age = max(0, self._clock() - self._checked) if self._cached is not None else None
            if age is not None and age < 2:
                result = {**self._cached, "fresh": True, "verification_pending": False,
                          "last_verified_age_seconds": age}
            else:
                result = {"supported": self._component_hint, "component_available": self._component_hint,
                    "active": None, "effective": False, "persistent": None,
                    "native_qualified": self.qualification["native_qualified"],
                    "qualification": dict(self.qualification),
                    "strict_isolation": False, "state": "checking", "fresh": False,
                    "verification_pending": True, "last_verified_age_seconds": age,
                    "last_observed_active": self._cached.get("active") if self._cached else None,
                    "namespace": ".", "nameservers": list(PEERS), "owned_rule_names": [],
                    "detail": "故障处理保留 DNS 规则；尚未重新核验当前有效状态。"}
        return {**result, "retained_after_failure": result.get("active"), "restore_attempted": False}
