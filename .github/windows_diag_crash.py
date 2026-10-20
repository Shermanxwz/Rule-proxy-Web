"""Diagnostic lab: capture the first fault of stock browsers inside a zero-capability AppContainer.

Every browser process is created SUSPENDED in its own kill-on-close Job. A cdb.exe debugger is
attached with -pb while the browser is still suspended, and only then is the primary thread
resumed, so the first instruction is observed. IFEO GlobalFlag FLG_SHOW_LDR_SNAPS (0x2) makes the
loader print its snaps, which reach the attached debugger. Event filters print the fault record,
stack and module list. Only trimmed text is reported: no raw debugger log, dump or debugger binary
is exported. Diagnostic only; nothing here qualifies a product or real TLS/OAuth behaviour.
"""
from __future__ import annotations

import argparse
import base64
import dataclasses
import functools
import json
import os
import platform
import re
import secrets
import subprocess
import sys
import threading
import time
from contextlib import contextmanager, nullcontext
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import windows_appcontainer_compat as compat  # noqa: E402  (module level has no side effects)

lab = None  # Loaded by main() after the runner guard; lab's import mutates sys.path and binds ctypes.
WORK = Path(r'C:\RuleProxyDiagCrash')
IMAGES = ('chrome.exe', 'msedge.exe', 'firefox.exe')
IFEO_KEY = r'SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options'
FLG_SHOW_LDR_SNAPS = 0x2
CREATE_SUSPENDED = 0x4
CREATE_NO_WINDOW = 0x08000000
KILL_ON_JOB_CLOSE = 0x2000
WAIT_TIMEOUT = 258
RUN_CAP_MS = 40_000
CDB_GRACE_MS = 15_000
ATTACH_CAP_S = 15.0
BUDGET_S = 22 * 60
HEADLESS_FLAG = '--headless=new'  # headed rows differ from headless rows by this flag only
LOGGING_FLAGS = ('--enable-logging=stderr', '--v=1', '--disable-crash-reporter')
# Executed with -cf (a script file) so no quote escaping crosses the Windows command line.
# av/bpe print the record and CONTINUE with the exception unhandled (gn): the loader raises a benign
# breakpoint while a debugged process initialises, so quitting there would end every session before
# the browser's own int3. Only the process-exit event quits the debugger.
CDB_SCRIPT = (
    'sxe -c ".echo ===EXC_AV;.exr -1;kv 60;lm;.echo ===END;gn" av\n'
    'sxe -c ".echo ===EXC_BPE;.exr -1;kv 60;lm;.echo ===END;gn" bpe\n'
    'sxe -c ".echo ===PROCESS_EXIT;kv 60;.echo ===END;q" epr\n'
    'g\n'
)
WARM_SCRIPT = '.reload /f\nlm\n.echo ===WARM_DONE\nq\n'
BLOCK_START = re.compile(r'===(EXC_AV|EXC_BPE|PROCESS_EXIT)\b')
LOADER_FAILURE = re.compile(r'(?i)(fail|error|denied|not found|status|c0000|\bldr\b.*(?:fail|error)'
                            r'|unable|cannot|access_denied)')
CHECK_LINE = re.compile(r'(?i)\bFATAL\b|check failed|\bCHECK\b|ImmediateCrash')
FRAME = re.compile(r'^\s*[0-9a-fA-F]{2}\s+[0-9a-fA-F`]{8,}\s+[0-9a-fA-F`]{8,}\s.*?'
                   r'\b([A-Za-z_][\w.\-]*(?:![\w:~`<>.\-]+)?\+0x[0-9a-fA-F]+)')
BENIGN_FRAME = re.compile(r'(?i)^ntdll!(?:LdrpDoDebuggerBreak|DbgBreakPoint|LdrpInitializeProcess|LdrInitializeThunk)')
EXC_CODE = re.compile(r'ExceptionCode:\s*([0-9a-fA-F]{8})')
EXC_ADDRESS = re.compile(r'ExceptionAddress:\s*(\S+(?:\s+\([^)]*\))?)')

EVENT_SCRIPT = r'''$image=$env:RP_DIAG_IMAGE; $leaf=[IO.Path]::GetFileName($image); $out=@()
Get-WinEvent -FilterHashtable @{LogName='Application';Id=@(1000,1001);StartTime=(Get-Date).AddSeconds(-__SECONDS__)} -MaxEvents 64 -ErrorAction SilentlyContinue | ForEach-Object {
 if($_.Id -eq 1001){
  if($_.Message -like "*$leaf*"){ $out += [ordered]@{id=1001;text=$_.Message.Substring(0,[Math]::Min(800,$_.Message.Length))} }
 } else {
  $data=@{}; foreach($d in ([xml]$_.ToXml()).Event.EventData.Data){ $data[[string]$d.Name]=[string]$d.'#text' }
  if($data.AppPath -ieq $image){ $out += [ordered]@{id=1000;process_id_hex=$data.ProcessId;exception=$data.ExceptionCode;module=$data.ModuleName;module_version=$data.ModuleVersion;offset=$data.FaultingOffset;app_version=$data.AppVersion} }
 }
};ConvertTo-Json -InputObject @($out | Select-Object -First 16) -Compress
'''
VERSION_SCRIPT = (
    '$files=@(ConvertFrom-Json $env:RP_DIAG_FILES); $out=[ordered]@{}; '
    'foreach($f in $files){ if(Test-Path -LiteralPath $f){ $out[$f]=(Get-Item -LiteralPath $f).VersionInfo.ProductVersion } }; '
    'ConvertTo-Json -InputObject $out -Compress')


@dataclasses.dataclass(frozen=True)
class Case:
    family: str
    variant: str
    flags: tuple = ()
    contained: bool = True
    debugged: bool = True
    diagnostic: bool = False
    headed: bool = False

    @property
    def label(self) -> str:
        return f'{self.family}_{self.variant}'


@dataclasses.dataclass
class Context:
    api: object
    work: Path
    sid: object
    env: dict
    cdb_env: dict
    proxy: object
    debugger: Path | None
    errors: list


def plan(families):
    chromium = [family for family in ('chrome', 'edge') if family in families]
    cases = [Case(family, 'contained') for family in chromium]
    cases += [Case(family, 'contained_logging', flags=LOGGING_FLAGS, debugged=False) for family in chromium]
    cases += [Case(family, 'diagnostic_no_sandbox', flags=('--no-sandbox',), diagnostic=True) for family in chromium]
    cases += [Case(family, 'control', contained=False) for family in chromium]
    cases += [Case(family, 'contained_headed', headed=True) for family in chromium]
    if 'firefox' in families:
        cases += [Case('firefox', 'contained'), Case('firefox', 'control', contained=False)]
    return cases


def notice(text, limit=2900):
    body = text
    while True:
        escaped = body.replace('%', '%25').replace('\r', '%0D').replace('\n', '%0A')
        if len(escaped) <= limit:
            return '::notice title=crash-debug::' + escaped
        body = body[:int(len(body) * 0.9)]


def powershell(script, env, timeout=20):
    encoded = base64.b64encode(script.encode('utf-16-le')).decode('ascii')
    run = subprocess.run(['powershell', '-NoProfile', '-NonInteractive', '-EncodedCommand', encoded],
                         capture_output=True, timeout=timeout, env=env)
    return run.stdout.decode('utf-8-sig', errors='replace')


def file_versions(paths, env):
    try:
        value = json.loads(powershell(VERSION_SCRIPT, {**env, 'RP_DIAG_FILES': json.dumps(paths)}) or '{}')
        return value if isinstance(value, dict) else {}
    except (ValueError, OSError, subprocess.TimeoutExpired):
        return {}


def image_events(program, since, env):
    seconds = min(120, max(1, int(time.time() - since) + 3))
    try:
        text = powershell(EVENT_SCRIPT.replace('__SECONDS__', str(seconds)), {**env, 'RP_DIAG_IMAGE': str(program)})
        value = json.loads(text) if text.strip() else []
        return value if isinstance(value, list) else [value]
    except (ValueError, OSError, subprocess.TimeoutExpired) as exc:
        return [{'error': f'{type(exc).__name__}: {exc}'[:200]}]


def cdb_introspection(debugger, work, env):
    """Record what this cdb build says about the option and filter names used below."""
    result = {}
    try:
        run = subprocess.run([str(debugger), '-c', 'sx;q'], capture_output=True, timeout=30, env=env, cwd=work,
                             creationflags=CREATE_NO_WINDOW)
        text = (run.stdout + run.stderr).decode('utf-8', errors='replace')
        result['sx_exit'] = run.returncode
        result['sx_filter_lines'] = [line[:200] for line in text.splitlines()
                                     if re.search(r'\b(av|bpe|epr)\b', line)][:12]
    except (OSError, subprocess.TimeoutExpired) as exc:
        result['sx_error'] = f'{type(exc).__name__}: {exc}'[:200]
    try:
        run = subprocess.run([str(debugger), '-?'], capture_output=True, timeout=30, env=env, cwd=work,
                             creationflags=CREATE_NO_WINDOW)
        text = (run.stdout + run.stderr).decode('utf-8', errors='replace')
        result['usage_lines'] = [line[:200] for line in text.splitlines()
                                 if re.search(r'-pb\b|-logo\b|-loga\b|-pv\b|-p\s', line)][:12]
    except (OSError, subprocess.TimeoutExpired) as exc:
        result['usage_error'] = f'{type(exc).__name__}: {exc}'[:200]
    return result


def warm_symbols(debugger, work, env):
    """Download the OS symbols once, so the first fault inside a browser run is not spent fetching them."""
    script = work / 'cdb-warm.cmd.txt'
    script.write_text(WARM_SCRIPT, encoding='ascii')
    started = time.monotonic()
    try:
        run = subprocess.run([str(debugger), '-cf', str(script), r'C:\Windows\System32\cmd.exe', '/c', 'exit'],
                             capture_output=True, timeout=180, env=env, cwd=work, creationflags=CREATE_NO_WINDOW)
        text = (run.stdout + run.stderr).decode('utf-8', errors='replace')
        return {'seconds': round(time.monotonic() - started, 1), 'exit': run.returncode,
                'done': '===WARM_DONE' in text,
                'module_lines': [line[:200] for line in text.splitlines()
                                 if re.search(r'(?i)\b(ntdll|kernel32|kernelbase)\b', line)][:6]}
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {'seconds': round(time.monotonic() - started, 1), 'error': f'{type(exc).__name__}: {exc}'[:200]}


@functools.lru_cache(maxsize=None)
def _ntdll():
    import ctypes as C
    dll = C.WinDLL('ntdll', use_last_error=True)
    dll.NtQueryInformationProcess.argtypes = [C.c_void_p, C.c_ulong, C.c_void_p, C.c_ulong, C.POINTER(C.c_ulong)]
    dll.NtQueryInformationProcess.restype = C.c_long
    return dll


def debug_object_attached(api, process) -> bool:
    """True when the kernel reports a debug object for the process (ProcessDebugObjectHandle = 30)."""
    import ctypes as C
    value, returned = C.c_void_p(), C.c_ulong()
    status = _ntdll().NtQueryInformationProcess(process, 30, C.addressof(value), C.sizeof(value),
                                                C.byref(returned))
    if status == 0 and value.value:
        api.close_handle(value.value)
        return True
    return False


def _query(key, name):
    import winreg
    try:
        return winreg.QueryValueEx(key, name)  # (value, registry type)
    except FileNotFoundError:
        return None


@contextmanager
def ldr_snaps(images, errors):
    """IFEO GlobalFlag = FLG_SHOW_LDR_SNAPS in both registry views; restore exactly what existed."""
    import winreg
    saved = []
    try:
        for image in images:
            path = IFEO_KEY + '\\' + image
            for view in (winreg.KEY_WOW64_64KEY, winreg.KEY_WOW64_32KEY):
                access = winreg.KEY_QUERY_VALUE | winreg.KEY_SET_VALUE | view
                try:
                    key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path, 0, access)
                    created = False
                except FileNotFoundError:
                    key = winreg.CreateKeyEx(winreg.HKEY_LOCAL_MACHINE, path, 0, access)
                    created = True
                with key:
                    if _query(key, 'Debugger') is not None:
                        raise RuntimeError(f'IFEO Debugger value already set for {image}; refusing to run')
                    previous = _query(key, 'GlobalFlag')
                    saved.append((path, view, created, previous))
                    winreg.SetValueEx(key, 'GlobalFlag', 0, winreg.REG_DWORD, FLG_SHOW_LDR_SNAPS)
        yield
    finally:
        for path, view, created, previous in reversed(saved):
            try:
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path, 0,
                                    winreg.KEY_QUERY_VALUE | winreg.KEY_SET_VALUE | view) as key:
                    if previous is None:
                        try:
                            winreg.DeleteValue(key, 'GlobalFlag')
                        except FileNotFoundError:
                            pass
                    else:
                        winreg.SetValueEx(key, 'GlobalFlag', 0, previous[1], previous[0])
                    subkeys, values, _stamp = winreg.QueryInfoKey(key)
                if created and subkeys == 0 and values == 0:
                    winreg.DeleteKeyEx(winreg.HKEY_LOCAL_MACHINE, path, view, 0)
            except OSError as exc:
                errors.append(f'ifeo restore {path} view={view}: {exc}')


@contextmanager
def local_dumps(folder, images, errors):
    """WER LocalDumps pointed at our work folder; dumps are measured, never exported."""
    import winreg
    saved = []
    try:
        for image in images:
            path = compat.LOCALDUMPS + '\\' + image
            try:
                winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path).Close()
                created = False
            except FileNotFoundError:
                created = True
            with winreg.CreateKeyEx(winreg.HKEY_LOCAL_MACHINE, path, 0,
                                    winreg.KEY_QUERY_VALUE | winreg.KEY_SET_VALUE) as key:
                old = {}
                for field, value, kind in (('DumpFolder', str(folder), winreg.REG_EXPAND_SZ),
                                           ('DumpType', 1, winreg.REG_DWORD), ('DumpCount', 3, winreg.REG_DWORD)):
                    old[field] = _query(key, field)
                    winreg.SetValueEx(key, field, 0, kind, value)
                saved.append((path, created, old))
        yield
    finally:
        for path, created, old in reversed(saved):
            try:
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path, 0,
                                    winreg.KEY_QUERY_VALUE | winreg.KEY_SET_VALUE) as key:
                    for field, previous in old.items():
                        if previous is None:
                            try:
                                winreg.DeleteValue(key, field)
                            except FileNotFoundError:
                                pass
                        else:
                            winreg.SetValueEx(key, field, 0, previous[1], previous[0])
                    subkeys, values, _stamp = winreg.QueryInfoKey(key)
                if created and subkeys == 0 and values == 0:
                    winreg.DeleteKey(winreg.HKEY_LOCAL_MACHINE, path)
            except OSError as exc:
                errors.append(f'LocalDumps restore {path}: {exc}')


def kill_strays(errors):
    for image in (*IMAGES, 'cdb.exe'):
        try:
            subprocess.run(['taskkill', '/F', '/T', '/IM', image], capture_output=True, timeout=30)
        except (OSError, subprocess.TimeoutExpired) as exc:
            errors.append(f'taskkill {image}: {exc}')


class Child:
    """A process created SUSPENDED in its own kill-on-close Job. Nothing runs until resume()."""

    def __init__(self, api):
        self.api = api
        self.job = api.create_job()
        self.process = lab.PROCESS_INFORMATION()
        self.started, self.error, self.pid, self.resumed_at = False, None, None, None
        api.configure_job(self.job, KILL_ON_JOB_CLOSE)

    def resume(self) -> int:
        """ResumeThread on the primary thread. Previous suspend count 1 is expected; 0 means it was never suspended."""
        import ctypes as C
        kernel = lab.kernel
        kernel.ResumeThread.argtypes = [C.c_void_p]
        kernel.ResumeThread.restype = C.c_ulong
        previous = kernel.ResumeThread(self.process.hThread)
        if previous in (0, 0xFFFFFFFF):
            raise OSError(f'ResumeThread previous count {previous}, last error {C.get_last_error()}')
        # A debugger attach can leave one extra suspend count (freeze) behind; release it so the
        # browser does not sit frozen until the run cap. The first count is still what gets recorded.
        remaining = previous
        for _ in range(8):
            if remaining <= 1:
                break
            remaining = kernel.ResumeThread(self.process.hThread)
            if remaining == 0xFFFFFFFF:
                raise OSError(f'ResumeThread failed after count {previous}, last error {C.get_last_error()}')
        self.resumed_at = time.monotonic()
        return previous

    def running(self) -> bool:
        return self.api.wait_process(self.process.hProcess, 0) == WAIT_TIMEOUT

    def wait(self, milliseconds) -> bool:
        """True when the process is still running after the wait."""
        return self.api.wait_process(self.process.hProcess, milliseconds) == WAIT_TIMEOUT

    def exit_code(self) -> int:
        return self.api.exit_code(self.process.hProcess)

    def kill(self):
        try:
            self.api.terminate_job(self.job)
        except OSError:
            pass

    def close(self, errors):
        if self.job:
            self.kill()
            try:
                self.api.close_handle(self.job)
            except OSError as exc:
                errors.append(f'close job: {exc}')
            self.job = None
        for name in ('hThread', 'hProcess'):
            handle = getattr(self.process, name)
            if handle:
                try:
                    self.api.close_handle(handle)
                except OSError as exc:
                    errors.append(f'close {name}: {exc}')
                setattr(self.process, name, None)


def spawn(api, argv, *, env, cwd, log, sid=None):
    """CreateProcessW(SUSPENDED [+ zero-capability AppContainer]) with stdio to log, then Job assignment.

    Mirrors compat.launch_owned: same attribute list, handle inheritance and environment block.
    """
    import ctypes as C
    import msvcrt
    child = Child(api)
    try:
        with log.open('wb') as stream:
            handle = msvcrt.get_osfhandle(stream.fileno())
            os.set_handle_inheritable(handle, True)
            try:
                info = lab.STARTUPINFOEXW()
                info.StartupInfo.cb = C.sizeof(info)
                info.StartupInfo.dwFlags = lab.STARTF_USESTDHANDLES
                info.StartupInfo.hStdOutput = info.StartupInfo.hStdError = handle
                size = C.c_size_t()
                lab.kernel.InitializeProcThreadAttributeList(None, 1, 0, C.byref(size))
                attributes = C.create_string_buffer(size.value)
                if not lab.kernel.InitializeProcThreadAttributeList(attributes, 1, 0, C.byref(size)):
                    raise C.WinError(C.get_last_error())
                try:
                    if sid is not None:
                        capabilities = lab.SECURITY_CAPABILITIES(sid.value, None, 0, 0)
                        if not lab.kernel.UpdateProcThreadAttribute(
                                attributes, 0, lab.PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES,
                                C.byref(capabilities), C.sizeof(capabilities), None, None):
                            raise C.WinError(C.get_last_error())
                        info.lpAttributeList = C.cast(attributes, C.c_void_p)
                    flags = (lab.EXTENDED_STARTUPINFO_PRESENT | lab.CREATE_NO_WINDOW
                             | lab.CREATE_UNICODE_ENVIRONMENT | CREATE_SUSPENDED)
                    command = C.create_unicode_buffer(subprocess.list2cmdline(argv), 32768)
                    if not lab.kernel.CreateProcessW(None, command, None, None, True, flags,
                                                     lab.environment_block(env), str(cwd),
                                                     C.byref(info), C.byref(child.process)):
                        child.error = C.get_last_error()
                        return child
                    child.started, child.pid = True, child.process.dwProcessId
                    api.assign_job(child.job, child.process.hProcess)
                finally:
                    lab.kernel.DeleteProcThreadAttributeList(attributes)
            finally:
                os.set_handle_inheritable(handle, False)
    except BaseException:
        child.close([])
        raise
    return child


def read_cdb_log(path):
    if not path.is_file():
        return ''
    data = path.read_bytes()
    if data[:2] in (b'\xff\xfe', b'\xfe\xff'):
        return data.decode('utf-16', errors='replace')
    return data.decode('utf-8', errors='replace')


def trim_cdb(text):
    """Event blocks kept whole (<=12000 chars) in log order, first 2 + last 6 when there are many;
    head/tail 120 lines; <=200 loader-failure lines outside blocks."""
    lines = text.splitlines()
    events, inside, name, body = [], set(), None, []
    for index, line in enumerate(lines):
        if name is None:
            start = BLOCK_START.search(line)
            if start is None:
                continue
            name, body = start.group(1), []
        inside.add(index)
        body.append(line)
        if '===END' in line:
            events.append((name, '\n'.join(body)))
            name = None
    if name is not None:
        events.append((name, '\n'.join(body) + '\n[log ended inside block]'))
    omitted = max(0, len(events) - 8)
    kept = events if not omitted else events[:2] + events[-6:]
    blocks = {}
    for kind, block in kept:
        blocks.setdefault(kind, []).append(block[:12000] + ('\n[truncated]' if len(block) > 12000 else ''))
    outside = [line for index, line in enumerate(lines) if index not in inside]
    return {'lines': len(lines), 'head': [line[:300] for line in lines[:120]],
            'tail': [line[:300] for line in lines[-120:]],
            'loader_matches': [line[:300] for line in outside if LOADER_FAILURE.search(line)][:200],
            'blocks': blocks, 'order': [kind for kind, _block in kept], 'events_total': len(events),
            'events_omitted': omitted}


def parse_fault(blocks, order=()):
    """The LAST exception block wins: a debugged process first raises the loader's own initial
    breakpoint, which is skipped explicitly, and the real fault is the final one before the exit."""
    seen, sequence = {}, []
    for kind in order:
        index = seen.get(kind, 0)
        seen[kind] = index + 1
        items = blocks.get(kind, [])
        if kind in ('EXC_AV', 'EXC_BPE') and index < len(items):
            sequence.append((kind, items[index]))
    if not sequence:
        sequence = [(kind, item) for kind in ('EXC_AV', 'EXC_BPE') for item in blocks.get(kind, [])]
    candidates = []
    for kind, text in sequence:
        code = EXC_CODE.search(text)
        address = EXC_ADDRESS.search(text)
        frame = None
        for line in text.splitlines():
            match = FRAME.search(line)
            if match:
                frame = match.group(1)
                break
        if code or frame:
            candidates.append({'block': kind, 'code': code.group(1) if code else None,
                               'address': address.group(1) if address else None, 'frame': frame})
    real = [item for item in candidates if not (item['frame'] and BENIGN_FRAME.search(item['frame']))]
    chosen = real or candidates
    return {**chosen[-1], 'candidates': len(candidates)} if chosen else None


def signature_of(fault, loader_matches, check_lines, exit_code):
    if fault and fault['frame']:
        return fault['frame'] + (f" [exc {fault['code']}]" if fault['code'] else '')
    failure = next((line for line in reversed(loader_matches) if re.search(r'(?i)fail|error', line)), None)
    if failure:
        return failure
    if check_lines:
        return check_lines[-1]
    if exit_code is None:
        return 'not run'
    return f'no fault frame; exit=0x{exit_code & 0xFFFFFFFF:08x}'


class Cdb:
    """cdb.exe attached with -pb to a still-suspended browser. Own Job; no -o (children) in this pass."""

    def __init__(self, api, debugger, work, label, pid, env):
        self.api = api
        self.log = work / f'cdb-{label}.log'
        self.stdout = work / f'cdb-{label}.stdout.txt'
        script = work / f'cdb-{label}.cmd.txt'
        script.write_text(CDB_SCRIPT, encoding='ascii')
        argv = [str(debugger), '-pb', '-p', str(pid), '-logo', str(self.log), '-cf', str(script)]
        self.child = spawn(api, argv, env=env, cwd=work, log=self.stdout)
        self.exit_code = None
        self.timed_out = None
        if self.child.started:
            self.child.resume()

    def ready(self, browser) -> str:
        """Attached (kernel debug object on the suspended PID) and the cdb log stable for 1.5 s."""
        deadline = time.monotonic() + ATTACH_CAP_S
        attached_at, size, stable_since = None, -1, None
        while time.monotonic() < deadline:
            if not self.child.running():
                return 'cdb_exited_before_attach'
            now = time.monotonic()
            if attached_at is None and debug_object_attached(self.api, browser.process.hProcess):
                attached_at = now
            current = self.log.stat().st_size if self.log.exists() else 0
            if current != size:
                size, stable_since = current, now
            if attached_at is not None and now - attached_at >= 1.5 and now - stable_since >= 1.5:
                return 'ready'
            time.sleep(0.2)
        return 'attach_timeout'

    def finish(self):
        self.timed_out = self.child.wait(CDB_GRACE_MS)
        if self.timed_out:
            self.child.kill()
            self.child.wait(5000)
        self.exit_code = self.child.exit_code()

    def evidence(self):
        text = read_cdb_log(self.log)
        evidence = trim_cdb(text)
        evidence.update(log_bytes=len(text.encode('utf-8', errors='replace')), exit_code=self.exit_code,
                        timed_out=self.timed_out, stdout_tail=compat.read_tail(self.stdout, 2000)
                        if self.stdout.exists() else '')
        return evidence


def new_dumps(folder, before):
    found = sorted(set(folder.glob('*.dmp')) - before)[:3]
    return [{'name': dump.name, 'bytes': dump.stat().st_size, 'exported': False,
             'sha256': compat.digest(dump) if dump.stat().st_size <= 16 * 1024 * 1024 else None}
            for dump in found]


def check_lines_of(path):
    text = compat.read_tail(path, 8 * 1024 * 1024) if path.exists() else ''
    return [line[:300] for line in text.splitlines() if CHECK_LINE.search(line)][-40:]


def run_case(case, ctx):
    """Loader snaps are read by ntdll AFTER the suspended process is resumed, so GlobalFlag must stay
    set for the whole row; uncontained controls get none (they would flood the debugger log)."""
    program = compat.PROGRAMS[case.family]
    snaps = case.contained and case.debugged and ctx.debugger is not None
    with (ldr_snaps([program.name], ctx.errors) if snaps else nullcontext()):
        return _run_case(case, ctx)


def _run_case(case, ctx):
    program = compat.PROGRAMS[case.family]
    profile = ctx.work / case.label
    profile.mkdir()
    log = ctx.work / (case.label + '.log')
    shot = ctx.work / (case.label + '.png') if case.family == 'firefox' else None
    url = ctx.proxy.url(case.label)
    if shot is not None:
        argv = compat.firefox_args(profile, ctx.proxy.port, shot, url)
    else:
        base = [flag for flag in compat.BASE if not (case.headed and flag == HEADLESS_FLAG)]
        argv = [*base, f'--user-data-dir={profile}', f'--proxy-server=http://127.0.0.1:{ctx.proxy.port}',
                '--proxy-bypass-list=<-loopback>', *case.flags, '--dump-dom', url]
    wants_debugger = case.debugged and ctx.debugger is not None
    entry = {'family': case.family, 'variant': case.variant, 'contained': case.contained, 'headed': case.headed,
             'diagnostic_only': case.diagnostic, 'debugger_requested': wants_debugger,
             'debugger_attached': False, 'attach_state': None, 'argv': argv, 'pid': None, 'started': False,
             'exit_code': None, 'timed_out': None, 'seconds': None, 'resume_previous_count': None,
             'error': None, 'harness_error': None}
    dumps_before = set((ctx.work / 'dumps').glob('*.dmp'))
    wall_start = time.time()
    browser = spawn(ctx.api, [str(program), *argv], env=ctx.env, cwd=program.parent, log=log,
                    sid=ctx.sid if case.contained else None)
    cdb = None
    try:
        entry['started'] = browser.started
        if not browser.started:
            entry['error'] = f'CreateProcessW error {browser.error}'
        else:
            entry['pid'] = browser.pid
            if wants_debugger:
                cdb = Cdb(ctx.api, ctx.debugger, ctx.work, case.label, browser.pid, ctx.cdb_env)
                entry['attach_state'] = cdb.ready(browser) if cdb.child.started else 'cdb_not_started'
                entry['debugger_attached'] = entry['attach_state'] == 'ready'
            if wants_debugger and not entry['debugger_attached']:
                entry['error'] = 'debugger did not attach; browser was never resumed'
            else:
                entry['resume_previous_count'] = browser.resume()
                entry['timed_out'] = browser.wait(RUN_CAP_MS)
                if entry['timed_out']:
                    browser.kill()
                    browser.wait(5000)
                entry['seconds'] = round(time.monotonic() - browser.resumed_at, 3)
                entry['exit_code'] = browser.exit_code()
                if cdb is not None:
                    cdb.finish()
    finally:
        if cdb is not None:
            cdb.child.kill()
            cdb.child.wait(5000)
            cdb.child.close(ctx.errors)
        browser.close(ctx.errors)
    if browser.started:
        time.sleep(3)  # WER writes its events and any dump after the process is gone
        entry['events'] = {'same_pid_1000': compat.crash_events(wall_start, program, browser.pid),
                           'image_events': image_events(program, wall_start, ctx.env)}
    evidence = cdb.evidence() if cdb is not None else None
    entry['cdb'] = evidence
    text = compat.read_tail(log)
    entry['stderr_tail'] = text[-6000:]
    entry['check_lines'] = check_lines_of(log)
    entry['fixture_requests'] = ctx.proxy.count(case.label)
    entry['rendered'] = compat.png_valid(shot) if shot is not None else ctx.proxy.marker(case.label) in text
    entry['render_evidence'] = 'valid_png_and_proxy_receipt' if shot is not None else 'dom_nonce_and_proxy_receipt'
    entry['dumps'] = new_dumps(ctx.work / 'dumps', dumps_before)
    entry['fault'] = parse_fault(evidence['blocks'], evidence['order']) if evidence else None
    entry['signature'] = signature_of(entry['fault'], evidence['loader_matches'] if evidence else [],
                                      entry['check_lines'], entry['exit_code'])
    return entry


def grant_package(work, package, report):
    """Give the package SID full control of the (still empty) fixture tree, before any tool writes into it.
    The first CI run failed with icacls exit 5 here because the grant ran after cdb had written logs: files
    created later inherit the ACE, so the grant belongs first. /C keeps going past a single bad file."""
    done = subprocess.run(['icacls', str(work), '/grant', f'*{package}:(OI)(CI)(F)', '/T', '/Q', '/C'],
                          capture_output=True, text=True, errors='replace', timeout=120)
    report['acl_grant'] = {'exit_code': done.returncode, 'tail': ((done.stdout or '') + (done.stderr or ''))[-400:]}
    return done.returncode == 0


def main() -> int:
    sys.stdout.reconfigure(encoding='utf-8', errors='backslashreplace')
    global lab
    parser = argparse.ArgumentParser()
    parser.add_argument('--work', type=Path, required=True)
    work = parser.parse_args().work.resolve()
    if os.name != 'nt' or os.environ.get('GITHUB_ACTIONS') != 'true' or work != WORK:
        raise RuntimeError('requires disposable Windows Actions runner and fixed work directory')
    if work.exists():
        raise RuntimeError('diagnostic work directory already exists')
    for name in ('tmp', 'home', 'local', 'roaming', 'dumps'):
        (work / name).mkdir(parents=True)
    import windows_appcontainer_lab as lab  # noqa: E402  (after the guard, as compat does)
    from ruleproxy.windows_app_process import _get_api

    started = time.monotonic()
    version = sys.getwindowsversion()
    report = {'schema_version': 1, 'diagnostic_only': True, 'product_qualified': False,
              'exports': 'trimmed text only; no raw logs, dumps, debugger binaries or fixture bodies',
              'windows': {'major': version.major, 'minor': version.minor, 'build': version.build,
                          'platform_id': version.platform, 'service_pack': version.service_pack},
              'platform': platform.platform(),
              'image': {'ImageOS': os.environ.get('ImageOS'), 'ImageVersion': os.environ.get('ImageVersion')},
              'source_commit': os.environ.get('GITHUB_SHA'), 'harness_sha256': compat.digest(Path(__file__)),
              'notes': ['cdb options and filter names are re-checked at runtime (debugger.introspection)',
                        'IFEO GlobalFlag (both registry views) only for debugged contained rows; firefox.exe added to LocalDumps',
                        'ready = kernel debug object on the suspended PID plus cdb log stable for 1.5 s',
                        'ResumeThread previous count is recorded; 2 would mean a debugger freeze was pending'],
              'runs': {}, 'cleanup_errors': [], 'harness_errors': [], 'budget_seconds': BUDGET_S}
    errors = report['cleanup_errors']
    sid = lab.container_sid()
    package = lab.sid_text(sid)
    report['package_sid'] = package
    grant_ok = grant_package(work, package, report)
    env = compat.safe_environment(work)
    cdb_env = {**env, '_NT_SYMBOL_PATH': compat.SYMBOLS}
    present = {name: path for name, path in compat.PROGRAMS.items() if path.exists()}
    for name in compat.PROGRAMS:
        if name not in present:
            report['notes'].append(f'{name} missing; not run')
    debugger = compat.cdb()
    paths = [str(path) for path in present.values()] + ([str(debugger)] if debugger else [])
    versions = file_versions(paths, env)
    report['browsers'] = {name: {'path': str(path), 'sha256': compat.digest(path),
                                 'version': versions.get(str(path))} for name, path in present.items()}
    report['debugger'] = {'found': debugger is not None, 'path': str(debugger) if debugger else None,
                          'sha256': compat.digest(debugger) if debugger else None,
                          'version': versions.get(str(debugger)) if debugger else None}
    if debugger is None:
        report['notes'].append('cdb.exe not found under Windows Kits\\10\\Debuggers\\x64; rows ran undebugged')
    else:
        report['debugger']['introspection'] = cdb_introspection(debugger, work, cdb_env)
        report['debugger']['symbol_warmup'] = warm_symbols(debugger, work, cdb_env)
    cases = plan(list(present))
    proxy = None
    try:
        if not grant_ok:
            raise RuntimeError('package ACL grant failed: ' + report['acl_grant']['tail'][-200:])
        proxy = Fixture([case.label for case in cases])
        api = _get_api()
        with local_dumps(work / 'dumps', IMAGES, errors):
            lab.exemption(sid, True)
            with lab.PackageFilters(sid, proxy.port) as filters:
                report['package_field_in_connect_layer'] = filters.field_supported()
                ctx = Context(api=api, work=work, sid=sid, env=env, cdb_env=cdb_env, proxy=proxy,
                              debugger=debugger, errors=errors)
                for index, case in enumerate(cases):
                    if time.monotonic() - started > BUDGET_S:
                        report['notes'].append('budget exhausted; not run: '
                                               + ', '.join(item.label for item in cases[index:]))
                        break
                    try:
                        entry = run_case(case, ctx)
                    except Exception as exc:  # harness fault: keep the other rows, then exit 1
                        entry = {'harness_error': f'{type(exc).__name__}: {exc}'[:400]}
                        report['harness_errors'].append(case.label + ': ' + entry['harness_error'])
                    report['runs'][case.label] = entry
                    print(f"{case.label}: exit={entry.get('exit_code')} signature={entry.get('signature')}",
                          flush=True)
    except Exception as exc:
        report['error'] = f'{type(exc).__name__}: {exc}'[:400]
    finally:
        if proxy is not None:
            proxy.close()
        kill_strays(errors)
        if sid is not None:
            try:
                lab.exemption(sid, False)
            except OSError as exc:
                errors.append(f'exemption cleanup: {exc}')
            try:
                code = lab.userenv.DeleteAppContainerProfile(lab.PROFILE)
                if code != 0:
                    errors.append(f'DeleteAppContainerProfile 0x{code & 0xFFFFFFFF:08x}')
            except OSError as exc:
                errors.append(f'DeleteAppContainerProfile: {exc}')
    report['summary'] = [{'label': label, 'exit_code': entry.get('exit_code'),
                          'exit_hex': (f"0x{entry['exit_code'] & 0xFFFFFFFF:08x}"
                                       if isinstance(entry.get('exit_code'), int) else None),
                          'seconds': entry.get('seconds'), 'debugger_attached': entry.get('debugger_attached'),
                          'signature': entry.get('signature'), 'error': entry.get('error') or entry.get('harness_error')}
                         for label, entry in report['runs'].items()]
    report['harness_ok'] = not report.get('error') and not errors and not report['harness_errors']
    report['seconds'] = round(time.monotonic() - started, 1)
    (work / 'crash-debug-report.json').write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding='utf-8')
    messages = ['crash-debug summary harness_ok=%s\n' % report['harness_ok'] + '\n'.join(
        f"{item['label']}: exit={item['exit_hex']} t={item['seconds']}s attached={item['debugger_attached']} "
        f"sig={item['signature']} err={item['error']}" for item in report['summary'])]
    for label, entry in report['runs'].items():
        blocks = (entry.get('cdb') or {}).get('blocks', {})
        for name in ('EXC_BPE', 'EXC_AV', 'PROCESS_EXIT'):
            for block in blocks.get(name, [])[:1]:
                messages.append(f'{label} {name}\n' + block[:2400])
    for label, entry in report['runs'].items():
        if entry.get('check_lines'):
            messages.append(f'{label} CHECK/FATAL lines\n' + '\n'.join(entry['check_lines'][-15:]))
    for label, entry in report['runs'].items():
        matches = (entry.get('cdb') or {}).get('loader_matches', [])
        if matches:
            messages.append(f'{label} loader failure lines\n' + '\n'.join(matches[-25:]))
            break
    if report.get('error') or report['harness_errors'] or errors:
        messages.append('harness: ' + '; '.join(
            [str(report.get('error') or '')] + report['harness_errors'] + errors)[:1500])
    for message in messages[:8]:
        print(notice(message), flush=True)
    return 0 if report['harness_ok'] else 1


class Fixture:
    """compat.Fixture's arrangement (nonce .invalid host, marker body, proxy receipt) with this lab's labels."""

    def __init__(self, labels):
        self.nonce = secrets.token_hex(16)
        self.host = 'rp-' + self.nonce + '.invalid'
        self.labels = frozenset(labels)
        self.received, self.lock = [], threading.Lock()
        owner = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_):
                pass

            def do_GET(self):
                prefix = 'http://' + owner.host + '/' + owner.nonce + '/'
                label = self.path[len(prefix):] if self.path.startswith(prefix) else ''
                if label not in owner.labels:
                    self.send_error(403)
                    return
                with owner.lock:
                    owner.received.append(label)
                body = ('<!doctype html><html><title>RuleProxy fixture</title><body>'
                        + owner.marker(label) + '</body></html>').encode('ascii')
                self.send_response(200)
                self.send_header('Content-Type', 'text/html; charset=utf-8')
                self.send_header('Content-Length', str(len(body)))
                self.send_header('Cache-Control', 'no-store')
                self.end_headers()
                self.wfile.write(body)

            def do_CONNECT(self):
                self.send_error(403)

        self.server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        self.server.daemon_threads = True
        self.port = self.server.server_port
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def marker(self, label):
        return 'RuleProxyFixture:' + self.nonce + ':' + label

    def url(self, label):
        return 'http://' + self.host + '/' + self.nonce + '/' + label

    def count(self, label):
        with self.lock:
            return self.received.count(label)

    def close(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(2)


if __name__ == '__main__':
    raise SystemExit(main())
