"""Show what MXC 1.0.0 does when plm.exe sits under a top folder that starts with a Chinese character.

Usage: python mxc_path_check.py PACKAGE_DIR

Run with the package's Python after an older package's plm.exe has been put back into
bin/windows-amd64. MXC panics while vetting plm.exe on such a path (it slices the path at
byte 4); the panel removes plm.exe before its own check. This calls the probe directly,
without that cleanup, and requires that a crash is reported with the panel's explanation.
"""
from pathlib import Path
import sys
import tempfile

from ruleproxy import windows_runtime


def main(package: Path) -> int:
    runtime = package / "bin" / "windows-amd64" / "wxc-exec.exe"
    with tempfile.TemporaryDirectory() as temp:
        policy = windows_runtime.build_policy([r"C:\Windows\System32\whoami.exe"], {}, Path(temp) / "probe", 49152)
        try:
            output = windows_runtime._probe_request(str(runtime), policy)
        except windows_runtime.UnsupportedRuntimeError as exc:
            message = str(exc)
        else:
            message = f"no crash; tier {output.get('tier')!r}"
    crashed = "is not a char boundary" in message
    if crashed and "顶层文件夹名" not in message:
        print(f"::error title=MXC path check::MXC crashed without the panel's explanation: {message}", flush=True)
        return 1
    outcome = "MXC 1.0.0 crashed on this path while plm.exe was present, and the panel explained it" if crashed \
        else "MXC did not crash here (it only vets plm.exe when wpr.exe is present)"
    print(f"::notice title=MXC path check::{outcome}. {message[:300]}", flush=True)
    return 0


if __name__ == "__main__":
    for stream in (sys.stdout, sys.stderr):
        stream.reconfigure(encoding="utf-8", errors="replace")
    sys.exit(main(Path(sys.argv[1])))
