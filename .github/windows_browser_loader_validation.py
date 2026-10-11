"""Local-only browser loader controls; experimental grants never reach production.

Compare the same verified browser outside and inside PSEC, then change only
its installation's read/write permission or documented user capabilities.
Network policy and the browser's own sandbox remain enabled in every PSEC case.
"""
from __future__ import annotations

import argparse
import http.server
import json
import os
from pathlib import Path
import secrets
import shutil
import subprocess
import sys
import tempfile
import threading
import traceback

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))
from ruleproxy import windows_runtime as runtime
from ruleproxy.launcher import prepare_app
from windows_native_validation import free_port, host_info, start_core


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--chrome", type=Path, required=True)
    parser.add_argument("--firefox", type=Path, required=True)
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    report = {"host": host_info(), "mocked": False, "diagnosis_only": True, "cases": []}
    nonce = secrets.token_hex(16)
    requests = []

    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_GET(self):
            requests.append(self.path)
            body = ("<!doctype html><html><body>" + nonce + "</body></html>").encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        executable = ROOT / "bin/windows-amd64/wxc-exec.exe"
        browsers = {"chrome": args.chrome.resolve(strict=True), "firefox": args.firefox.resolve(strict=True)}
        for key in ("ProgramFiles(x86)", "ProgramFiles"):
            edge = Path(os.environ.get(key, "C:/Program Files")) / "Microsoft/Edge/Application/msedge.exe"
            if edge.is_file():
                browsers["edge"] = edge
                break
        with tempfile.TemporaryDirectory(prefix="browser-loader-", ignore_cleanup_errors=True) as temporary:
            folder = Path(temporary)
            proxy = free_port()
            core, core_log = start_core(folder, proxy)
            try:
                cases = [(browser, mode) for browser in ("chrome", "firefox")
                         for mode in ("host", "readonly", "writable-copy", "capabilities")]
                cases += [("edge", "capabilities")]
                for browser_name, mode in cases:
                    name = f"{browser_name}-{mode}"
                    entry = {"name": name, "mode": mode}
                    report["cases"].append(entry)
                    profile = folder / name
                    profile.mkdir()
                    browser = browsers[browser_name]
                    if mode == "writable-copy":
                        shutil.copytree(browser.parent, profile / "installation")
                        browser = profile / "installation" / browser.name
                    url = f"http://127.0.0.1:{server.server_port}/{name}"
                    firefox = browser_name == "firefox"
                    screenshot = profile / "page.png"
                    browser_args = (["--headless", "--screenshot", str(screenshot), "--window-size", "1280,800", url]
                                    if firefox else ["--headless=new", "--disable-gpu", "--dump-dom", url])
                    command, env, _ = prepare_app(
                        {"id": name, "label": name, "path": str(browser),
                         "adapter": "firefox" if firefox else "chromium", "args": browser_args},
                        proxy, folder,
                    )
                    path = output / f"{name}.log"
                    process = None
                    with path.open("wb") as stream:
                        try:
                            if mode == "host":
                                # Synthetic profile, localhost fixture and the same
                                # explicit proxy. No user application is launched.
                                process = subprocess.Popen(command, cwd=profile,
                                                           env=runtime._profile_environment(env, profile),
                                                           stdout=stream, stderr=subprocess.STDOUT)
                            else:
                                policy = runtime.build_policy(command, env, profile, proxy)
                                policy["process"]["commandLine"] = subprocess.list2cmdline(command)
                                if mode == "capabilities":
                                    policy["processContainer"]["capabilities"] = ["registryRead", "userAccountInformation"]
                                config = profile / "policy.json"
                                config.write_text(json.dumps(policy), encoding="ascii")
                                entry["tier"] = runtime._probe_request(executable, policy)["tier"]
                                process = subprocess.Popen([str(executable), "--config", str(config)],
                                                           stdout=stream, stderr=subprocess.STDOUT)
                            try:
                                entry["exit"] = process.wait(35)
                            except subprocess.TimeoutExpired:
                                entry["timeout"] = True
                        except Exception:
                            entry["error"] = traceback.format_exc()
                        finally:
                            if process is not None and process.poll() is None:
                                if mode == "host":
                                    process.terminate()
                                    process.wait(10)
                                else:
                                    runtime.stop(process)
                    text = path.read_text(encoding="utf-8", errors="replace")
                    entry["requested"] = "/" + name in requests
                    entry["rendered"] = (screenshot.is_file() and screenshot.stat().st_size > 1000
                                         if firefox else nonce in text)
                    entry["log_tail"] = text[-4000:]
                    if screenshot.is_file():
                        shutil.copyfile(screenshot, output / f"{name}.png")
                    print(json.dumps(entry, ensure_ascii=True), flush=True)
            finally:
                core.terminate()
                core.wait(10)
                core_log.close()
    except Exception:
        report["error"] = traceback.format_exc()
    finally:
        server.shutdown()
        server.server_close()
        thread.join(2)
        report["requests"] = requests
        (output / "loader-report.json").write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    return 1 if "error" in report else 0


if __name__ == "__main__":
    raise SystemExit(main())
