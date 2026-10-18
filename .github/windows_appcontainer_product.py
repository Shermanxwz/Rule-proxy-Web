"""Native check of the shipped AppContainer code on a disposable Windows runner.

Unlike windows_appcontainer_lab.py (raw API experiments), this drives the
product modules end to end: ``ContainerGate`` (persistent WFP + exemption, as
the SYSTEM service runs it), ``start_contained`` (profile, ACLs, environment)
and ``windows_app_process.launch(container_sid=...)``. Only for CI.
"""
from __future__ import annotations

import argparse
import json
import shutil
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / '.github'))

import windows_appcontainer_lab as lab  # noqa: E402  host-side fixtures
from ruleproxy import windows_appcontainer as product  # noqa: E402
from ruleproxy.windows_app_process import launch  # noqa: E402
from ruleproxy.windows_proxy_client import current_user_sid  # noqa: E402

PROBE = lab.PROBE.replace('print("RESULT " + json.dumps(out))',
                          'open(cfg["out"], "w", encoding="utf-8").write(json.dumps(out))')
assert PROBE != lab.PROBE
CONFINED = {key: False for key in ('direct_physical_tcp', 'direct_internet_tcp', 'loopback_other_v4',
                                   'loopback_other_v6', 'direct_physical_udp', 'grandchild_direct_tcp',
                                   'dns_resolve')}
GATES = {
    'product_confined': {**CONFINED, 'proxy_to_physical': True},
    'product_firewall_off': {**CONFINED, 'proxy_to_physical': True},
    'product_revoked': {**CONFINED, 'proxy_to_physical': False},
}


class DirectBackend:
    """Stands in for the pipe: calls the gate exactly as the service does."""

    def __init__(self, gate):
        self.gate = gate

    def container_allow(self, container, proxy_port):
        return self.gate.allow(container, proxy_port)

    def container_revoke(self, container):
        return self.gate.revoke(container)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument('--work', type=Path, required=True)
    work = parser.parse_args().work.resolve()
    if work.exists():
        shutil.rmtree(work)
    work.mkdir(parents=True)
    started = time.monotonic()
    report = {'schema_version': 1, 'windows': sys.getwindowsversion()[:4], 'phases': {}, 'notes': []}
    host = lab.physical_ipv4()
    target, local = lab._banner_server(host), lab._banner_server('127.0.0.1', banner=b'RPLOCAL\n')
    local6 = lab._banner_server('::1', lab.socket.AF_INET6, b'RPLOCAL6\n')
    udp, proxy = lab._udp_echo(), lab.ConnectProxy()
    gate = product.ContainerGate({'owner_sid': current_user_sid(), 'root': str(work)})
    backend = DirectBackend(gate)
    ident = 'product-check'
    name = product.container_name(ident)
    profile = work / 'profile'
    profile.mkdir()
    probe = profile / 'probe.py'
    probe.write_text(PROBE, encoding='utf-8')
    config = {'host': host, 'target': target.getsockname()[1], 'local': local.getsockname()[1],
              'local6': local6.getsockname()[1], 'udp': udp.getsockname()[1], 'proxy': proxy.port}
    report['config'] = config
    environment = {key: value for key, value in lab.os.environ.items()}
    # The hosted interpreter's stdlib lives beside python.exe; start_contained
    # grants the executable directory, which is sys.base_prefix here.
    report['notes'].append(f'python={sys.executable} base={sys.base_prefix}')

    def record(phase, process):
        out = profile / f'{phase}.json'
        code = process.wait(timeout=120)
        results = json.loads(out.read_text(encoding='utf-8')) if out.exists() else {
            'probe': {'ok': False, 'detail': f'no result, exit {code}'}}
        report['phases'][phase] = {'results': results, 'exit_code': code, 'firewall': lab.firewall()}
        summary = ' '.join(f"{k}={'Y' if v['ok'] else 'n'}" for k, v in sorted(results.items()))
        print(f'::notice title=AppContainer product {phase}::{summary}', flush=True)

    def command(phase):
        return [sys.executable, '-I', str(probe), json.dumps({**config, 'out': str(profile / f'{phase}.json')})]

    lease = None
    firewall_changed = False
    try:
        process, lease = product.start_contained(backend, ident, command('product_confined'), environment,
                                                 profile=profile, proxy_port=proxy.port, launch=launch)
        report['package_sid'] = sid = product.ensure_profile(name)
        record('product_confined', process)
        firewall_changed = True
        lab.firewall(False)
        # Second allow replaces the same persistent rules in place.
        process, second = product.start_contained(backend, ident, command('product_firewall_off'), environment,
                                                  profile=profile, proxy_port=proxy.port, launch=launch)
        record('product_firewall_off', process)
        second.close()
        lease.close()
        lease = None
        with gate._engine() as engine:
            report['rules_after_revoke'] = len(gate._present(engine, sid))
        report['exempt_after_revoke'] = sid in gate.api.exemptions()
        process = launch(command('product_revoked'), product.container_environment(environment, profile / 'AppContainer'),
                         str(Path(sys.executable).parent), container_sid=sid)
        record('product_revoked', process)
    except Exception as exc:
        report['error'] = f'{type(exc).__name__}: {exc}'[:400]
        print(f"::error title=AppContainer product error::{report['error']}", flush=True)
    finally:
        if firewall_changed:
            report['firewall_restored'] = lab.firewall(True)
        if lease is not None:
            try:
                lease.close()
            except Exception as exc:
                report['notes'].append(f'revoke: {exc}')
        try:
            product.delete_profile(name)
            report['profile_deleted'] = True
        except Exception as exc:
            report['notes'].append(f'delete profile: {exc}')
        report['seconds'] = round(time.monotonic() - started, 1)
    failures = []
    for phase, expected in GATES.items():
        results = report['phases'].get(phase, {}).get('results', {})
        for key, want in expected.items():
            got = results.get(key, {}).get('ok')
            if got is not want:
                failures.append(f'{phase}.{key}: expected {want}, got {got}')
    if report.get('rules_after_revoke') != 0 or report.get('exempt_after_revoke') is not False:
        failures.append(f"revoke left rules={report.get('rules_after_revoke')} "
                        f"exempt={report.get('exempt_after_revoke')}")
    report['gate_failures'] = failures
    report['passed'] = not failures and 'error' not in report
    (work / 'product-report.json').write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding='utf-8')
    print(f"::notice title=AppContainer product verdict::passed={report['passed']} failures={len(failures)} "
          f"seconds={report['seconds']}", flush=True)
    for failure in failures[:20]:
        print(f'::error title=AppContainer product gate::{failure}', flush=True)
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
