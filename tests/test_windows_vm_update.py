"""Validate the VM-only update worker without installing or restarting Windows."""
from __future__ import annotations
import hashlib
import http.server
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import threading
import unittest

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / '.github/windows-vm-update.ps1'
RUN_SCRIPT = ROOT / '.github/windows-vm-run.ps1'
SETUP_SCRIPT = ROOT / '.github/windows-vm-setup.ps1'
POWERSHELL = shutil.which('powershell.exe') or shutil.which('pwsh')


class WindowsVMUpdateSourceTests(unittest.TestCase):
    def test_source_is_vm_only_and_does_not_change_host_network_or_bypass_servicing(self):
        source = SCRIPT.read_text(encoding='utf-8')
        self.assertIn("C:\\RuleProxyCIUpdates", source)
        self.assertIn("RuleProxyCI-InstallOfficialUpdate", source)
        self.assertNotIn('/IgnoreCheck', source)
        self.assertNotIn('/Unsigned', source)
        self.assertNotIn('Restart-Computer -Force', source)
        for command in ('Set-Net', 'New-NetFirewallRule', 'Set-DnsClient', 'Stop-Process', 'taskkill'):
            self.assertNotIn(command, source)


@unittest.skipUnless(POWERSHELL, 'PowerShell is required for the real manifest validator')
class WindowsVMUpdateManifestTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        (self.directory / 'packages').mkdir()
        data = b'public deterministic test MSU bytes; never installed'
        filename = 'windows11.0-kb5127648-x64_fixture.msu'
        (self.directory / 'packages' / filename).write_bytes(data)
        self.manifest = {'target_build': 26300, 'target_ubr': 9711,
                         'target_package': filename,
                         'packages': [{'filename': filename, 'sha256': hashlib.sha256(data).hexdigest()}]}

    def validate(self, expected, *, hide_hash_cmdlet=False):
        (self.directory / 'update-manifest.json').write_text(json.dumps(self.manifest), encoding='utf-8')
        quote = lambda value: "'" + str(value).replace("'", "''") + "'"
        runner = self.directory / 'validate.ps1'
        # Dot sourcing only defines helpers: the SYSTEM entry point is guarded.
        prelude = "function Get-FileHash { throw 'hash_cmdlet_unavailable' }\n" if hide_hash_cmdlet else ''
        runner.write_text("$ErrorActionPreference='Stop'\n. " + quote(SCRIPT) + '\n' + prelude +
                          "\ntry { $null = Read-UpdateManifest " + quote(self.directory) +
                          "; Write-Output 'valid' } catch { Write-Output $_.Exception.Message }\n", encoding='utf-8-sig')
        result = subprocess.run([POWERSHELL, '-NoProfile', '-NonInteractive', '-File', str(runner)],
                                capture_output=True, text=True, timeout=30, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), expected)

    def test_real_validator_accepts_exact_target_and_all_verified_packages(self):
        self.validate('valid', hide_hash_cmdlet=True)

    def test_real_validator_rejects_tampered_package(self):
        self.manifest['packages'][0]['sha256'] = '0' * 64
        self.validate('update_package_hash_mismatch')

    def test_real_validator_rejects_path_escape_before_opening_another_file(self):
        self.manifest['packages'][0]['filename'] = '..\\escape.msu'
        self.validate('update_invalid_package_entry')

    def test_real_validator_rejects_unverified_target_package(self):
        self.manifest['target_package'] = 'unlisted.msu'
        self.validate('update_target_not_verified')

    def test_real_validator_rejects_duplicate_case_insensitive_paths(self):
        duplicate = dict(self.manifest['packages'][0])
        duplicate['filename'] = duplicate['filename'].upper().replace('.MSU', '.msu')
        self.manifest['packages'].append(duplicate)
        self.validate('update_duplicate_filename')

    def test_real_validator_rejects_different_OS_target(self):
        self.manifest['target_build'] = 26200
        self.validate('update_manifest_unexpected_target')

    def test_real_validator_rejects_unlisted_MSU_before_servicing_can_discover_it(self):
        (self.directory / 'packages' / 'unlisted.msu').write_bytes(b'unverified checkpoint')
        self.validate('update_unlisted_package')

    def test_real_validator_rejects_an_extra_subdirectory_in_package_search_path(self):
        (self.directory / 'packages' / 'nested').mkdir()
        self.validate('update_unlisted_package')


@unittest.skipUnless(POWERSHELL, 'PowerShell is required for the real streaming downloader')
class WindowsVMUpdateDownloadTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        (self.directory / 'packages').mkdir()
        self.data = (b'public deterministic MSU transport fixture\x00' * 5000) + b'END'
        self.entry = {'filename': 'target.msu', 'sha256': hashlib.sha256(self.data).hexdigest(),
                      'bytes': len(self.data), 'url': 'http://10.0.2.2:45678/' + 'a' * 64 + '/updates/target.msu'}
        owner = self
        self.requests = []
        self.status, self.header_length, self.body = 200, len(self.data), self.data

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                owner.requests.append(self.path)
                self.send_response(owner.status)
                self.send_header('Content-Length', str(owner.header_length))
                self.send_header('Connection', 'close')
                if owner.status == 302:
                    self.send_header('Location', '/must-not-follow')
                self.end_headers()
                try:
                    self.wfile.write(owner.body)
                    self.wfile.flush()
                except (BrokenPipeError, ConnectionResetError):
                    pass

            def log_message(self, *_args):
                pass

        self.server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        self.worker = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.worker.start()
        self.addCleanup(self.close_server)

    def close_server(self):
        self.server.shutdown()
        self.server.server_close()
        self.worker.join(2)
        self.assertFalse(self.worker.is_alive())

    def stage(self):
        quote = lambda value: "'" + str(value).replace("'", "''") + "'"
        entry = self.directory / 'entry.json'
        entry.write_text(json.dumps(self.entry), encoding='utf-8')
        script = self.directory / 'download.ps1'
        # The production endpoint validator runs unchanged. Only the factory
        # maps its private VM address to this controlled loopback fixture;
        # ACL validation uses real no-reparse checks in this ordinary test.
        fixture = f'http://127.0.0.1:{self.server.server_port}/fixed.msu'
        script.write_text(
            "$ErrorActionPreference='Stop'\n. " + quote(SCRIPT) + '\n' +
            "function New-UpdateHttpRequest($Url) { return [Net.HttpWebRequest]::Create(" + quote(fixture) + ") }\n" +
            "function Assert-ProtectedUpdatePath($Path,[switch]$Directory,[switch]$ProtectedDacl) { "
            "$null = Assert-UpdateFile $Path -Directory:$Directory }\n" +
            "$entry = [IO.File]::ReadAllText(" + quote(entry) + ") | ConvertFrom-Json\n" +
            "try { $saved = Save-UpdatePackage $entry " + quote(self.directory) +
            " ([Diagnostics.Stopwatch]::StartNew()); Write-Output ('saved=' + $saved) } "
            "catch { Write-Output $_.Exception.Message }\n", encoding='utf-8-sig')
        result = subprocess.run([POWERSHELL, '-NoProfile', '-NonInteractive', '-File', str(script)],
                                capture_output=True, text=True, timeout=30, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn(self.entry['url'], result.stdout + result.stderr)
        self.assertEqual(list(self.directory.glob('*.part')), [])
        return result.stdout.strip()

    def test_real_http_stream_spans_many_chunks_and_moves_only_verified_bytes(self):
        self.assertGreater(len(self.data), 65536 * 3)
        self.assertEqual(self.stage(), 'saved=True')
        self.assertEqual((self.directory / 'packages/target.msu').read_bytes(), self.data)
        self.assertEqual(self.requests, ['/fixed.msu'])

    def test_verified_cache_skips_http_and_preserves_the_original_file(self):
        path = self.directory / 'packages/target.msu'
        path.write_bytes(self.data)
        self.assertEqual(self.stage(), 'saved=False')
        self.assertEqual(self.requests, [])

        self.assertEqual(path.read_bytes(), self.data)

    def test_existing_unverified_file_is_preserved_and_never_serviced(self):
        path = self.directory / 'packages/target.msu'
        path.write_bytes(b'old invalid bytes')
        self.assertEqual(self.stage(), 'update_existing_package_mismatch')
        self.assertEqual(self.requests, [])
        self.assertEqual(path.read_bytes(), b'old invalid bytes')

    def test_header_size_mismatch_is_rejected_before_creating_a_package(self):
        self.header_length += 1
        self.assertEqual(self.stage(), 'update_download_length_or_status_mismatch')
        self.assertFalse((self.directory / 'packages/target.msu').exists())

    def test_corrupt_download_is_removed_and_never_promoted(self):
        self.body = b'x' * len(self.data)
        self.assertEqual(self.stage(), 'update_download_hash_mismatch')
        self.assertFalse((self.directory / 'packages/target.msu').exists())

    def test_early_eof_fails_without_leaving_part_or_target_file(self):
        self.body = self.body[:123]
        self.assertIn(self.stage(), ('update_download_read_failed', 'update_download_ended_early'))
        self.assertFalse((self.directory / 'packages/target.msu').exists())

    def test_redirect_is_not_followed(self):
        self.status, self.header_length, self.body = 302, 0, b''
        self.assertEqual(self.stage(), 'update_download_length_or_status_mismatch')
        self.assertEqual(self.requests, ['/fixed.msu'])

    def test_unapproved_endpoint_and_oversized_entry_are_rejected_before_http(self):
        self.entry['url'] = 'http://example.invalid/updates/target.msu'
        self.assertEqual(self.stage(), 'update_download_endpoint_rejected')
        self.entry['url'] = 'http://10.0.2.2:45678/' + 'a' * 64 + '/updates/target.msu'
        self.entry['bytes'] = 5 * 1024 * 1024 * 1024 + 1
        self.assertEqual(self.stage(), 'update_invalid_download_entry')
        self.assertEqual(self.requests, [])



@unittest.skipUnless(POWERSHELL, 'PowerShell is required for the real diagnostic helpers')
class WindowsVMUpdateDiagnosticTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)

    def run_helpers(self, body, *, worker=False):
        quote = lambda value: "'" + str(value).replace("'", "''") + "'"
        # Load only function ASTs from the ordinary runner, never its startup,
        # servicing or shutdown entry points. The worker supports dot sourcing.
        if worker:
            prelude = '. ' + quote(SCRIPT) + '\n$script:UpdateDirectory=' + quote(self.directory) + '\n'
        else:
            prelude = ('$tokens=$null; $errors=$null\n'
                       '$ast=[Management.Automation.Language.Parser]::ParseFile(' + quote(RUN_SCRIPT) +
                       ',[ref]$tokens,[ref]$errors)\n'
                       'if($errors.Count){throw "parse_failed"}\n'
                       '$ast.FindAll({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst]},$false) | '
                       'ForEach-Object {Invoke-Expression $_.Extent.Text}\n')
        runner = self.directory / 'diagnostics.ps1'
        runner.write_text("$ErrorActionPreference='Stop'\n" + prelude + body, encoding='utf-8-sig')
        completed = subprocess.run([POWERSHELL, '-NoProfile', '-NonInteractive', '-File', str(runner)],
                                   capture_output=True, text=True, timeout=30, check=False)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        return completed.stdout.strip()

    def test_last_state_whitelist_keeps_real_failure_progress_without_urls_or_capabilities(self):
        cap = 'a' * 64
        state = {'schema_version': 1, 'status': 'installing', 'phase': 'staging_official_MSU',
                 'actual_build': '26300', 'completed': 'true', 'staged_package_count': 1,
                 'error_detail': f'failed http://10.0.2.2:45678/{cap}/updates/target.msu {cap}',
                 'manifest': {'url': 'http://private.invalid/secret'}, 'raw_url': 'http://private.invalid/secret'}
        (self.directory / 'state.json').write_text(json.dumps(state), encoding='utf-8')
        value = json.loads(self.run_helpers(
            "$state=Get-Content -LiteralPath (Join-Path $PSScriptRoot 'state.json') -Raw | ConvertFrom-Json\n"
            'ConvertTo-UpdateDiagnosticState $state | ConvertTo-Json -Compress\n'))
        self.assertEqual(value['status'], 'installing')
        self.assertEqual(value['staged_package_count'], 1)
        self.assertNotIn('actual_build', value)
        self.assertNotIn('completed', value)
        self.assertNotIn('manifest', value)
        self.assertNotIn('raw_url', value)
        self.assertNotIn(cap, json.dumps(value))
        self.assertNotIn('http://', json.dumps(value))

    def test_actual_log_tail_is_bounded_and_redacts_public_transport_url_and_capability(self):
        cap = 'b' * 64
        (self.directory / 'dism.log').write_bytes(b'OLD' * 80000 +
            f'\nlatest http://10.0.2.2:1234/{cap}/updates/target.msu token={cap}\nEND'.encode())
        value = json.loads(self.run_helpers(
            "$path=Join-Path $PSScriptRoot 'dism.log'\n$fact=Get-UpdateFileFact $path\n"
            "$text=Read-UpdateDiagnosticLog $path $fact\n@{fact=$fact;text=$text} | ConvertTo-Json -Compress\n"))
        self.assertEqual(value['fact']['bytes_read'], 131072)
        self.assertEqual(value['fact']['read_status'], 'read')
        self.assertTrue(value['text'].endswith('END'))
        self.assertNotIn(cap, value['text'])
        self.assertNotIn('http://', value['text'])
        self.assertLessEqual(len(value['text']), 131072)

    def test_actual_utf16_dism_log_remains_readable(self):
        (self.directory / 'dism.log').write_text('DISM servicing started\r\nError 5\r\n', encoding='utf-16')
        value = json.loads(self.run_helpers(
            "$path=Join-Path $PSScriptRoot 'dism.log'\n$fact=Get-UpdateFileFact $path\n"
            "$text=Read-UpdateDiagnosticLog $path $fact\n@{fact=$fact;text=$text} | ConvertTo-Json -Compress\n"))
        self.assertIn('DISM servicing started', value['text'])
        self.assertNotIn('\x00', value['text'])
        self.assertEqual(value['fact']['read_status'], 'read')

    def test_actual_missing_file_is_explicit_and_not_an_empty_successful_log(self):
        value = json.loads(self.run_helpers(
            "Get-UpdateFileFact (Join-Path $PSScriptRoot 'missing.log') | ConvertTo-Json -Compress\n"))
        self.assertEqual(value['status'], 'missing')
        self.assertIs(value['exists'], False)
        self.assertIsInstance(value['error_code'], int)

    def diagnostic_task(self, body):
        return json.loads(self.run_helpers(
            "function Join-Path($Path,$ChildPath) { return ($Path + '/' + $ChildPath) }\n"
            "function Get-UpdateFileFact($Path,[switch]$Directory) { return @{status='missing';exists=$false} }\n"
            "function Get-ItemProperty { return [pscustomobject]@{CurrentBuildNumber='26300';UBR=9457} }\n" + body +
            "$result=@{logs=@{}}\nGet-RuleProxyCIUpdateDiagnostics $result\n$result | ConvertTo-Json -Depth 8 -Compress\n"))

    def test_task_access_denied_and_no_logs_still_produce_read_only_facts(self):
        value = self.diagnostic_task(
            "function Get-ScheduledTask { throw [UnauthorizedAccessException]::new('http://private.invalid/secret') }\n")
        facts = value['windows_update_diagnostics']
        self.assertEqual(facts['task']['status'], 'unavailable')
        self.assertEqual(facts['task']['error_type'], 'UnauthorizedAccessException')
        self.assertIsInstance(facts['task']['error_code'], int)
        self.assertEqual(facts['os'], {'build': 26300, 'ubr': 9457})
        self.assertEqual(facts['files']['dism']['status'], 'missing')
        self.assertNotIn('http://', json.dumps(value))

    def test_task_result_is_recorded_and_null_is_never_cast_to_successful_zero(self):
        base = "function Get-ScheduledTask { return [pscustomobject]@{State='Ready'} }\n"
        value = self.diagnostic_task(base +
            "function Get-ScheduledTaskInfo { return [pscustomobject]@{LastRunTime=[DateTime]'2026-10-15T00:00:00Z';LastTaskResult=[uint32]2147942402} }\n")
        task = value['windows_update_diagnostics']['task']
        self.assertEqual(task['status'], 'observed')
        self.assertEqual(task['last_task_result'], 2147942402)
        value = self.diagnostic_task(base +
            "function Get-ScheduledTaskInfo { return [pscustomobject]@{LastRunTime=[DateTime]'2026-10-15T00:00:00Z';LastTaskResult=$null} }\n")
        self.assertEqual(value['windows_update_diagnostics']['task']['status'], 'unavailable')
        self.assertNotIn('last_task_result', value['windows_update_diagnostics']['task'])

    def test_worker_log_checks_protection_before_any_write_and_accepts_only_fixed_event_ids(self):
        output = self.run_helpers(
            "function Assert-ProtectedUpdatePath { throw 'blocked_acl' }\n"
            "try { Write-UpdateWorkerEvent 'worker_started' } catch { Write-Output $_.Exception.Message }\n", worker=True)
        self.assertEqual(output, 'blocked_acl')
        self.assertFalse((self.directory / 'update-worker.log').exists())
        output = self.run_helpers(
            "function Assert-ProtectedUpdatePath($Path,[switch]$Directory,[switch]$ProtectedDacl) { $null=Assert-UpdateFile $Path -Directory:$Directory }\n"
            "Write-UpdateWorkerEvent 'worker_started'\nWrite-UpdateWorkerEvent 'dism_starting'\n"
            "try { Write-UpdateWorkerEvent 'http://private.invalid/secret' } catch { Write-Output $_.Exception.Message }\n", worker=True)
        self.assertEqual(output, 'update_invalid_log_event')
        lines = (self.directory / 'update-worker.log').read_text().splitlines()
        self.assertEqual(len(lines), 2)
        self.assertTrue(lines[0].endswith('event=worker_started'))
        self.assertTrue(lines[1].endswith('event=dism_starting'))

    def test_logging_failure_cannot_publish_a_completed_state(self):
        state = self.directory / 'update-state.json'
        state.write_text('{"status":"installing","completed":false}')
        output = self.run_helpers(
            "function Assert-ProtectedUpdatePath {}\nfunction Write-UpdateWorkerEvent { throw 'log_failed' }\n"
            "try { Write-UpdateState @{status='completed';completed=$true} } catch { Write-Output $_.Exception.Message }\n", worker=True)
        self.assertEqual(output, 'log_failed')
        self.assertEqual(json.loads(state.read_text()), {'status': 'installing', 'completed': False})
        self.assertFalse((self.directory / 'update-state.json.tmp').exists())

    def test_all_three_real_powershell_scripts_parse_without_running_vm_entrypoints(self):
        quote = lambda value: "'" + str(value).replace("'", "''") + "'"
        paths = ','.join(quote(path) for path in (SCRIPT, RUN_SCRIPT, SETUP_SCRIPT))
        output = self.run_helpers(
            'foreach($path in @(' + paths + ')) {$tokens=$null;$errors=$null;'
            '$null=[Management.Automation.Language.Parser]::ParseFile($path,[ref]$tokens,[ref]$errors);'
            'if($errors.Count){throw "script_parse_failed"}}\nWrite-Output "parsed"\n')
        self.assertEqual(output, 'parsed')
