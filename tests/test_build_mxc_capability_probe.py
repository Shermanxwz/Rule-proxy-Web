"""Check diagnostic source/build provenance; never claim native network success."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("build_mxc_capability_probe", ROOT / ".github/build_mxc_capability_probe.py")
builder = importlib.util.module_from_spec(spec)
spec.loader.exec_module(builder)


def fixture_source():
    return ("// Fixed test source; production verification uses the immutable upstream SHA.\n"
            "pub(super) fn build_psec_v1_security_environment_spec(\n"
            "    request: &ExecutionRequest,\n"
            ") -> Vec<u8> {\n" + builder.ANCHOR + "    original_network_and_filesystem_tables();\n}\n").encode()


def pe_bytes(machine=0x8664):
    raw = bytearray(512)
    raw[:2] = b"MZ"
    struct.pack_into("<I", raw, 0x3c, 128)
    raw[128:132] = b"PE\0\0"
    struct.pack_into("<H", raw, 132, machine)
    return bytes(raw)


class CapabilityProbeBuilderTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name).resolve()
        self.source = self.base / "source"
        self.target = self.source / builder.TARGET_FILE
        self.target.parent.mkdir(parents=True)
        self.original = fixture_source()
        self.target.write_bytes(self.original)
        self.license = b'MIT License\nCopyright (c) Microsoft Corporation.\nPublic fixture license bytes.\n'
        (self.source / 'LICENSE.md').write_bytes(self.license)
        (self.source / "src/rust-toolchain.toml").write_text('[toolchain]\nchannel = "1.93"\n')
        self.output = self.base / "diagnostic"
        self.calls = []

    def source_commands(self, arguments, **kwargs):
        self.calls.append((arguments, kwargs))
        if arguments[:3] == ["git", "rev-parse", "HEAD"]:
            return (builder.UPSTREAM_COMMIT + "\n").encode()
        if arguments[:2] == ["git", "status"]:
            return b""
        if arguments[:2] == ["git", "show"]:
            return self.license if arguments[2] == 'HEAD:LICENSE.md' else self.original
        if arguments[:3] == ["git", "diff", "--name-only"]:
            return (builder.TARGET_FILE + "\n").encode()
        if arguments[:2] == ["rustc", "+1.93"]:
            return b"rustc 1.93.0 (fixed-test 2026-01-01)\n"
        if arguments[:3] == ["cargo", "+1.93", "build"]:
            artifact = self.source / "src/target" / builder.BUILD_TARGET / "release/wxc-exec.exe"
            artifact.parent.mkdir(parents=True, exist_ok=True)
            artifact.write_bytes(pe_bytes())
            return b""
        raise AssertionError("unexpected diagnostic command")

    def prepare(self):
        with mock.patch.object(builder, "ORIGINAL_SHA256", hashlib.sha256(self.original).hexdigest()), \
                mock.patch.object(builder, "run", side_effect=self.source_commands):
            return builder.prepare_source(self.source)

    def test_one_exact_insertion_preserves_every_original_byte_and_has_stable_diff_provenance(self):
        with mock.patch.object(builder, "ORIGINAL_SHA256", hashlib.sha256(self.original).hexdigest()):
            changed, digest = builder.patch_bytes(self.original)
            self.assertEqual(changed.replace(builder.INSERTION.encode(), b"", 1), self.original)
            self.assertEqual(changed.count(builder.INSERTION.encode()), 1)
            self.assertEqual(builder.patch_bytes(self.original), (changed, digest))
            self.assertEqual(len(digest), 64)
            with self.assertRaisesRegex(ValueError, "fixed release SHA256"):
                builder.patch_bytes(changed)

    def test_wrong_release_file_or_non_unique_anchor_is_never_patched(self):
        with self.assertRaisesRegex(ValueError, "fixed release SHA256"):
            builder.patch_bytes(self.original)
        duplicated = self.original + builder.ANCHOR.encode()
        with mock.patch.object(builder, "ORIGINAL_SHA256", hashlib.sha256(duplicated).hexdigest()), \
                self.assertRaisesRegex(ValueError, "not unique"):
            builder.patch_bytes(duplicated)

    def test_prepare_manifest_has_no_executor_and_cannot_claim_runtime_or_privacy_success(self):
        source, manifest = self.prepare()
        self.assertEqual(source, self.source)
        self.assertEqual(manifest["status"], "prepared_only")
        self.assertIsNone(manifest["executor_sha256"])
        self.assertEqual(manifest["upstream_commit"], builder.UPSTREAM_COMMIT)
        self.assertEqual(manifest["patch"], builder.PATCH_INFO)
        self.assertEqual(manifest["patched_file_sha256"], builder.sha256(self.target.read_bytes()))
        self.assertNotIn("acceptance_passed", manifest)
        self.assertFalse(any(command[0] in ("cargo", "rustc") for command, _ in self.calls))

    def test_wrong_git_commit_dirty_source_and_blob_mismatch_fail_before_writing(self):
        for mode in ("commit", "dirty", "blob"):
            with self.subTest(mode=mode):
                def commands(arguments, **kwargs):
                    if mode == "commit" and arguments[1] == "rev-parse":
                        return b"0" * 40
                    if mode == "dirty" and arguments[1] == "status":
                        return b" M src/other.rs\n"
                    if mode == "blob" and arguments[1] == "show":
                        return b"drifted source"
                    return self.source_commands(arguments, **kwargs)
                with mock.patch.object(builder, "ORIGINAL_SHA256", hashlib.sha256(self.original).hexdigest()), \
                        mock.patch.object(builder, "run", side_effect=commands), self.assertRaises(ValueError):
                    builder.prepare_source(self.source)
                self.assertEqual(self.target.read_bytes(), self.original)

    def test_changed_toolchain_and_alias_source_target_fail_before_patch(self):
        (self.source / "src/rust-toolchain.toml").write_text('channel = "stable"\n')
        with mock.patch.object(builder, "run", side_effect=self.source_commands), self.assertRaisesRegex(ValueError, "Rust 1.93"):
            builder.prepare_source(self.source)
        self.assertEqual(self.target.read_bytes(), self.original)
        (self.source / "src/rust-toolchain.toml").write_text('channel = "1.93"\n')
        original = self.base / "original.rs"
        original.write_bytes(self.original)
        self.target.unlink()
        try:
            self.target.symlink_to(original)
        except OSError:
            self.skipTest("platform does not permit this owned test symlink")
        with mock.patch.object(builder, "run", side_effect=self.source_commands), self.assertRaisesRegex(ValueError, "alias"):
            builder.prepare_source(self.source)
        self.assertEqual(original.read_bytes(), self.original)

    def test_windows_build_is_locked_x64_minimal_and_checks_both_staged_digests(self):
        source, manifest = self.prepare()
        self.output.mkdir()
        with mock.patch.object(builder, "os", SimpleNamespace(name="nt")), \
                mock.patch.object(builder, "run", side_effect=self.source_commands), \
                mock.patch.object(builder, "LICENSE_SHA256", builder.sha256(self.license)):
            builder.build(source, self.output, manifest)
        self.assertEqual(manifest["status"], "built")
        self.assertEqual(manifest["executor_sha256"], builder.sha256(pe_bytes()))
        self.assertEqual((self.output / "wxc-exec.exe").read_bytes(), pe_bytes())
        self.assertEqual((self.output / "MXC-LICENSE.md").read_bytes(), self.license)
        cargo = next(command for command, _ in self.calls if command[0] == "cargo")
        self.assertEqual(cargo[:3], ["cargo", "+1.93", "build"])
        self.assertIn("--locked", cargo)
        self.assertIn("--no-default-features", cargo)
        self.assertIn("--message-format=json", cargo)
        self.assertEqual(cargo[cargo.index("--target") + 1], "x86_64-pc-windows-msvc")
        self.assertEqual(cargo[cargo.index("-p") + 1], "wxc")
        self.assertNotIn("--features", cargo)

    def test_wrong_compiler_or_source_drift_never_stages_a_built_artifact(self):
        for failure in ("compiler", "source"):
            with self.subTest(failure=failure):
                self.target.write_bytes(self.original)
                source, manifest = self.prepare()
                output = self.base / ("output-" + failure)
                output.mkdir()
                def commands(arguments, **kwargs):
                    if failure == "compiler" and arguments[0] == "rustc":
                        return b"rustc 1.94.0 (other 2026-02-01)\n"
                    if failure == "source" and arguments[:3] == ["git", "diff", "--name-only"]:
                        return (builder.TARGET_FILE + "\nsrc/other.rs\n").encode()
                    return self.source_commands(arguments, **kwargs)
                with mock.patch.object(builder, "os", SimpleNamespace(name="nt")), \
                        mock.patch.object(builder, "run", side_effect=commands), self.assertRaises(ValueError):
                    builder.build(source, output, manifest)
                self.assertEqual(manifest["status"], "prepared_only")
                self.assertFalse((output / "wxc-exec.exe").exists())

    def test_unsupported_or_malformed_pe_cannot_get_native_x64_metadata(self):
        path = self.base / "executor.exe"
        for raw in (pe_bytes(0xAA64), b"junk" * 128, b"MZ" + b"\0" * 510):
            path.write_bytes(raw)
            with self.assertRaises(ValueError):
                builder.executable_digest(path)

    def test_product_bin_and_stale_diagnostic_output_are_not_overwritten(self):
        with self.assertRaisesRegex(ValueError, "product runtime"):
            builder.permitted_destination(ROOT / "bin" / "windows-amd64")
        self.output.mkdir()
        (self.output / "build-manifest.json").write_text("old")
        with mock.patch("builtins.print"), mock.patch.object(builder, "prepare_source") as prepare:
            self.assertEqual(builder.main(["--source", str(self.source), "--output", str(self.output), "--prepare-only"]), 1)
        prepare.assert_not_called()
        self.assertEqual((self.output / "build-manifest.json").read_text(), "old")

    def test_non_windows_default_build_fails_before_any_source_or_output_mutation(self):
        with mock.patch.object(builder, "os", SimpleNamespace(name="posix")), \
                mock.patch("builtins.print"), mock.patch.object(builder, "prepare_source") as prepare:
            self.assertEqual(builder.main(["--source", str(self.source), "--output", str(self.output)]), 1)
        prepare.assert_not_called()
        self.assertFalse(self.output.exists())

    def test_prepare_only_cli_writes_the_named_non_runnable_manifest(self):
        with mock.patch.object(builder, "ORIGINAL_SHA256", hashlib.sha256(self.original).hexdigest()), \
                mock.patch.object(builder, "run", side_effect=self.source_commands), mock.patch("builtins.print"):
            self.assertEqual(builder.main(["--source", str(self.source), "--output", str(self.output), "--prepare-only"]), 0)
        manifest = json.loads((self.output / "build-manifest.json").read_text())
        self.assertEqual(manifest["status"], "prepared_only")
        self.assertIsNone(manifest["executor_sha256"])
        self.assertFalse((self.output / "wxc-exec.exe").exists())

    def test_changed_license_or_git_blob_cannot_publish_a_built_executor(self):
        for mode in ('hash', 'blob'):
            with self.subTest(mode=mode):
                self.target.write_bytes(self.original)
                source, manifest = self.prepare()
                output = self.base / ('license-' + mode)
                output.mkdir()
                def commands(arguments, **kwargs):
                    if mode == 'blob' and arguments == ['git', 'show', 'HEAD:LICENSE.md']:
                        return b'different license git blob'
                    return self.source_commands(arguments, **kwargs)
                license_digest = '0' * 64 if mode == 'hash' else builder.sha256(self.license)
                with mock.patch.object(builder, 'os', SimpleNamespace(name='nt')), \
                        mock.patch.object(builder, 'run', side_effect=commands), \
                        mock.patch.object(builder, 'LICENSE_SHA256', license_digest), \
                        self.assertRaisesRegex(ValueError, 'license'):
                    builder.build(source, output, manifest)
                self.assertEqual(manifest['status'], 'prepared_only')
                self.assertFalse((output / 'wxc-exec.exe').exists())
                self.assertFalse((output / 'MXC-LICENSE.md').exists())

    def compiler_message(self, *, filename=None, code='E0609'):
        secret = 'ghp_SyntheticPrivateCredentialNotAnActualToken'
        return {'reason': 'compiler-message', 'package_id': 'file:///private/compiler/path',
                'message': {'level': 'error', 'code': {'code': code},
                            'message': f'no field `{secret}` on type `Example`',
                            'rendered': f'error: {secret} https://private.invalid/?token={secret}',
                            'children': [{'message': 'private inherited environment=' + secret}],
                            'spans': [{'file_name': filename or str(self.target), 'line_start': 51,
                                       'column_start': 9, 'is_primary': True,
                                       'text': [{'text': 'private environment=' + secret}]}]}}

    def test_actual_failed_child_output_preserves_rust_code_and_public_position_only(self):
        message = self.compiler_message()
        output = json.dumps(message) + '\n' + json.dumps({'reason': 'build-script-executed',
            'env': [['PRIVATE_TOKEN', 'ghp_SyntheticPrivateCredentialNotAnActualToken']]}) + '\n'
        program = 'import sys; sys.stdout.write(' + repr(output) + '); sys.stderr.write("error: failed to get private-token https://private.invalid\\n"); sys.exit(101)'
        with self.assertRaises(builder.BuildCommandError) as raised:
            builder.run([sys.executable, '-c', program], cwd=self.source / 'src')
        facts = raised.exception.diagnostics
        self.assertEqual(facts['exit_code'], 101)
        self.assertEqual(facts['compiler_errors'], [{'code': 'E0609', 'category': 'unknown_field',
            'source': self.target.relative_to(self.source / 'src').as_posix(), 'line': 51, 'column': 9}])
        self.assertEqual(facts['cargo_failure_categories'], ['dependency_fetch_failed'])
        encoded = json.dumps(facts)
        for private in ('SyntheticPrivateCredential', 'PRIVATE_TOKEN', 'https://', str(self.source), 'rendered'):
            self.assertNotIn(private, encoded)

    def test_external_or_escaping_source_paths_never_appear_in_compiler_facts(self):
        for filename in (str(self.base / 'private-source.rs'), '../private.rs', 'C:\\Users\\private\\error.rs',
                         'https://private.invalid/error.rs', ('a' * 64) + '.rs'):
            with self.subTest(filename=filename):
                raw = json.dumps(self.compiler_message(filename=filename)).encode()
                facts = builder.compiler_failure_facts(raw, b'', self.source / 'src')
                self.assertEqual(facts['compiler_errors'], [{'code': 'E0609', 'category': 'unknown_field'}])
                self.assertNotIn(filename, json.dumps(facts))

    def test_malformed_and_oversized_output_is_bounded_without_printing_raw_text(self):
        raw = (b'private raw environment\n' + b'x' * builder.MAX_DIAGNOSTIC_INPUT_BYTES + b'\n' +
               b'{bad json}\n' + (json.dumps(self.compiler_message()) + '\n').encode() * 100)
        facts = builder.compiler_failure_facts(raw, b'private token only\n', self.source / 'src')
        self.assertTrue(facts['input_tail_truncated'])
        self.assertEqual(len(facts['compiler_errors']), builder.MAX_COMPILER_ERRORS)
        self.assertLess(len(json.dumps(facts)), 8192)
        self.assertNotIn('private raw', json.dumps(facts))

    def test_timeout_retains_safe_partial_compiler_facts_and_never_command_arguments(self):
        timeout = subprocess.TimeoutExpired(['cargo', 'private command argument'], 30,
            output=json.dumps(self.compiler_message()).encode(), stderr=b'private environment')
        with mock.patch.object(builder.subprocess, 'run', side_effect=timeout), \
                self.assertRaises(builder.BuildCommandError) as raised:
            builder.run(['cargo', 'private command argument'], cwd=self.source / 'src', timeout=30)
        self.assertTrue(raised.exception.diagnostics['timed_out'])
        self.assertIsNone(raised.exception.diagnostics['exit_code'])
        self.assertEqual(raised.exception.diagnostics['compiler_errors'][0]['code'], 'E0609')
        self.assertNotIn('private', str(raised.exception))

    def test_cli_failure_emits_safe_compiler_facts_and_never_a_success_manifest(self):
        source, manifest = self.prepare()
        failure = builder.BuildCommandError(['cargo'], source / 'src', returncode=101,
            stdout=json.dumps(self.compiler_message()).encode(), stderr=b'private credentials')
        with mock.patch.object(builder, 'os', SimpleNamespace(name='nt')), \
                mock.patch.object(builder, 'prepare_source', return_value=(source, manifest)), \
                mock.patch.object(builder, 'build', side_effect=failure), mock.patch('builtins.print') as printed:
            self.assertEqual(builder.main(['--source', str(source), '--output', str(self.output)]), 1)
        value = json.loads(printed.call_args.args[0])
        self.assertEqual(value['status'], 'failed')
        self.assertFalse(value['acceptance_passed'])
        self.assertFalse(value['product_runtime_changed'])
        self.assertEqual(value['build_diagnostics']['compiler_errors'][0]['code'], 'E0609')
        self.assertFalse((self.output / 'build-manifest.json').exists())
        self.assertNotIn('private', json.dumps(value))


if __name__ == "__main__":
    unittest.main()
