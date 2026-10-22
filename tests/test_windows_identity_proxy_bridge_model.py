"""Pure mock bridge lifecycle; these tests create no socket or process."""
import importlib.util
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('bridge_model_test', ROOT / '.github/windows_identity_proxy_bridge_model.py')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
c = m._codec()


def model():
    return m.BridgeModel(c.BridgeConfig(b'r' * 16, b'c' * 16, 51001, 51002, 11000), start=1000)


def request(x):
    return (b'GET http://ruleproxy-identity-proof.invalid/' + x.config.case_id.hex().encode() +
            b' HTTP/1.1\r\nHost: ruleproxy-identity-proof.invalid\r\n\r\n')


def chunks(data, split):
    if split is None or split >= len(data):
        return [data]
    return [data[:split], data[split:]]


def write(x, channel, split=None):
    data = x.pending_output(channel)
    assert data
    for piece in chunks(data, split):
        x.write_progress(channel, len(piece), now=x.now)
    return data


def transfer(x, channel, split=None):
    data = write(x, channel, split)
    for piece in chunks(data, split):
        x.receive_frame(channel, piece, now=x.now)


def ready(x, split=None):
    transfer(x, 'relay_to_front', split)
    transfer(x, 'front_to_relay', split)


def requested(x, split=None, request_split=None):
    ready(x, split)
    for piece in chunks(request(x), request_split):
        x.client_request_bytes(piece, now=x.now)
    x.finish_client_request(now=x.now)
    transfer(x, 'front_to_relay', split)
    assert write(x, 'relay_http', split) == c.relay_request(x.config)


def verified(x, split=None, request_split=None, response_split=None):
    requested(x, split, request_split)
    for piece in chunks(c.expected_response(x.config), response_split):
        x.relay_response_bytes(piece, now=x.now)
    x.relay_response_eof(now=x.now)


def response_received(x, split=None):
    verified(x, split)
    transfer(x, 'relay_to_front', split)


def client_written(x, split=None):
    response_received(x, split)
    x.close_result('relay_writer', True, now=x.now)
    x.pipe_eof('relay_to_front', now=x.now)
    assert write(x, 'client_http', split) == c.expected_response(x.config)


def close_remaining(x):
    for resource, state in tuple(x.resources.items()):
        if state == 'owned' and resource in x.close_requested:
            x.close_result(resource, True, now=x.now)


def finish_verified(x, split=None):
    transfer(x, 'relay_to_front', split)
    x.close_result('relay_writer', True, now=x.now)
    x.pipe_eof('relay_to_front', now=x.now)
    write(x, 'client_http', split)
    x.close_result('client_stream', True, now=x.now)
    transfer(x, 'front_to_relay', split)
    x.close_result('front_writer', True, now=x.now)
    x.pipe_eof('front_to_relay', now=x.now)
    close_remaining(x)
    return x.snapshot()


class BridgeModelTests(unittest.TestCase):
    def test_happy_path_is_only_mock_protocol_and_ownership(self):
        x = model(); verified(x)
        self.assertTrue(x.snapshot()['response_verified'])
        self.assertFalse(x.snapshot()['model_complete'])
        result = finish_verified(x)
        self.assertTrue(result['protocol_complete'])
        self.assertTrue(result['cleanup_confirmed'])
        self.assertTrue(result['model_complete'])
        self.assertTrue(result['model_only'])
        self.assertFalse(result['runtime_acceptance'])
        self.assertEqual(set(result['resources']), set(m.BridgeModel.RESOURCES))
        self.assertNotIn('selected_client_process', result['resources'])

    def test_every_frame_read_and_write_split_point(self):
        for split in range(1, 48):
            with self.subTest(split=split):
                x = model(); verified(x, split)
                self.assertTrue(finish_verified(x, split)['model_complete'])

    def test_every_request_and_response_split_point(self):
        for split in range(1, len(request(model()))):
            x = model(); verified(x, request_split=split)
            self.assertTrue(finish_verified(x)['model_complete'])
        for split in range(1, len(c.expected_response(model().config))):
            x = model(); verified(x, response_split=split)
            self.assertTrue(finish_verified(x)['model_complete'])

    def test_every_http_write_split_point(self):
        for split in range(1, max(len(c.relay_request(model().config)), len(c.expected_response(model().config)))):
            x = model(); verified(x, split)
            self.assertTrue(finish_verified(x, split)['model_complete'])

    def test_one_byte_progress_and_fixed_deadline_no_renewal(self):
        x = model()
        wire = x.pending_output('relay_to_front')
        for index in range(48):
            x.write_progress('relay_to_front', 1, now=1001 + index)
            x.receive_frame('relay_to_front', wire[index:index+1], now=1001 + index)
        self.assertTrue(x.init_received)
        self.assertEqual(x.deadline, 11000)
        self.assertFalse(x.poll(now=10999)['failure'])
        self.assertEqual(x.poll(now=11000)['failure'], 'deadline')
        self.assertEqual(x.pending_output('front_to_relay'), b'')

    def test_response_requires_fixture_eof_and_pipe_eof(self):
        x = model(); requested(x)
        x.relay_response_bytes(c.expected_response(x.config), now=x.now)
        self.assertFalse(x.response_verified)
        self.assertEqual(x.pending_output('relay_to_front'), b'')
        x.relay_response_eof(now=x.now)
        transfer(x, 'relay_to_front')
        self.assertEqual(x.pending_output('client_http'), b'')
        x.close_result('relay_writer', True, now=x.now)
        self.assertEqual(x.pending_output('client_http'), b'')
        x.pipe_eof('relay_to_front', now=x.now)
        self.assertEqual(x.pending_output('client_http'), c.expected_response(x.config))

    def test_done_only_after_full_client_response_and_confirmed_client_close(self):
        x = model(); client_written(x)
        self.assertEqual(x.pending_output('front_to_relay'), b'')
        x.close_result('client_stream', True, now=x.now)
        self.assertEqual(c.decode_frame(x.config, x.pending_output('front_to_relay')).frame_type, 5)
        transfer(x, 'front_to_relay')
        self.assertFalse(x.protocol_complete)
        x.close_result('front_writer', True, now=x.now)
        self.assertFalse(x.protocol_complete)
        x.pipe_eof('front_to_relay', now=x.now)
        self.assertTrue(x.protocol_complete)
        self.assertFalse(x.snapshot()['cleanup_confirmed'])

    def test_wrong_pipe_eof_cannot_substitute_for_required_eof(self):
        x = model(); response_received(x)
        x.pipe_eof('front_to_relay', now=x.now)
        self.assertEqual(x.failure, 'eof_order')
        self.assertTrue(x.response_verified)
        self.assertFalse(x.client_response_written)

    def test_eof_before_writer_closed_is_not_invented(self):
        x = model(); response_received(x)
        x.pipe_eof('relay_to_front', now=x.now)
        self.assertEqual(x.failure, 'eof_order')
        self.assertFalse(x.client_response_written)

    def test_partial_frame_eof_at_every_byte(self):
        for split in range(1, 48):
            x = model(); data = write(x, 'relay_to_front')
            x.receive_frame('relay_to_front', data[:split], now=x.now)
            x.pipe_eof('relay_to_front', now=x.now)
            self.assertEqual(x.failure, 'partial_eof')
            close_remaining(x)
            self.assertTrue(x.snapshot()['cleanup_confirmed'])
            self.assertFalse(x.snapshot()['model_complete'])

    def test_zero_read_or_write_progress_is_terminal(self):
        for operation in ('read', 'write'):
            x = model()
            if operation == 'read': x.receive_frame('relay_to_front', b'', now=x.now)
            else: x.write_progress('relay_to_front', 0, now=x.now)
            self.assertIsNotNone(x.failure)
            self.assertEqual(x.pending_output('relay_to_front'), b'')
            self.assertEqual(x.close_requested, set(x.RESOURCES))

    def test_write_overcount_bool_negative_and_unknown_channel_fail(self):
        for count in (True, -1, 49):
            x = model(); x.write_progress('relay_to_front', count, now=x.now)
            self.assertEqual(x.failure, 'write_progress')
        x = model(); x.write_progress('other', 1, now=x.now)
        self.assertEqual(x.failure, 'write_progress')

    def test_oversized_and_surplus_frames_fail(self):
        x = model(); wire = write(x, 'relay_to_front')
        x.receive_frame('relay_to_front', wire + b'x', now=x.now)
        self.assertEqual(x.failure, 'frame')
        x = model(); response_received(x)
        x.receive_frame('relay_to_front', b'x', now=x.now)
        x.close_result('relay_writer', True, now=x.now)
        x.pipe_eof('relay_to_front', now=x.now)
        self.assertEqual(x.failure, 'partial_eof')
        self.assertTrue(x.response_verified)
        self.assertFalse(x.client_response_written)

    def test_stale_identity_reserved_sequence_and_replay_fail(self):
        for offset in (0, 5, 8, 24, 40):
            x = model(); wire = bytearray(write(x, 'relay_to_front')); wire[offset] ^= 1
            x.receive_frame('relay_to_front', bytes(wire), now=x.now)
            self.assertEqual(x.failure, 'frame')
        x = model(); transfer(x, 'relay_to_front')
        x.receive_frame('relay_to_front', c.encode_frame(x.config, 1), now=x.now)
        self.assertEqual(x.failure, 'order')

    def test_unsent_or_out_of_order_frame_is_not_accepted(self):
        x = model(); x.receive_frame('relay_to_front', c.encode_frame(x.config, 1), now=x.now)
        self.assertEqual(x.failure, 'order')
        x = model(); ready(x)
        x.receive_frame('front_to_relay', c.encode_frame(x.config, 5), now=x.now)
        self.assertEqual(x.failure, 'order')

    def test_request_replay_and_malformed_request_fail_without_relay_output(self):
        x = model(); ready(x); x.client_request_bytes(b'bad\r\n\r\n', now=x.now)
        x.finish_client_request(now=x.now)
        self.assertEqual(x.failure, 'request')
        self.assertEqual(x.pending_output('relay_http'), b'')
        x = model(); requested(x)
        x.client_request_bytes(request(x), now=x.now)
        self.assertEqual(x.failure, 'order')

    def test_http_bounds_and_partial_eof(self):
        x = model(); ready(x); x.client_request_bytes(b'x' * 8193, now=x.now)
        self.assertEqual(x.failure, 'request')
        x = model(); requested(x); x.relay_response_bytes(b'x' * 257, now=x.now)
        self.assertEqual(x.failure, 'response')
        x = model(); requested(x)
        x.relay_response_bytes(c.expected_response(x.config)[:-1], now=x.now)
        x.relay_response_eof(now=x.now)
        self.assertEqual(x.failure, 'response')
        self.assertFalse(x.response_verified)

    def test_all_nonzero_response_statuses_terminal_no_done_wait(self):
        for status in range(1, 5):
            x = model(); requested(x); x.relay_failure(status, now=x.now)
            transfer(x, 'relay_to_front')
            self.assertEqual(x.failure, 'relay_failure')
            self.assertEqual(x.response_status, status)
            self.assertFalse(x.done_received)
            self.assertEqual(x.pending_output('client_http'), b'')
            close_remaining(x)
            self.assertTrue(x.snapshot()['cleanup_confirmed'])
            self.assertFalse(x.snapshot()['model_complete'])

    def test_early_connect_failure_disables_upstream_before_error_frame_drains(self):
        x = model(); ready(x)
        x.client_request_bytes(request(x), now=x.now); x.finish_client_request(now=x.now)
        transfer(x, 'front_to_relay')
        self.assertTrue(x.pending_output('relay_http'))
        x.relay_failure(1, now=x.now)
        self.assertEqual(x.pending_output('relay_http'), b'')
        self.assertEqual(x.pending_output('client_http'), b'')
        x.close_result('client_stream', True, now=x.now)
        self.assertEqual(x.pending_output('front_to_relay'), b'')
        transfer(x, 'relay_to_front')
        self.assertEqual(x.failure, 'relay_failure')
        close_remaining(x)
        self.assertTrue(x.snapshot()['cleanup_confirmed'])
        self.assertFalse(x.response_verified)

    def test_failed_relay_cannot_resume_or_overwrite_pending_status(self):
        for attempt in ('write', 'read', 'eof', 'second_failure'):
            x = model(); requested(x); x.relay_failure(2, now=x.now)
            original = x.outputs['relay_to_front']
            if attempt == 'write': x.write_progress('relay_http', 1, now=x.now)
            elif attempt == 'read': x.relay_response_bytes(c.expected_response(x.config), now=x.now)
            elif attempt == 'eof': x.relay_response_eof(now=x.now)
            else: x.relay_failure(3, now=x.now)
            self.assertIsNotNone(x.failure)
            self.assertFalse(x.response_verified)
            self.assertEqual(x.outputs['relay_to_front'], original)
            self.assertEqual(x.relay_status_sent, 2)

    def test_nonzero_cannot_be_changed_to_zero_by_mock_transport(self):
        x = model(); requested(x); x.relay_failure(1, now=x.now)
        write(x, 'relay_to_front')
        x.receive_frame('relay_to_front', c.encode_frame(x.config, 4, 0), now=x.now)
        self.assertEqual(x.failure, 'order')
        self.assertFalse(x.response_verified)

    def test_deadline_at_each_stage_closes_without_renewal(self):
        for reach in (lambda x: None, ready, requested, verified, response_received, client_written):
            x = model(); reach(x)
            positive = x.response_verified
            x.poll(now=x.deadline)
            self.assertEqual(x.failure, 'deadline')
            self.assertEqual(x.deadline, 11000)
            self.assertEqual(x.response_verified, positive)
            close_remaining(x)
            self.assertTrue(x.snapshot()['cleanup_confirmed'])
            self.assertFalse(x.snapshot()['model_complete'])

    def test_invalid_or_backwards_clock_fails_closed(self):
        for now in (True, 999, 1.5):
            x = model(); x.poll(now=now)
            self.assertEqual(x.failure, 'clock')
        for start in (True, -1, 0):
            with self.assertRaisesRegex(m.BridgeModelError, '^deadline$'):
                m.BridgeModel(model().config, start=start)

    def test_cleanup_failure_preserves_verified_response_and_no_retry(self):
        x = model(); verified(x)
        x.close_result('relay_stream', False, now=x.now)
        self.assertEqual(x.failure, 'cleanup')
        self.assertTrue(x.response_verified)
        self.assertEqual(x.resources['relay_stream'], 'unknown')
        x.close_result('relay_stream', True, now=x.now)
        self.assertEqual(x.resources['relay_stream'], 'unknown')
        close_remaining(x)
        self.assertFalse(x.snapshot()['cleanup_confirmed'])
        self.assertTrue(x.snapshot()['response_verified'])

    def test_late_cleanup_failure_preserves_protocol_and_written_observations(self):
        x = model(); client_written(x)
        x.close_result('client_stream', True, now=x.now)
        transfer(x, 'front_to_relay')
        x.close_result('front_writer', True, now=x.now)
        x.pipe_eof('front_to_relay', now=x.now)
        x.close_result('relay_stream', False, now=x.now)
        close_remaining(x)
        out = x.snapshot()
        self.assertTrue(out['protocol_complete'])
        self.assertTrue(out['response_verified'])
        self.assertTrue(out['client_response_written'])
        self.assertFalse(out['model_complete'])
        self.assertFalse(out['cleanup_confirmed'])

    def test_transport_error_is_closed_and_sticky(self):
        x = model(); verified(x); x.transport_error(now=x.now)
        close_remaining(x)
        wire = json.dumps(x.snapshot())
        self.assertEqual(x.failure, 'transport')
        self.assertTrue(x.response_verified)
        self.assertNotIn(x.config.case_id.hex(), wire)
        self.assertNotIn('10.0.2.2', wire)
        self.assertNotIn('51002', wire)

    def test_snapshot_cannot_mutate_owned_ledger(self):
        x = model(); out = x.snapshot(); out['resources']['relay_writer'] = 'closed'
        self.assertEqual(x.resources['relay_writer'], 'owned')
        with self.assertRaisesRegex(m.BridgeModelError, '^channel$'):
            x.pending_output('unknown')

    def test_model_source_has_no_runtime_or_security_primitives(self):
        import ast
        tree = ast.parse((ROOT / '.github/windows_identity_proxy_bridge_model.py').read_text())
        modules = {alias.name for node in ast.walk(tree) if isinstance(node, ast.Import) for alias in node.names}
        self.assertEqual(modules, {'importlib.util', 'sys'})
        names = {node.id for node in ast.walk(tree) if isinstance(node, ast.Name)}
        self.assertTrue(names.isdisjoint({'socket', 'subprocess', 'ctypes', 'os', 'time'}))


if __name__ == '__main__':
    unittest.main()
