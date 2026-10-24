"""Inactive bridge-v1 deterministic model; no transport or security APIs.

All time values are caller-supplied integer milliseconds. Output and close requests
are intentions only. A mock must separately report byte progress, EOF, and closure.
The ledger describes frontend/relay resources, never ownership of a selected client
process. Protocol assertions do not establish token identity or OS containment.
"""
import importlib.util
from pathlib import Path
import sys


def _codec():
    name = '_identity_proxy_bridge_codec_model'
    path = Path(__file__).with_name('windows_identity_proxy_bridge_codec.py')
    if name not in sys.modules:
        spec = importlib.util.spec_from_file_location(name, path)
        module = importlib.util.module_from_spec(spec)
        sys.modules[name] = module
        try:
            spec.loader.exec_module(module)
        except BaseException:
            sys.modules.pop(name, None)
            raise
    return sys.modules[name]


class BridgeModelError(ValueError):
    """Closed construction error, never containing supplied data."""


class BridgeModel:
    BUDGET_MS = 10000
    CHANNELS = ('relay_to_front', 'front_to_relay', 'relay_http', 'client_http')
    RESOURCES = ('relay_writer', 'front_reader', 'front_writer', 'relay_reader',
                 'client_stream', 'relay_stream')

    def __init__(self, config, *, start):
        self.codec = _codec()
        # Accept the immutable codec value even if imported by another test loader;
        # reconstruct through its strict constructor, never nominal type spoofing.
        try:
            self.config = self.codec.BridgeConfig(config.run_id, config.case_id,
                                                config.frontend_port, config.relay_port,
                                                config.deadline)
        except (AttributeError, TypeError, ValueError):
            raise BridgeModelError('configuration') from None
        if type(start) is not int or start < 0 or self.config.deadline != start + self.BUDGET_MS:
            raise BridgeModelError('deadline')
        self.start = self.now = start
        self.deadline = self.config.deadline
        self.failure = None
        self.protocol_complete = False
        self.response_verified = False
        self.client_response_written = False
        self.response_status = None
        self.relay_status_sent = None
        self.relay_failed = False
        self.init_received = self.ready_received = self.request_received = False
        self.request_submitted = self.response_received = self.done_received = False
        self.relay_eof = self.front_eof = False
        self.close_requested = set()
        self.resources = {key: 'owned' for key in self.RESOURCES}
        self.outputs = {key: b'' for key in self.CHANNELS}
        self.output_kinds = {key: None for key in self.CHANNELS}
        self.sent = set()
        self.frames = {key: bytearray() for key in self.CHANNELS[:2]}
        self.request = bytearray()
        self.response = bytearray()
        self._queue('relay_to_front', self.codec.encode_frame(self.config, 1), 'init')

    def _fail(self, reason):
        if self.failure is None:
            self.failure = reason
        self.close_requested.update(self.RESOURCES)

    def _clock(self, now):
        if type(now) is not int or now < self.now:
            self._fail('clock')
            return False
        self.now = now
        if now >= self.deadline:
            self._fail('deadline')
        return self.failure is None

    def _queue(self, channel, data, kind):
        if self.outputs[channel]:
            self._fail('order')
            return
        self.outputs[channel] = data
        self.output_kinds[channel] = kind

    def poll(self, *, now):
        self._clock(now)
        return self.snapshot()

    def pending_output(self, channel):
        if channel not in self.outputs:
            raise BridgeModelError('channel')
        return self.outputs[channel] if (self.failure is None and
                                        (not self.relay_failed or channel == 'relay_to_front')) else b''

    def write_progress(self, channel, count, *, now):
        if not self._clock(now):
            return self.snapshot()
        if channel not in self.outputs or type(count) is not int or count <= 0:
            self._fail('write_progress')
        elif not self.outputs[channel] or count > len(self.outputs[channel]):
            self._fail('write_progress')
        else:
            self.outputs[channel] = self.outputs[channel][count:]
            if not self.outputs[channel]:
                kind = self.output_kinds[channel]
                self.output_kinds[channel] = None
                self.sent.add(kind)
                if kind == 'response':
                    self.close_requested.add('relay_writer')
                elif kind == 'client_response':
                    self.client_response_written = True
                    self.close_requested.add('client_stream')
                elif kind == 'done':
                    self.close_requested.add('front_writer')
        return self.snapshot()

    def receive_frame(self, channel, data, *, now):
        if not self._clock(now):
            return self.snapshot()
        if channel not in self.frames or type(data) is not bytes or not data:
            self._fail('read_progress')
            return self.snapshot()
        buffer = self.frames[channel]
        if len(buffer) + len(data) > 48:
            self._fail('frame')
            return self.snapshot()
        buffer.extend(data)
        if len(buffer) != 48:
            return self.snapshot()
        try:
            frame = self.codec.decode_frame(self.config, bytes(buffer))
        except (ValueError, TypeError):
            self._fail('frame')
            return self.snapshot()
        buffer.clear()
        if channel == 'relay_to_front':
            if frame.frame_type == 1 and not self.init_received and 'init' in self.sent:
                self.init_received = True
                self._queue('front_to_relay', self.codec.encode_frame(self.config, 2), 'ready')
            elif (frame.frame_type == 4 and self.request_received and not self.response_received
                  and 'response' in self.sent and frame.status == self.relay_status_sent):
                self.response_received = True
                self.response_status = frame.status
                if frame.status != 0:
                    self._fail('relay_failure')
            else:
                self._fail('order')
        elif frame.frame_type == 2 and not self.ready_received and 'ready' in self.sent:
            self.ready_received = True
        elif (frame.frame_type == 3 and self.ready_received and not self.request_received
              and 'request' in self.sent):
            self.request_received = True
            self._queue('relay_http', self.codec.relay_request(self.config), 'relay_request')
        elif (frame.frame_type == 5 and self.response_received and not self.done_received
              and 'done' in self.sent):
            self.done_received = True
        else:
            self._fail('order')
        return self.snapshot()

    def client_request_bytes(self, data, *, now):
        if not self._clock(now):
            return self.snapshot()
        if not self.ready_received or self.request_submitted:
            self._fail('order')
        elif type(data) is not bytes or not data:
            self._fail('read_progress')
        elif len(self.request) + len(data) > 8192:
            self._fail('request')
        else:
            self.request.extend(data)
        return self.snapshot()

    def finish_client_request(self, *, now):
        if not self._clock(now):
            return self.snapshot()
        if not self.ready_received or self.request_submitted:
            self._fail('order')
        else:
            try:
                self.codec.parse_proxy_request(self.config, bytes(self.request))
            except (ValueError, TypeError):
                self._fail('request')
            else:
                self.request_submitted = True
                self._queue('front_to_relay', self.codec.encode_frame(self.config, 3), 'request')
        return self.snapshot()

    def relay_response_bytes(self, data, *, now):
        if not self._clock(now):
            return self.snapshot()
        if self.relay_failed or 'relay_request' not in self.sent or self.response_verified:
            self._fail('order')
        elif type(data) is not bytes or not data:
            self._fail('read_progress')
        elif len(self.response) + len(data) > 256:
            self._fail('response')
        else:
            self.response.extend(data)
        return self.snapshot()

    def relay_response_eof(self, *, now):
        if not self._clock(now):
            return self.snapshot()
        if self.relay_failed or 'relay_request' not in self.sent or self.response_verified:
            self._fail('order')
        else:
            try:
                self.codec.validate_response(self.config, bytes(self.response), eof=True)
            except (ValueError, TypeError):
                self._fail('response')
            else:
                self.response_verified = True
                self.relay_status_sent = 0
                self.close_requested.add('relay_stream')
                self._queue('relay_to_front', self.codec.encode_frame(self.config, 4), 'response')
        return self.snapshot()

    def relay_failure(self, status, *, now):
        """Mock relay reports connect/I/O/fixture/deadline failure; no retry."""
        if not self._clock(now):
            return self.snapshot()
        if (type(status) is not int or status not in (1, 2, 3, 4)
                or not self.request_received or self.relay_status_sent is not None):
            self._fail('order')
        else:
            self.relay_failed = True
            self.relay_status_sent = status
            self.outputs['relay_http'] = b''
            self.output_kinds['relay_http'] = None
            self.close_requested.update(('relay_stream', 'client_stream'))
            self._queue('relay_to_front', self.codec.encode_frame(self.config, 4, status), 'response')
        return self.snapshot()

    def pipe_eof(self, channel, *, now):
        if not self._clock(now):
            return self.snapshot()
        if channel not in self.frames or self.frames[channel]:
            self._fail('partial_eof')
        elif channel == 'relay_to_front':
            if (self.relay_eof or not self.response_received or self.response_status != 0
                    or self.resources['relay_writer'] != 'closed'):
                self._fail('eof_order')
            else:
                self.relay_eof = True
                self.close_requested.add('front_reader')
                self._queue('client_http', self.codec.expected_response(self.config), 'client_response')
        elif (self.front_eof or not self.done_received
              or self.resources['front_writer'] != 'closed'):
            self._fail('eof_order')
        else:
            self.front_eof = True
            self.protocol_complete = True
            self.close_requested.update(self.RESOURCES)
        return self.snapshot()

    def close_result(self, resource, confirmed, *, now):
        """Record one mock close attempt; failed/unknown closure is never retried."""
        healthy = self._clock(now)
        if (resource not in self.resources or type(confirmed) is not bool
                or resource not in self.close_requested or self.resources[resource] != 'owned'):
            self._fail('close_order')
        else:
            self.resources[resource] = 'closed' if confirmed else 'unknown'
            if not confirmed:
                self._fail('cleanup')
            elif healthy and not self.relay_failed and resource == 'client_stream':
                if not self.client_response_written or not self.relay_eof:
                    self._fail('order')
                else:
                    self._queue('front_to_relay', self.codec.encode_frame(self.config, 5), 'done')
        return self.snapshot()

    def transport_error(self, *, now):
        """A mock I/O exception, intentionally without exception text or endpoints."""
        self._clock(now)
        self._fail('transport')
        return self.snapshot()

    def snapshot(self):
        cleanup = all(value == 'closed' for value in self.resources.values())
        return {'schema_version': 1, 'model_only': True, 'runtime_acceptance': False,
                'protocol_complete': self.protocol_complete,
                'response_verified': self.response_verified,
                'client_response_written': self.client_response_written,
                'relay_pipe_eof': self.relay_eof, 'frontend_pipe_eof': self.front_eof,
                'cleanup_confirmed': cleanup,
                'model_complete': self.protocol_complete and cleanup and self.failure is None,
                'failure': self.failure, 'resources': dict(self.resources)}
