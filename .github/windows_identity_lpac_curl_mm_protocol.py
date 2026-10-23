"""Caller-owned ABI2 buffers; no library loading, Win32 lookup or process API.

The guarded owner supplies an already verified library. Only explicit call()
invokes its export. All critical storage and immutable expectations are built
before Resume; the observation path allocates no new ctypes output buffer.
"""
import ctypes as C
import importlib.util
from pathlib import Path

_spec = importlib.util.spec_from_file_location('cmm_protocol_inputs', Path(__file__).with_name('windows_identity_lpac_curl_mm_inputs.py'))
inputs = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(inputs)

EXPORTS = {
    'begin': ('cmm_begin_v2', 3),
    'update': ('cmm_update_v2', 2),
    'install': ('cmm_install_marker_v2', 3),
    'observe': ('cmm_observe_v2', 2),
    'forget': ('cmm_forget_exited_v2', 2),
}


def aligned_buffer(raw):
    inputs.require(type(raw) is bytes and raw, 'buffer_bytes')

    class Buffer(C.Union):
        _fields_ = [('storage', C.c_uint8 * len(raw)), ('alignment', C.c_uint64)]

    result = Buffer()
    result.storage[:] = raw
    inputs.require(C.alignment(Buffer) == 8 and C.addressof(result) % 8 == 0, 'alignment')
    return result


def logical_bytes(buffer):
    return bytes(buffer.storage)


def bind_library(library):
    version = library.cmm_abi_version
    version.argtypes = []
    version.restype = C.c_uint32
    observed = version()
    inputs.require(type(observed) is int and observed == 2, 'library_version')
    for name, count in EXPORTS.values():
        function = getattr(library, name)
        function.argtypes = [C.c_void_p] * count
        function.restype = C.c_uint32


class NativeBuffers:
    def __init__(self, *, config, window, generation, handles, paths, target, marker_file,
                 primary, security, signals):
        identity = inputs.identity_bytes(primary)
        sd = inputs.security_bytes(security, primary['sid'])
        initial_marker = inputs.marker_bytes(config, window, generation, signals)
        self._buffers = {
            'target_path': aligned_buffer(inputs.utf16(paths['target'], 260, dos=True)),
            'marker_nt_path': aligned_buffer(inputs.utf16(paths['marker_nt'], 1024)),
            'marker_ascii_path': aligned_buffer(paths['marker_ascii'].encode('ascii') + b'\0'),
            'expected_identity': aligned_buffer(identity),
            'expected_security': aligned_buffer(sd),
        }
        pointers = {name: C.addressof(value) for name, value in self._buffers.items()}
        packed_plan = inputs.plan_bytes(config, window, generation, handles, pointers, paths,
                                        target, marker_file, inputs.CMM_GUID)
        self.ctx = aligned_buffer(bytes(8192))
        self.plan = aligned_buffer(packed_plan)
        self.marker = aligned_buffer(initial_marker)
        self.output = aligned_buffer(bytes(24576))
        self._results = {operation: aligned_buffer(bytes(256)) for operation in EXPORTS if operation != 'observe'}
        all_buffers = [self.ctx, self.plan, self.marker, self.output,
                       *self._results.values(), *self._buffers.values()]
        intervals = [(C.addressof(value), C.addressof(value) + C.sizeof(value)) for value in all_buffers]
        inputs.require(all(end > start for start, end in intervals)
                       and all(a1 <= b0 or b1 <= a0 for index, (a0, a1) in enumerate(intervals)
                               for b0, b1 in intervals[index + 1:]), 'buffer_alias')
        self._expected = dict(plan512=packed_plan, identity256=identity, security1024=sd,
                              initial_marker320=initial_marker, target_path=paths['target'],
                              marker_nt_path=paths['marker_nt'], marker_ascii_path=paths['marker_ascii'],
                              commitments={key: bytes.fromhex(config[key]) for key in
                                           ('run', 'config_sha256', 'source_sha256', 'target_sha256', 'marker_sha256')})
        self._input_files = {
            'native-plan.bin': packed_plan,
            'native-marker.bin': initial_marker,
            'native-identity.bin': identity,
            'native-security.bin': sd,
            'native-target-path.u16': inputs.utf16(paths['target'], 260, dos=True),
            'native-marker-nt-path.u16': inputs.utf16(paths['marker_nt'], 1024),
            'native-marker-ascii-path.ascii': paths['marker_ascii'].encode('ascii') + b'\0',
        }
        self._input_buffers_original = {name: logical_bytes(value) for name, value in self._buffers.items()}
        self._entered = set()

    def expectation(self):
        return {**self._expected, 'commitments': dict(self._expected['commitments'])}

    def input_files(self):
        return dict(self._input_files)

    def inputs_unchanged(self):
        return (logical_bytes(self.plan) == self._expected['plan512']
                and logical_bytes(self.marker) == self._expected['initial_marker320']
                and all(logical_bytes(value) == self._input_buffers_original[name]
                        for name, value in self._buffers.items()))

    def call(self, library, operation):
        inputs.require(operation in EXPORTS and operation not in self._entered, 'export_once')
        self._entered.add(operation)
        name, _ = EXPORTS[operation]
        if operation == 'observe':
            code = int(getattr(library, name)(C.byref(self.ctx), C.byref(self.output)))
            raw_output = logical_bytes(self.output)
            return code, raw_output[:256], raw_output
        result = self._results[operation]
        arguments = [C.byref(self.ctx)]
        if operation == 'begin':
            arguments = [C.byref(self.plan), C.byref(self.ctx)]
        elif operation == 'install':
            arguments.append(C.byref(self.marker))
        code = int(getattr(library, name)(*arguments, C.byref(result)))
        # The caller durably saves these physical bytes before interpreting
        # inputs_unchanged(), result classes, clock or any success predicate.
        return code, logical_bytes(result), None
