"""Current desktop user's documented WinINet LAN connection flags."""
from __future__ import annotations

import ctypes

MANUAL_FLAGS = 1 | 2  # PROXY_TYPE_DIRECT | PROXY_TYPE_PROXY; no PAC or detection.
DWORD = ctypes.c_uint32


class Value(ctypes.Union):
    _fields_ = [('dwValue', DWORD), ('pszValue', ctypes.c_void_p), ('ftValue', DWORD * 2)]


class Option(ctypes.Structure):
    _fields_ = [('dwOption', DWORD), ('Value', Value)]


class Options(ctypes.Structure):
    _fields_ = [('dwSize', DWORD), ('pszConnection', ctypes.c_wchar_p),
                ('dwOptionCount', DWORD), ('dwOptionError', DWORD),
                ('pOptions', ctypes.POINTER(Option))]


def _api():
    api = ctypes.WinDLL('wininet', use_last_error=True)
    api.InternetQueryOptionW.argtypes = [ctypes.c_void_p, DWORD, ctypes.c_void_p, ctypes.POINTER(DWORD)]
    api.InternetQueryOptionW.restype = ctypes.c_int
    api.InternetSetOptionW.argtypes = [ctypes.c_void_p, DWORD, ctypes.c_void_p, DWORD]
    api.InternetSetOptionW.restype = ctypes.c_int
    return api


def _options(option):
    return Options(ctypes.sizeof(Options), None, 1, 0, ctypes.pointer(option))


def query_flags():
    api = _api()
    for identifier in (10, 1):  # FLAGS_UI; documented fallback to FLAGS.
        option = Option(identifier)
        options = _options(option)
        size = DWORD(ctypes.sizeof(options))
        if api.InternetQueryOptionW(None, 75, ctypes.byref(options), ctypes.byref(size)):
            return int(option.Value.dwValue)
    raise OSError('WinINet connection flags could not be queried')


def set_flags(flags):
    if type(flags) is not int or not 0 <= flags <= 0xffffffff:
        raise ValueError('Invalid WinINet connection flags')
    option = Option(1)  # Restore using FLAGS, including on Windows 7 and later.
    option.Value.dwValue = flags
    options = _options(option)
    api = _api()
    if not api.InternetSetOptionW(None, 75, ctypes.byref(options), ctypes.sizeof(options)):
        raise OSError('WinINet connection flags could not be changed')
    for identifier in (39, 37):
        if not api.InternetSetOptionW(None, identifier, None, 0):
            raise OSError('WinINet connection flags refresh failed')
