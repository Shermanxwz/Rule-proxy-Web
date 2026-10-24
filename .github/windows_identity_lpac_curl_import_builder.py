"""Offline fixed-curl import builder/model. No process or file access.

Root authorized this offline-only implementation after design03; that does
not authorize a loader, memory backend, shim, target or network experiment.
All outputs are immutable private model data, never runtime acceptance.
"""
from dataclasses import dataclass
from enum import Enum
import hashlib
import re
import struct

ACTUAL_READY=False
OFFLINE_IMPLEMENTATION_AUTHORIZED=True
INTERFACE_VERSION=1
CURL_BYTES=818512
CURL_SHA256='73d24149ff289afc49ec41f08918ef9faa727d39ad993e929757dc2ddafab805'
PRIVATE_BASENAME='windows_identity_lpac_curl_ws2_shim.dll'
ARENA_RVA=0xD0000
ARENA_BYTES=4096
NAME_OFFSET=864
IMPORT_HEADER_OFFSET=400
IMPORT_RVA=777208
IMPORT_BYTES=860
IAT_RVA=593920
IAT_BYTES=2232
SIZE_HEADERS=1024
SIZE_IMAGE=827392
MAX_U64=0xffffffffffffffff
SOURCE_TRANSCRIPT_SHA256='9650b53c06387f060e332ab0feb201b644d5963fbac037d039318d403827723e'
DESIGN_CONTRACT_SHA256='29cf4a9c230745cb2b78bc687aec2d032a8d05208a1733817f7c3b6b503d7d40'
EXPORT_MANIFEST_SHA256='f8d7075efc12a956914094e75751fd8d3ade23df98ae7aef92789f7116c51e23'
_EXPECTED_SECTIONS=(('.text', 585968, 4096, 586240, 1024, 1610612768), ('.rdata', 191092, 593920, 191488, 587264, 1073741888), ('.data', 8096, 786432, 3072, 778752, 3221225536), ('.pdata', 19044, 794624, 19456, 781824, 1073741888), ('.rsrc', 1432, 815104, 1536, 801280, 1073741888), ('.reloc', 5176, 819200, 5632, 802816, 1107296320))
_EXPECTED_IMPORTS=(('WS2_32.dll', 777208, 782160, 778496, 594344, 0, 0, 'e6a63cd15324c3afa137f41c89cd86f9e933e57a7422bc907c0cc7596e9b12bf', (('WSAEnumNetworkEvents', 44, None, 781068), (None, None, 7, 9223372036854775815), ('WSAWaitForMultipleEvents', 94, None, 781092), ('WSAResetEvent', 77, None, 781120), ('WSAEventSelect', 47, None, 781136), ('WSACreateEvent', 37, None, 781154), ('WSACloseEvent', 32, None, 781172), (None, None, 6, 9223372036854775814), (None, None, 111, 9223372036854775919), (None, None, 16, 9223372036854775824), (None, None, 23, 9223372036854775831), (None, None, 10, 9223372036854775818), (None, None, 3, 9223372036854775811), (None, None, 8, 9223372036854775816), (None, None, 4, 9223372036854775812), (None, None, 19, 9223372036854775827), (None, None, 57, 9223372036854775865), ('getaddrinfo', 166, None, 781814), ('freeaddrinfo', 165, None, 781798), (None, None, 112, 9223372036854775920), (None, None, 13, 9223372036854775821), (None, None, 22, 9223372036854775830), (None, None, 21, 9223372036854775829), (None, None, 2, 9223372036854775810), (None, None, 1, 9223372036854775809), (None, None, 17, 9223372036854775825), (None, None, 20, 9223372036854775828), (None, None, 151, 9223372036854775959), (None, None, 18, 9223372036854775826), (None, None, 116, 9223372036854775924), (None, None, 115, 9223372036854775923), ('WSAIoctl', 59, None, 781366), (None, None, 5, 9223372036854775813), (None, None, 15, 9223372036854775823), (None, None, 9, 9223372036854775817))), ('api-ms-win-core-console-l2-1-0.dll', 777228, 782172, 778824, 594672, 0, 0, 'b44c8923e7a1f790b984e0facd71584b83de7777364e0c4d417b98303758449d', (('GetConsoleScreenBufferInfo', 9, None, 780304),)), ('api-ms-win-core-processenvironment-l1-1-0.dll', 777248, 782208, 779096, 594944, 0, 0, '808250be343414ce369770ee4fa260891df607f247de7a2d1c0a6dd3c0cc89fc', (('GetStdHandle', 12, None, 780334), ('SetStdHandle', 22, None, 780622), ('SearchPathW', 16, None, 780424), ('GetEnvironmentVariableA', 10, None, 780798))), ('api-ms-win-core-string-l1-1-0.dll', 777268, 782254, 779240, 595088, 0, 0, '44c4703cc34a801d7f282ce839c2cf33b913acd1ce40f159ec1e8c9762330316', (('WideCharToMultiByte', 7, None, 780638), ('MultiByteToWideChar', 6, None, 780350))), ('api-ms-win-core-console-l1-1-0.dll', 777288, 782288, 778784, 594632, 0, 0, '9f44f0932065d47c7726bb65199e81f49d8aa7dfa2bcc323bfc69545b8816cb0', (('SetConsoleCtrlHandler', 16, None, 780400), ('SetConsoleMode', 17, None, 780458), ('GetConsoleMode', 6, None, 780522), ('WriteConsoleW', 19, None, 780372))), ('api-ms-win-core-file-l1-1-0.dll', 777308, 782324, 778864, 594712, 0, 0, '7cd4fdb347a291cadb3c72a55154e98eece412bfb5e09cf6178a5184405f80b7', (('GetFileTime', 49, None, 780690), ('GetFullPathNameW', 54, None, 780876), ('SetEndOfFile', 81, None, 780726), ('GetFileType', 50, None, 781420), ('ReadFile', 76, None, 780388), ('CreateFileW', 7, None, 780896), ('SetFileTime', 90, None, 780676))), ('api-ms-win-core-processthreads-l1-1-0.dll', 777328, 782356, 779136, 594984, 0, 0, 'eea000b6c8a458c9eba4f6dcb877f5a1fd839d129457b9fe28c1f7e678425abf', (('TlsFree', 88, None, 784476), ('TlsSetValue', 90, None, 784462), ('GetCurrentProcess', 12, None, 780438), ('CreateThread', 6, None, 780588), ('TlsAlloc', 87, None, 784436), ('TlsGetValue', 89, None, 784448), ('TerminateThread', 86, None, 780556))), ('api-ms-win-core-handle-l1-1-0.dll', 777348, 782398, 778944, 594792, 0, 0, 'd0195368c7f9ec25c67d05bf9e79f8c0f9d0f8b30859cd709a4f25d5bdad9daa', (('CloseHandle', 0, None, 780574), ('DuplicateHandle', 2, None, 780476))), ('api-ms-win-core-toolhelp-l1-1-0.dll', 777368, 782432, 779448, 595296, 0, 0, 'a29ce8cfaacec5928c6c9d9692b9907eb8d1679b61450b4b6a81490af0c6c094', (('Module32FirstW', 5, None, 780604), ('Module32NextW', 6, None, 780660), ('CreateToolhelp32Snapshot', 0, None, 780494))), ('api-ms-win-core-errorhandling-l1-1-0.dll', 777388, 782468, 778840, 594688, 0, 0, '4cc4c6667e019778b40cc66c17998007c44621b8df8835ef7184a769c79be56d', (('SetLastError', 13, None, 780782), ('GetLastError', 5, None, 780540))), ('api-ms-win-core-libraryloader-l1-2-0.dll', 777408, 782510, 779000, 594848, 0, 0, '38eabb3c363b8aa4a4b7efb790e668e2f8473a3ebf424874d211f8795db626b6', (('LoadLibraryExW', 25, None, 784500), ('GetModuleHandleW', 21, None, 781026), ('GetModuleFileNameA', 16, None, 780704), ('FreeLibrary', 13, None, 784486), ('GetProcAddress', 22, None, 780986))), ('api-ms-win-core-timezone-l1-1-0.dll', 777428, 782552, 779432, 595280, 0, 0, 'f267747cf36e119f7d17d6818d73866de7058de3266d984b55b8823ce7fe7332', (('SystemTimeToFileTime', 10, None, 780742),)), ('api-ms-win-core-sysinfo-l1-1-0.dll', 777448, 782588, 779400, 595248, 0, 0, '58bb62e7934616c2996538e5e823ff661c02cce01f56f6d78c2d23a9f4960dad', (('GetSystemTime', 20, None, 780766),)), ('api-ms-win-core-synch-l1-1-0.dll', 777468, 782624, 779264, 595112, 0, 0, '1760ee2eb7f3d77a6c5ab2ccd3f63dbdcd3871b0c5d6540ed73df05f899a5296', (('WaitForSingleObjectEx', 55, None, 782136), ('InitializeCriticalSectionEx', 26, None, 781236), ('EnterCriticalSection', 17, None, 781188), ('AcquireSRWLockExclusive', 0, None, 780850), ('ReleaseSRWLockExclusive', 36, None, 780824), ('LeaveCriticalSection', 29, None, 781212), ('SleepEx', 48, None, 781356), ('InitializeCriticalSectionAndSpinCount', 25, None, 784396), ('DeleteCriticalSection', 15, None, 781266))), ('api-ms-win-core-synch-l1-2-0.dll', 777488, 782658, 779344, 595192, 0, 0, '3c33568e72e5dd83fe8a5118470cb66c8f8c8ff1f1d9d51da90f51a6c38202a0', (('InitializeConditionVariable', 23, None, 781768), ('Sleep', 45, None, 780910), ('SleepConditionVariableCS', 46, None, 782084), ('WakeConditionVariable', 60, None, 782112))), ('api-ms-win-core-file-l2-1-0.dll', 777508, 782692, 778928, 594776, 0, 0, 'b0700f960917a880a4f82f07aacabb043e68be30c70334579917afd605b9a8b4', (('MoveFileExW', 8, None, 780918),)), ('api-ms-win-core-profile-l1-1-0.dll', 777528, 782724, 779200, 595048, 0, 0, '98bb035eb07f481b22ecbb6a5e9ee090d314b8dff4dbdc0e146a3cd3233591e4', (('QueryPerformanceFrequency', 1, None, 780932), ('QueryPerformanceCounter', 0, None, 780960))), ('api-ms-win-core-sysinfo-l1-2-0.dll', 777548, 782760, 779416, 595264, 0, 0, '490fbaa1021a78c4b4477855aab110fd3296df5972f1872a71e60d99f2551f85', (('VerSetConditionMask', 46, None, 781004),)), ('api-ms-win-core-kernel32-legacy-l1-1-1.dll', 777568, 782796, 778984, 594832, 0, 0, 'e10d21efc33a7ceb0b0a0edc1e979cff966a868fd3637c5c66c8fbcd9efa6319', (('VerifyVersionInfoW', 99, None, 781046),)), ('api-ms-win-core-localization-l1-2-0.dll', 777588, 782840, 779048, 594896, 0, 0, '1f397c6beab82819e53e7fe9479d3eb42a12491d2e31d61c91eb79eb2d4fde8d', (('FormatMessageA', 8, None, 781338), ('IdnToAscii', 40, None, 781290), ('IdnToUnicode', 41, None, 781304))), ('bcrypt.dll', 777608, 782880, 780288, 596136, 0, 0, '018525503ab333448d9ecb2c5fd3c8f4e10b01028da409b2376e2684f69a4d93', (('BCryptGenRandom', 29, None, 781320),)), ('WLDAP32.dll', 777628, 782892, 778344, 594192, 0, 0, '16c7244fe2f9962acf76c4d1c97b342655e7be665bcc3391837db7a256a4b6c8', ((None, None, 145, 9223372036854775953), (None, None, 216, 9223372036854776024), (None, None, 142, 9223372036854775950), (None, None, 41, 9223372036854775849), (None, None, 14, 9223372036854775822), (None, None, 147, 9223372036854775955), (None, None, 79, 9223372036854775887), (None, None, 27, 9223372036854775835), (None, None, 26, 9223372036854775834), (None, None, 127, 9223372036854775935), (None, None, 46, 9223372036854775854), (None, None, 117, 9223372036854775925), (None, None, 301, 9223372036854776109), (None, None, 219, 9223372036854776027), (None, None, 133, 9223372036854775941), (None, None, 73, 9223372036854775881), (None, None, 208, 9223372036854776016), (None, None, 167, 9223372036854775975))), ('api-ms-win-core-synch-l1-2-1.dll', 777648, 782904, 779384, 595232, 0, 0, '900f8a4f867cac09ca79c451789219c0812278c912d7f7750a43f6143b05232e', (('WaitForMultipleObjects', 101, None, 781378),)), ('api-ms-win-core-namedpipe-l1-1-0.dll', 777668, 782938, 779080, 594928, 0, 0, '1f19871df704bb19e0c397d40854bae5036dc39673b86d7b4ef7c878da533943', (('PeekNamedPipe', 9, None, 781404),)), ('IPHLPAPI.DLL', 777688, 782976, 778208, 594056, 0, 0, 'd5fa725b68fcd3b1cfe598c71f5be24265359b233ee83d777a88758498349494', (('if_nametoindex', 305, None, 781434),)), ('api-ms-win-security-cryptoapi-l1-1-0.dll', 777708, 782990, 780232, 596080, 0, 0, '9945afcb0e0808a4977a4f4c0e0175bd2a2bd2a191ca79b82f58a7b3e3216770', (('CryptGetHashParam', 20, None, 781496), ('CryptHashData', 24, None, 781566), ('CryptAcquireContextW', 1, None, 781694), ('CryptCreateHash', 3, None, 781582), ('CryptDestroyHash', 6, None, 781546), ('CryptReleaseContext', 27, None, 781452))), ('CRYPT32.dll', 777728, 783032, 778072, 593920, 0, 0, '2beaaecb5b5a89803313d49d65e2b79670d8750315801302fc451325fc0e745a', (('CertCreateCertificateChainEngine', 27, None, 782048), ('PFXImportCertStore', 292, None, 781474), ('CertFreeCertificateContext', 64, None, 781516), ('CertEnumCertificatesInStore', 44, None, 781600), ('CertCloseStore', 18, None, 781630), ('CertFindCertificateInStore', 53, None, 781648), ('CertOpenStore', 89, None, 781678), ('CryptStringToBinaryW', 223, None, 781718), ('CertFindExtension', 55, None, 782028), ('CryptDecodeObjectEx', 131, None, 781828), ('CertGetCertificateChain', 69, None, 781850), ('CertFreeCertificateChainEngine', 62, None, 781876), ('CertAddCertificateContextToStore', 4, None, 781910), ('CryptQueryObject', 197, None, 781946), ('CertFreeCertificateChain', 61, None, 781966), ('CertGetNameStringW', 75, None, 781994))), ('SspiCli.dll', 777748, 783044, 778328, 594176, 0, 0, 'd9f2f3a0f9090ccc6c39f46589990395436297855253b94d6c662936358a8a5c', (('InitSecurityInterfaceW', 30, None, 781742),)), ('api-ms-win-core-heap-l2-1-0.dll', 777768, 783056, 778968, 594816, 0, 0, '71ac571bbe509fa6eb549020bbe7a7453a5aece754d7d7aaf2c31e2496ce8842', (('LocalFree', 10, None, 782016),)), ('api-ms-win-crt-string-l1-1-0.dll', 777788, 783712, 780072, 595920, 0, 0, '719bbe55673154c94f1691f8b0ae5694e5e8317f80017479d016a07ed858439f', (('strspn', 147, None, 783310), ('strncmp', 142, None, 783330), ('strpbrk', 146, None, 783378), ('strcmp', 134, None, 784992), ('_stricmp', 42, None, 783498), ('wcscpy_s', 161, None, 783592), ('_strdup', 41, None, 783088), ('strcspn', 138, None, 783098), ('wcsncmp', 166, None, 783628), ('wcscmp', 158, None, 785002), ('wcsncpy_s', 168, None, 783638))), ('api-ms-win-crt-runtime-l1-1-0.dll', 777808, 783746, 779656, 595504, 0, 0, 'f5b74e9265a6691271a668f10f7b11505e2b8b094e135185aead801c4923db46', (('terminate', 103, None, 784972), ('_crt_atexit', 30, None, 784612), ('abort', 84, None, 784984), ('_c_exit', 21, None, 784862), ('_register_thread_local_exe_atexit_callback', 61, None, 784872), ('__p___wargv', 6, None, 784848), ('__p___argc', 4, None, 784834), ('_register_onexit_function', 60, None, 784584), ('_initialize_onexit_table', 52, None, 784556), ('_configure_wide_argv', 25, None, 784690), ('_exit', 35, None, 784812), ('_initialize_wide_environment', 53, None, 784714), ('_cexit', 22, None, 784626), ('exit', 85, None, 784804), ('strerror_s', 101, None, 783540), ('_initterm_e', 55, None, 784790), ('_seh_filter_exe', 64, None, 784636), ('_initterm', 54, None, 784778), ('_get_initial_wide_environment', 41, None, 784746), ('_errno', 33, None, 783108), ('_set_app_type', 66, None, 784654))), ('api-ms-win-crt-heap-l1-1-0.dll', 777828, 783780, 779560, 595408, 0, 0, 'f11318178b93326b65659d48e2ec5702cd8fa92314939dd55005d476b62860fe', (('realloc', 26, None, 783260), ('_set_new_mode', 22, None, 784940), ('free', 24, None, 783118), ('malloc', 25, None, 783126), ('calloc', 23, None, 783290))), ('api-ms-win-crt-stdio-l1-1-0.dll', 777848, 783812, 779832, 595680, 0, 0, '268b1b9a3c3c4f0b878627a9f7312c49a932ede9be6637efae1684977e4c3950', (('__acrt_iob_func', 0, None, 783144), ('fputc', 127, None, 783136), ('fflush', 119, None, 783162), ('_write', 107, None, 783702), ('_set_fmode', 84, None, 784820), ('_fseeki64', 47, None, 783616), ('_wsopen_s', 110, None, 783604), ('_wfreopen_s', 101, None, 783578), ('_wfsopen', 102, None, 783566), ('fgets', 122, None, 783490), ('feof', 117, None, 783482), ('__p__commode', 1, None, 784956), ('fseek', 135, None, 783454), ('getc', 139, None, 783424), ('puts', 147, None, 783408), ('fread', 131, None, 783370), ('_setmode', 87, None, 783358), ('ferror', 118, None, 783348), ('ftell', 137, None, 783340), ('fclose', 116, None, 783300), ('_close', 23, None, 783280), ('_isatty', 66, None, 783270), ('_get_osfhandle', 55, None, 783232), ('_lseeki64', 70, None, 783220), ('_read', 82, None, 783212), ('_fileno', 38, None, 783190), ('fputs', 128, None, 783182), ('fwrite', 138, None, 783172), ('__stdio_common_vsprintf', 13, None, 783664))), ('api-ms-win-crt-filesystem-l1-1-0.dll', 777868, 783844, 779512, 595360, 0, 0, 'a38e1a47a5b696b4ce1f4500ef04246c288d0a54108ebdde917a919a50ff92b7', (('_fstat64', 16, None, 783200), ('_fullpath', 18, None, 783690), ('_unlink', 35, None, 783462), ('_wstat64', 60, None, 783554), ('_mkdir', 25, None, 783320))), ('api-ms-win-crt-math-l1-1-0.dll', 777888, 783882, 779632, 595480, 0, 0, '61292de47beaa4591f31a59e9d37e9c8754c17ad73caf2da2c92d1a577acd588', (('_fdopen', 33, None, 783250), ('__setusermatherr', 9, None, 784670))), ('api-ms-win-crt-utility-l1-1-0.dll', 777908, 783914, 780208, 596056, 0, 0, 'a92868b8873d4ee9365465701d13be2c46a1b1576303fee3abd345be29f5c346', (('qsort', 25, None, 783416), ('bsearch', 16, None, 783388))), ('api-ms-win-crt-conio-l1-1-0.dll', 777928, 783948, 779480, 595328, 0, 0, '87ecb520a5523e4013c78c8b94b1ef9a349bce02662e35ab3aa6fc50bd656f6c', (('_getch', 14, None, 783398),)), ('api-ms-win-crt-environment-l1-1-0.dll', 777948, 783980, 779496, 595344, 0, 0, '54e0f11ec501093506e7744b2bd53adb78a0e3d62fb26172d76e5f46df430d2b', (('getenv', 16, None, 783432),)), ('api-ms-win-crt-locale-l1-1-0.dll', 777968, 784018, 779608, 595456, 0, 0, '654864989e5522a72597fb1296762f9269c0e234616644cef8bce45b7ffe403c', (('setlocale', 19, None, 783442), ('_configthreadlocale', 8, None, 784918))), ('api-ms-win-crt-time-l1-1-0.dll', 777988, 784052, 780168, 596016, 0, 0, '327c9968cbd1aec2b4984548468e081d1d96d7c4eec637244eacd9ac751ad87d', (('_time64', 48, None, 783472), ('_localtime64_s', 36, None, 783522), ('strftime', 70, None, 783510), ('_gmtime64_s', 32, None, 783650))), ('KERNEL32.dll', 778008, 784368, 778224, 594072, 0, 0, '56580637fc9c13d0d7d35b739ae95be3acb56133f6939d1d890baebac1683661', (('GetSystemTimeAsFileTime', 778, None, 784320), ('GetCurrentThreadId', 567, None, 784298), ('GetCurrentProcessId', 563, None, 784276), ('InitializeSListHead', 906, None, 784346), ('RtlCaptureContext', 1269, None, 784084), ('IsDebuggerPresent', 928, None, 784256), ('UnhandledExceptionFilter', 1510, None, 784150), ('RtlLookupFunctionEntry', 1277, None, 784104), ('IsProcessorFeaturePresent', 936, None, 784228), ('TerminateProcess', 1476, None, 784208), ('SetUnhandledExceptionFilter', 1444, None, 784178), ('RtlVirtualUnwind', 1284, None, 784130))), ('api-ms-win-core-rtlsupport-l1-1-0.dll', 778028, 784518, 779224, 595072, 0, 0, 'a519aa70fe0d50191a742ce5beb5491d3a012aeb2688e8553f35d9693dbfceea', (('RtlUnwindEx', 16, None, 784382),)))
EXPECTED_EXPORTS=(('accept', 1, 'private-WS2-implementation-or-recorded-unsupported-stub', None, True), ('bind', 2, 'private-WS2-implementation-or-recorded-unsupported-stub', None, True), ('closesocket', 3, 'private-WS2-implementation-or-recorded-unsupported-stub', None, True), ('connect', 4, 'private-WS2-implementation-or-recorded-unsupported-stub', None, True), ('getpeername', 5, 'private-WS2-implementation-or-recorded-unsupported-stub', None, True), ('getsockname', 6, 'private-WS2-implementation-or-recorded-unsupported-stub', None, True), ('getsockopt', 7, 'private-WS2-implementation-or-recorded-unsupported-stub', None, True), ('htonl', 8, 'private-WS2-implementation-or-recorded-unsupported-stub', None, True), ('htons', 9, 'private-WS2-implementation-or-recorded-unsupported-stub', None, True), ('ioctlsocket', 10, 'private-WS2-implementation-or-recorded-unsupported-stub', None, True), ('listen', 13, 'private-WS2-implementation-or-recorded-unsupported-stub', None, True), ('ntohs', 15, 'private-WS2-implementation-or-recorded-unsupported-stub', None, True), ('recv', 16, 'private-WS2-implementation-or-recorded-unsupported-stub', None, True), ('recvfrom', 17, 'private-WS2-implementation-or-recorded-unsupported-stub', None, True), ('select', 18, 'private-WS2-implementation-or-recorded-unsupported-stub', None, True), ('send', 19, 'private-WS2-implementation-or-recorded-unsupported-stub', None, True), ('sendto', 20, 'private-WS2-implementation-or-recorded-unsupported-stub', None, True), ('setsockopt', 21, 'private-WS2-implementation-or-recorded-unsupported-stub', None, True), ('shutdown', 22, 'private-WS2-implementation-or-recorded-unsupported-stub', None, True), ('socket', 23, 'private-WS2-implementation-or-recorded-unsupported-stub', None, True), ('WSACloseEvent', 45, 'private-WS2-implementation-or-recorded-unsupported-stub', None, True), ('WSACreateEvent', 50, 'private-WS2-implementation-or-recorded-unsupported-stub', None, True), ('gethostname', 57, 'private-WS2-implementation-or-recorded-unsupported-stub', None, True), ('WSAEnumNetworkEvents', 64, 'private-WS2-implementation-or-recorded-unsupported-stub', None, True), ('WSAEventSelect', 67, 'private-WS2-implementation-or-recorded-unsupported-stub', None, True), ('WSAIoctl', 78, 'private-WS2-implementation-or-recorded-unsupported-stub', None, True), ('WSAResetEvent', 95, 'private-WS2-implementation-or-recorded-unsupported-stub', None, True), ('WSAGetLastError', 111, 'private-WS2-implementation-or-recorded-unsupported-stub', None, True), ('WSASetLastError', 112, 'private-WS2-implementation-or-recorded-unsupported-stub', None, True), ('WSAStartup', 115, 'private-WS2-implementation-or-recorded-unsupported-stub', None, True), ('WSACleanup', 116, 'private-WS2-implementation-or-recorded-unsupported-stub', None, True), ('WSAWaitForMultipleEvents', 124, 'private-WS2-implementation-or-recorded-unsupported-stub', None, True), ('__WSAFDIsSet', 151, 'private-WS2-implementation-or-recorded-unsupported-stub', None, True), ('freeaddrinfo', 191, 'private-WS2-implementation-or-recorded-unsupported-stub', None, True), ('getaddrinfo', 192, 'private-WS2-implementation-or-recorded-unsupported-stub', None, True), ('GetProcAddress', 200, 'private-gateway', None, False), ('GetModuleHandleW', 201, 'private-gateway', None, False), ('LoadLibraryExW', 202, 'private-gateway', None, False), ('FreeLibrary', 203, 'private-gateway', None, False), ('GetModuleFileNameA', 204, 'system-forwarder', 'KERNEL32.GetModuleFileNameA', False))
_DESCRIPTOR_SHA256='ea50c455b73357e9d700078f58d2d663dabab0d4500259d973966dbfb579732b'

class RejectCode(str,Enum):
    TYPE='type';LENGTH='length';DOS='dos';COFF='coff';OPTIONAL='optional'
    SECTION='section';DIRECTORY='directory';RVA='rva';STRING='string'
    DESCRIPTOR='descriptor';LOOKUP='lookup';IAT='iat';HASH='hash'
    BASE='base';PATH='path';READBACK='readback'

class BuilderError(ValueError):
    def __init__(self,code):
        self.code=code
        super().__init__('fixed_curl_import_'+code.value)

def _need(ok,code):
    if not ok:raise BuilderError(code)

def _uint(value,maximum=MAX_U64):
    return type(value) is int and 0<=value<=maximum

def _sha(raw):return hashlib.sha256(raw).hexdigest()

def _part(raw,at,size,code=RejectCode.RVA):
    _need(_uint(at) and _uint(size) and at<=len(raw) and size<=len(raw)-at,code)
    return raw[at:at+size]

def _unpack(raw,at,fmt,code=RejectCode.RVA):
    return struct.unpack(fmt,_part(raw,at,struct.calcsize(fmt),code))

def _rva_offset(rva,size):
    _need(_uint(rva,0xffffffff) and _uint(size,0xffffffff),RejectCode.RVA)
    if rva<SIZE_HEADERS:
        _need(size<=SIZE_HEADERS-rva,RejectCode.RVA)
        return rva
    found=[]
    for name,virtual_size,section_rva,raw_size,raw_offset,flags in _EXPECTED_SECTIONS:
        if section_rva<=rva and rva-section_rva<=raw_size and size<=raw_size-(rva-section_rva):
            found.append(raw_offset+rva-section_rva)
    _need(len(found)==1,RejectCode.RVA)
    return found[0]

def _rva_part(raw,rva,size):return _part(raw,_rva_offset(rva,size),size)

def _cstring(raw,rva,expected,limit=512):
    encoded=expected.encode('ascii')
    _need(0<len(encoded)<limit and b'\0' not in encoded,RejectCode.STRING)
    _need(_rva_part(raw,rva,len(encoded)+1)==encoded+b'\0',RejectCode.STRING)

@dataclass(frozen=True)
class OriginalTables:
    descriptors:bytes
    lookup_tables:tuple
    IAT_tables:tuple

@dataclass(frozen=True)
class VerifiedPE:
    image_sha256:str
    image_bytes:int
    header:bytes
    original_tables:OriginalTables
    descriptor_count:int
    import_count:int
    preferred_image_base:int

@dataclass(frozen=True)
class PatchMetadata:
    schema_version:int
    actual_ready:bool
    offline_model:bool
    actual_process_observed:bool
    remote_mutation_performed:bool
    owned_private_path_verified:bool
    loader_accepted:bool
    image_sha256:str
    actual_base:int
    arena_address:int
    arena_rva:int
    arena_bytes:int
    arena_used:int
    private_path_bytes:int
    private_path_sha256:str
    descriptor_count:int
    replaced_indices:tuple
    preserved_indices:tuple
    header_offset:int
    header_patch_bytes:int
    source_transcript_sha256:str
    design_contract_sha256:str
    export_manifest_sha256:str

@dataclass(frozen=True)
class ImportPatch:
    arena:bytes
    header_patch:bytes
    expected_header:bytes
    original_tables:OriginalTables
    metadata:PatchMetadata

@dataclass(frozen=True)
class ReadbackModel:
    schema_version:int
    readback_bytes_match:bool
    actual_process_observed:bool
    remote_mutation_performed:bool
    loader_accepted:bool
    source_image_sha256:str
    header_sha256:str
    arena_sha256:str
    original_table_count:int

def verify_fixed_pe(image):
    """Verify the full pinned image, including every old ILT and IAT entry."""
    _need(type(image) is bytes,RejectCode.TYPE)
    _need(len(image)==CURL_BYTES,RejectCode.LENGTH)
    _need(image[:2]==b'MZ' and _unpack(image,60,'<I')[0]==256,RejectCode.DOS)
    _need(image[256:260]==b'PE\0\0',RejectCode.DOS)
    machine,count,timestamp,symbols,symbol_count,optional_bytes,flags=_unpack(image,260,'<HHIIIHH')
    _need(machine==0x8664 and count==len(_EXPECTED_SECTIONS) and optional_bytes==240,RejectCode.COFF)
    o=280
    _need(_unpack(image,o,'<H')[0]==0x20b and _unpack(image,o+24,'<Q')[0]==0x140000000
        and _unpack(image,o+56,'<II')==(SIZE_IMAGE,SIZE_HEADERS)
        and _unpack(image,o+108,'<I')[0]==16,RejectCode.OPTIONAL)
    for index,expected in enumerate(_EXPECTED_SECTIONS):
        at=o+240+index*40
        name,vs,va,rs,rp,flags=expected
        _need(_part(image,at,8)==name.encode('ascii').ljust(8,b'\0')
            and _unpack(image,at+8,'<IIII')==(vs,va,rs,rp)
            and _unpack(image,at+36,'<I')[0]==flags,RejectCode.SECTION)
    for index,expected in ((1,(IMPORT_RVA,IMPORT_BYTES)),(11,(0,0)),(12,(IAT_RVA,IAT_BYTES)),(13,(0,0))):
        _need(_unpack(image,o+112+index*8,'<II')==expected,RejectCode.DIRECTORY)
    descriptors=_rva_part(image,IMPORT_RVA,IMPORT_BYTES)
    lookup=[];iat=[];total=0
    for index,entry in enumerate(_EXPECTED_IMPORTS):
        name,drva,nrva,oft,ft,stamp,chain,digest,imports=entry
        _need(drva==IMPORT_RVA+index*20 and _unpack(descriptors,index*20,'<IIIII')==(oft,stamp,chain,nrva,ft),RejectCode.DESCRIPTOR)
        _cstring(image,nrva,name)
        size=(len(imports)+1)*8
        lt=_rva_part(image,oft,size);it=_rva_part(image,ft,size)
        for slot,(symbol,hint,ordinal,expected_value) in enumerate(imports):
            value=_unpack(lt,slot*8,'<Q')[0]
            _need(value==expected_value,RejectCode.LOOKUP)
            _need(_unpack(it,slot*8,'<Q')[0]==expected_value,RejectCode.IAT)
            if ordinal is not None:
                _need(value==((1<<63)|ordinal) and symbol is None and hint is None,RejectCode.LOOKUP)
            else:
                _need(0<value<0x8000000000000000 and _unpack(image,_rva_offset(value,2),'<H')[0]==hint,RejectCode.LOOKUP)
                _cstring(image,value+2,symbol)
        _need(_unpack(lt,len(imports)*8,'<Q')[0]==0,RejectCode.LOOKUP)
        _need(_unpack(it,len(imports)*8,'<Q')[0]==0,RejectCode.IAT)
        _need(_sha(lt)==digest,RejectCode.LOOKUP)
        lookup.append(lt);iat.append(it);total+=len(imports)
    _need(descriptors[-20:]==bytes(20) and _sha(descriptors)==_DESCRIPTOR_SHA256,RejectCode.DESCRIPTOR)
    _need(sum(map(len,iat))==IAT_BYTES,RejectCode.IAT)
    _need(_sha(image)==CURL_SHA256,RejectCode.HASH)
    return VerifiedPE(CURL_SHA256,CURL_BYTES,image[:SIZE_HEADERS],OriginalTables(descriptors,tuple(lookup),tuple(iat)),42,total,0x140000000)

def _base(actual_base):
    _need(type(actual_base) is int and 0<actual_base<=MAX_U64 and actual_base%65536==0,RejectCode.BASE)
    _need(ARENA_RVA==(SIZE_IMAGE+65535)//65536*65536 and ARENA_RVA>=SIZE_IMAGE,RejectCode.BASE)
    _need(actual_base<=MAX_U64-ARENA_RVA-ARENA_BYTES,RejectCode.BASE)
    return actual_base+ARENA_RVA

def _path(private_path):
    _need(type(private_path) is str and 1<=len(private_path)<=1023,RejectCode.PATH)
    try:raw=private_path.encode('ascii')
    except UnicodeEncodeError:raise BuilderError(RejectCode.PATH) from None
    _need(1<=len(raw)<=1023 and re.fullmatch(r'[A-Za-z]:\\.+',private_path) is not None,RejectCode.PATH)
    parts=private_path[3:].split('\\')
    _need(parts[-1]==PRIVATE_BASENAME and all(part not in ('','.','..') and not part.endswith(('.', ' '))
        and re.search(r'[<>:"/|?*\x00-\x1f\x7f]',part) is None for part in parts),RejectCode.PATH)
    reserved={'CON','PRN','AUX','NUL',*('COM'+str(i) for i in range(1,10)),*('LPT'+str(i) for i in range(1,10))}
    _need(all(part.split('.',1)[0].upper() not in reserved for part in parts),RejectCode.PATH)
    return raw

def build_import_patch(image,actual_base,private_path):
    """Return immutable desired bytes. No allocation, process query or file IO."""
    pe=verify_fixed_pe(image);address=_base(actual_base);path=_path(private_path)
    used=(NAME_OFFSET+len(path)+1+7)//8*8
    _need(used<=1888 and used<=ARENA_BYTES,RejectCode.LENGTH)
    arena=bytearray(ARENA_BYTES);arena[:IMPORT_BYTES]=pe.original_tables.descriptors
    for index in (0,10):struct.pack_into('<I',arena,index*20+12,ARENA_RVA+NAME_OFFSET)
    arena[NAME_OFFSET:NAME_OFFSET+len(path)]=path
    patch=struct.pack('<I',ARENA_RVA);header=bytearray(pe.header);header[IMPORT_HEADER_OFFSET:IMPORT_HEADER_OFFSET+4]=patch
    metadata=PatchMetadata(1,False,True,False,False,False,False,CURL_SHA256,actual_base,address,ARENA_RVA,ARENA_BYTES,used,len(path),_sha(path),42,
        (0,10),tuple(i for i in range(42) if i not in (0,10)),IMPORT_HEADER_OFFSET,4,SOURCE_TRANSCRIPT_SHA256,DESIGN_CONTRACT_SHA256,EXPORT_MANIFEST_SHA256)
    return ImportPatch(bytes(arena),patch,bytes(header),pe.original_tables,metadata)

def verify_readback_model(image,actual_base,private_path,*,header,arena,old_descriptors,old_lookup_tables,old_IAT_tables):
    """Compare supplied byte samples only; never claim they came from a process."""
    _need(type(header) is bytes and type(arena) is bytes and type(old_descriptors) is bytes
        and type(old_lookup_tables) is tuple and type(old_IAT_tables) is tuple
        and len(header)==SIZE_HEADERS and len(arena)==ARENA_BYTES and len(old_descriptors)==IMPORT_BYTES
        and len(old_lookup_tables)==len(old_IAT_tables)==42
        and all(type(x) is bytes for x in (*old_lookup_tables,*old_IAT_tables)),RejectCode.READBACK)
    expected=build_import_patch(image,actual_base,private_path)
    _need(header==expected.expected_header and arena==expected.arena and old_descriptors==expected.original_tables.descriptors
        and old_lookup_tables==expected.original_tables.lookup_tables and old_IAT_tables==expected.original_tables.IAT_tables,RejectCode.READBACK)
    return ReadbackModel(1,True,False,False,False,CURL_SHA256,_sha(header),_sha(arena),42)
