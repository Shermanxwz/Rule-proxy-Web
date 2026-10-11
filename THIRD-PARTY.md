# Third-party components

Source checkouts do not commit runtime binaries or private configurations. The Windows release package, and a source checkout after its one-time setup, may include the following components:

| Component | Version | License | Corresponding source |
|---|---|---|---|
| Mihomo | v1.19.32 | GPL-3.0 | [Source and license](https://github.com/MetaCubeX/mihomo/tree/v1.19.32) · [Source archive](https://github.com/MetaCubeX/mihomo/archive/refs/tags/v1.19.32.tar.gz) |
| Microsoft MXC (`wxc-exec.exe`, `winhttp-proxy-shim.exe`) | 1.0.0+c6f301d.ruleproxy.1 | MIT | [Pinned source and license](https://github.com/microsoft/mxc/tree/c6f301d53a1430c4c921a05c57af838f7392348f) |
| Python, Windows embeddable package (Windows release package only) | 3.14.8 | PSF License Agreement, with the notices for its bundled libraries | [Source](https://www.python.org/downloads/release/python-3148/); license in `python/LICENSE.txt` |
| PyYAML | 6.0.3 in the Windows release package; on Linux, the system package or the version pip installs into `vendor/` | MIT | [Source and license](https://github.com/yaml/pyyaml/tree/6.0.3); license in the `vendor/pyyaml-*.dist-info` folder |
| Ubuntu `bwrap-userns-restrict` AppArmor profiles | 4.0.1 (Ubuntu 24.04) | GPL-2+ | Adapted from the Ubuntu `apparmor-profiles` source package; path-scoped files in `apparmor/`; license included. |

Mihomo and the MXC executors run as separate programs. The embedded Python runs the panel unmodified, apart from its `python314._pth` path file. License files are included alongside the corresponding bundled files. Node credentials and the user's reference YAML are excluded from all public source and CI artifacts.

The MXC binaries are built by this project from the pinned Microsoft source revision, with Rust 1.93, the upstream Cargo.lock, static CRT and upstream hardening flags, and no optional backends. They include the PSEC 1.0 identity-less proxy compatibility change which is absent from the official npm 1.0.0 archive. This is a project-qualified build, not a new Microsoft official release. The exact archive and executable SHA-256 values are pinned in install_runtime.py; bin/windows-amd64/MXC-SOURCE.txt records the source. Rebuilding the source is supported, but bit-for-bit reproducibility is not claimed.
