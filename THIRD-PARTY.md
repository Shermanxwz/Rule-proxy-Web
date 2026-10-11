# Third-party components

Source checkouts do not commit runtime binaries or private configurations. The Windows release package, and a source checkout after its one-time setup, may include the following components:

| Component | Version | License | Corresponding source |
|---|---|---|---|
| Mihomo | v1.19.32 | GPL-3.0 | [Source and license](https://github.com/MetaCubeX/mihomo/tree/v1.19.32) · [Source archive](https://github.com/MetaCubeX/mihomo/archive/refs/tags/v1.19.32.tar.gz) |
| Microsoft MXC | 1.0.0 | MIT | [Source and license](https://github.com/microsoft/mxc/tree/v1.0.0) |
| Python, Windows embeddable package (Windows release package only) | 3.14.8 | PSF License Agreement, with the notices for its bundled libraries | [Source](https://www.python.org/downloads/release/python-3148/); license in `python/LICENSE.txt` |
| PyYAML | 6.0.3 in the Windows release package; on Linux, the system package or the version pip installs into `vendor/` | MIT | [Source and license](https://github.com/yaml/pyyaml/tree/6.0.3); license in the `vendor/pyyaml-*.dist-info` folder |
| Ubuntu `bwrap-userns-restrict` AppArmor profiles | 4.0.1 (Ubuntu 24.04) | GPL-2+ | Adapted from the Ubuntu `apparmor-profiles` source package; path-scoped files in `apparmor/`; license included. |

Mihomo and the MXC executors run as separate programs. The embedded Python runs the panel unmodified, apart from its `python314._pth` path file. License files are included alongside the corresponding bundled files. Node credentials and the user's reference YAML are excluded from all public source and CI artifacts.
