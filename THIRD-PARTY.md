# Third-party components

Source checkouts do not commit runtime binaries or private configurations. Prepared local bundles may include the following components:

| Component | Version | License | Corresponding source |
|---|---|---|---|
| Mihomo | v1.19.32 | GPL-3.0 | [Source and license](https://github.com/MetaCubeX/mihomo/tree/v1.19.32) · [Source archive](https://github.com/MetaCubeX/mihomo/archive/refs/tags/v1.19.32.tar.gz) |
| Microsoft MXC | 1.0.0 | MIT | [Source and license](https://github.com/microsoft/mxc/tree/v1.0.0) |
| PyYAML | Version recorded in the bundle | MIT | [Source and license](https://github.com/yaml/pyyaml) |
| Ubuntu `bwrap-userns-restrict` AppArmor profiles | 4.0.1 (Ubuntu 24.04) | GPL-2+ | Adapted from the Ubuntu `apparmor-profiles` source package; path-scoped files in `apparmor/`; license included. |

Mihomo runs as a separate program. MXC executors run as separate programs. License files are included alongside the corresponding bundled files. Node credentials and the user's reference YAML are excluded from all public source and CI artifacts.
