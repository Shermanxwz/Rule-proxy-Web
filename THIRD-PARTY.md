# Third-party components

The Windows 0.3.0 personal offline package uses the following fixed components. Source checkouts do not commit these runtime binaries or user configuration. Asset URLs and SHA-256 values are recorded in [windows_proxy_pins.py](ruleproxy/windows_proxy_pins.py); the built package records each shipped file in `package-manifest.json`.

| Component | Version | License and source |
|---|---|---|
| ProxiFyre | 2.6.4 | **AGPL-3.0**. [Source](https://github.com/wiresock/proxifyre/tree/v2.6.4), [license](https://github.com/wiresock/proxifyre/blob/v2.6.4/LICENSE), [source archive](https://github.com/wiresock/proxifyre/archive/refs/tags/v2.6.4.tar.gz). The unmodified official MSI is bundled, with the license in `licenses/PROXIFYRE-LICENSE`. |
| Windows Packet Filter / WinpkFilter signed driver installer | 3.6.2.1 x64 | Separate NT KERNEL driver license; **not covered by ProxiFyre's AGPL or the user-mode library's MIT license**. Official [personal/academic terms](https://www.ntkernel.com/windows-packet-filter/licensing/) provide free non-commercial personal use without an expiry. Commercial redistribution rights are separate. [Official release assets](https://github.com/wiresock/ndisapi/releases/tag/v3.6.2). |
| NDISAPI user-mode library source | v3.6.2 | MIT. [Source and license](https://github.com/wiresock/ndisapi/tree/v3.6.2). Notice shipped in `licenses/NDISAPI-LICENSE`. This license does not grant rights to the separately licensed kernel driver. |
| Mihomo | v1.19.32 | GPL-3.0. [Source and license](https://github.com/MetaCubeX/mihomo/tree/v1.19.32), [source archive](https://github.com/MetaCubeX/mihomo/archive/refs/tags/v1.19.32.tar.gz). License shipped as `bin/windows-amd64/MIHOMO-LICENSE`. |
| Microsoft Visual C++ x64 Redistributable | Pinned official asset in `windows_proxy_pins.py` | Microsoft software license, supplied unchanged as `installers/VC_redist.x64.exe`. [Official documentation and redistribution conditions](https://learn.microsoft.com/en-us/cpp/windows/redistributing-visual-cpp-files). The Microsoft license is independent of this project's license. |
| Python Windows embeddable distribution | 3.14.8 | PSF License Agreement and notices for bundled libraries. [Official release](https://www.python.org/downloads/release/python-3148/); license in `python/LICENSE.txt`. The controlled `python314._pth` is adjusted to load the private product and vendor directories. |
| PyYAML | 6.0.3 on Windows | MIT. [Source and license](https://github.com/yaml/pyyaml/tree/6.0.3); wheel notices in `vendor/pyyaml-*.dist-info/`. Linux uses its system package or the version installed into `vendor/` by setup. |
| Ubuntu `bwrap-userns-restrict` AppArmor profiles | 4.0.1 (Ubuntu 24.04) | GPL-2.0-or-later. Adapted from the Ubuntu `apparmor-profiles` source package; path-specific files and notices in [apparmor/](https://github.com/Shermanxwz/Rule-proxy-Web/tree/main/apparmor). |

ProxiFyre and Mihomo run as separate executables. The official ProxiFyre MSI is pinned by hash; it is not Authenticode-signed. Setup additionally checks signatures on the Microsoft VC installer, NDIS installer and installed NDIS driver. Hash pinning and signature validation serve different purposes.

This deployment is for the owner's personal use. It does not require buying a commercial Windows Packet Filter license. The personal package is not automatically published as a public binary release; any later redistribution must satisfy the independent driver, Microsoft and open-source obligations, including corresponding-source requirements where applicable. Public source availability alone does not settle every bundled component's distribution terms.

The current Windows product does not ship MXC binaries. Older MXC code, tests and reports remain only for historical reproduction; their fixed versions and MIT notices are described in the [0.2.2 historical documentation](https://github.com/Shermanxwz/Rule-proxy-Web/blob/main/verification/windows-2026-10-15/mxc-0.2.2-readme.md).

No user YAML, subscription, node password or browser profile is included in the product payload. Users import their own configuration through the local Web panel.
