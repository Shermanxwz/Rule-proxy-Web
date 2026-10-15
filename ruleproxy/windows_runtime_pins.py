"""Fixed Windows runtime identity shared by installation and acceptance checks.

This candidate pins a prebuilt MXC executor byte-for-byte. It does not claim
that native product acceptance has passed.
"""

MIHOMO_VERSION = "v1.19.32"
MXC_VERSION = "1.0.0"
MXC_VARIANTS = ("stock", "g-patched")
DEFAULT_MXC_VARIANT = "g-patched"

MXC_G_BUNDLE_URL = (
    "https://github.com/Shermanxwz/Rule-proxy-Web/releases/download/"
    "mxc-g-runtime-2026-10-15/mxc-g-runtime-bundle.zip"
)
MXC_G_BUNDLE_SHA256 = "89a9390d9db7f65c82c52ac8c545bff88d6e7577998bea9e5ab93d86f2be90a0"
MXC_G_EXECUTOR_SHA256 = "cd32e225fb858161b66bc23e9d2415843de348edf2cfdfb05cee0e7535dca1a7"
MXC_G_LICENSE_SHA256 = "d9a1b1e30d633d5732ea18e3cba9538d293ebc53e1a9e4e96ab739e0c5c4f1cb"
MXC_G_BUILD_MANIFEST = {
    "schema_version": 1,
    "status": "built",
    "upstream_commit": "7bf210247986cb73b1b314df60c2f1109c479c0b",
    "executor_sha256": MXC_G_EXECUTOR_SHA256,
    "patch": {
        "name": "exact_internal_tcp_without_automatic_internet_client",
        "capabilities_null": True,
        "network_table_unchanged": True,
        "exact_internal_tcp_only": True,
        "caller_capabilities_must_be_empty": True,
    },
    "original_file_sha256": "a03b8889d8d92fe854f46d56c702360403c6889e79b48b42f8b2535b66189491",
    "patch_sha256": "3b0c5e616e3575d5be0ec3f34abd9ba6dd8f213eb097e836ab80c7a60dda112a",
    "patched_file_sha256": "3809ab6269efaaf89011364c3f3355465ad11c7f5545f0a4f301181743bf926e",
    "toolchain": "1.93",
    "target": "x86_64-pc-windows-msvc",
}


def expected_mxc_record(variant: str = DEFAULT_MXC_VARIANT) -> str | dict:
    if variant == "stock":
        return MXC_VERSION
    if variant != "g-patched":
        raise ValueError("Unknown Windows MXC runtime variant")
    return {
        "version": MXC_VERSION,
        "executor_variant": variant,
        "bundle_sha256": MXC_G_BUNDLE_SHA256,
        "build": MXC_G_BUILD_MANIFEST,
        "license_sha256": MXC_G_LICENSE_SHA256,
    }


def expected_windows_record() -> dict:
    return {"mihomo": MIHOMO_VERSION, "mxc": expected_mxc_record()}
