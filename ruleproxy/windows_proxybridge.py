"""Experimental Windows transparent-proxy backend safety contract.

This is a *control-plane state machine*, NOT a WFP implementation. No production
WFP provider or WinDivert redirector is supplied here. In particular, this
module must not be exposed as a supported launcher until a native WFP provider
and real Windows packet-level tests exist.

The redirection engine is never a security boundary. The *independent*, durable
WFP fence must remain active if this module, the proxy, or the application
crashes. This includes unknown processes, child processes, IPv4/IPv6 and UDP.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import PureWindowsPath
from typing import Callable, Protocol


class ProtectionError(RuntimeError):
    """A launch or teardown failed; inspect session before attempting recovery."""

    def __init__(self, message: str, session: "StrictWindowsSession | None" = None):
        super().__init__(message)
        self.session = session


@dataclass(frozen=True)
class FenceSpec:
    executable: str
    proxy_host: str
    proxy_port: int

    def __post_init__(self) -> None:
        path = PureWindowsPath(self.executable)
        if (
            not isinstance(self.executable, str)
            or not self.executable
            or "\x00" in self.executable
            or not path.is_absolute()
            or not path.drive
            or not path.name.lower().endswith(".exe")
        ):
            raise ValueError("the protected application must be an absolute Windows .exe path")
        if self.proxy_host != "127.0.0.1":
            raise ValueError("only a dedicated IPv4 loopback proxy endpoint is supported")
        if isinstance(self.proxy_port, bool) or not isinstance(self.proxy_port, int) or not 1025 <= self.proxy_port <= 65535:
            raise ValueError("invalid dedicated proxy port")


@dataclass(frozen=True)
class FenceReceipt:
    """Unforgeable proof is the native provider's responsibility, NOT this struct.

    All flags are necessary but insufficient for certification. A real WFP
    provider must independently attest these properties from installed filters.
    """
    executable: str
    proxy_host: str
    proxy_port: int
    kernel_wfp: bool
    durable: bool
    ipv4: bool
    ipv6: bool
    tcp: bool
    udp: bool
    descendants: bool
    default_deny: bool
    no_direct_fallback: bool


def validate_receipt(spec: FenceSpec, receipt: FenceReceipt) -> None:
    if not isinstance(receipt, FenceReceipt):
        raise ProtectionError("native WFP guard returned no verifiable receipt")
    if (
        PureWindowsPath(receipt.executable) != PureWindowsPath(spec.executable)
        or receipt.proxy_host != spec.proxy_host
        or receipt.proxy_port != spec.proxy_port
    ):
        raise ProtectionError("native WFP guard does not bind the exact executable and proxy endpoint")
    requirements = (
        "kernel_wfp", "durable", "ipv4", "ipv6", "tcp", "udp",
        "descendants", "default_deny", "no_direct_fallback",
    )
    if not all(getattr(receipt, field) is True for field in requirements):
        raise ProtectionError("WFP guard does not provide the full fail-closed contract")


class WfpFence(Protocol):
    def install(self, spec: FenceSpec) -> FenceReceipt: ...
    def verify(self, receipt: FenceReceipt) -> bool: ...
    def release(self, receipt: FenceReceipt) -> None: ...


class ProxyRedirector(Protocol):
    def start(self, spec: FenceSpec) -> None: ...
    def ready(self, spec: FenceSpec) -> bool: ...
    def stop(self) -> None: ...


class OwnedProcess(Protocol):
    def poll(self) -> int | None: ...
    def terminate_tree_and_verify(self) -> bool: ...


class StrictWindowsSession:
    """All side effects are injectable to test ordering and failure paths.

    Once installed, an uncertain fence is NEVER automatically removed.
    A native provider must persist filters independently of this process;
    the process terminator must verify descendants have exited before release.
    """

    def __init__(
        self,
        spec: FenceSpec,
        fence: WfpFence,
        redirector: ProxyRedirector,
        spawn: Callable[[], OwnedProcess],
    ):
        self.spec = spec
        self.fence = fence
        self.redirector = redirector
        self.spawn = spawn
        self.receipt: FenceReceipt | None = None
        self.process: OwnedProcess | None = None
        self.redirector_started = False
        self.started = False
        self.closed = False

    def _verify(self) -> None:
        if self.receipt is None:
            raise ProtectionError("WFP protection has not been installed", self)
        validate_receipt(self.spec, self.receipt)
        if self.fence.verify(self.receipt) is not True:
            raise ProtectionError("WFP protection verification failed", self)

    def start(self) -> OwnedProcess:
        if self.closed or self.started or self.receipt is not None:
            raise ProtectionError("session cannot be started twice or after partial failure", self)
        try:
            self.receipt = self.fence.install(self.spec)
            self._verify()  # WFP first; no redirector, app, or socket before this
            self.redirector_started = True  # stop on partial start failure
            self.redirector.start(self.spec)
            if self.redirector.ready(self.spec) is not True:
                raise ProtectionError("transparent redirection is not ready", self)
            self._verify()
            process = self.spawn()
            if process is None or not hasattr(process, "terminate_tree_and_verify") or not hasattr(process, "poll"):
                raise ProtectionError("process identity/teardown not verifiable", self)
            self.process = process
            self._verify()
            self.started = True
            return process
        except Exception as exc:
            # Deliberately never release an installed fence on ambiguous failure.
            # The app may have been created before a post-spawn verification fault.
            # Redirector failure is harmless only because the WFP fence persists.
            if self.redirector_started:
                try:
                    self.redirector.stop()
                except Exception:
                    pass
            raise ProtectionError(f"protected launch rejected: {exc}", self) from exc

    def stop(self) -> None:
        if self.closed:
            return
        if self.receipt is None:
            # No guard installed and therefore start() never reached the spawner.
            self.closed = True
            return
        try:
            self._verify()
            if self.process is not None and self.process.poll() is None:
                if self.process.terminate_tree_and_verify() is not True:
                    raise ProtectionError("could not prove all owned processes exited", self)
            if self.process is not None and self.process.poll() is None:
                raise ProtectionError("process is still alive; WFP fence retained", self)
            if self.redirector_started:
                self.redirector.stop()
                self.redirector_started = False
            # Native implementations must refuse release while owned descendants exist.
            self._verify()
            self.fence.release(self.receipt)
            self.receipt = None
            self.closed = True
            self.started = False
        except Exception as exc:
            raise ProtectionError(f"could not safely stop protected session: {exc}", self) from exc


def production_probe() -> dict:
    """Fail closed: a native WFP provider is not yet implemented or verified."""
    return {
        "supported": False,
        "backend": "ProxyBridge + independent WFP (experimental)",
        "detail": (
            "Windows native WFP fence and WinDivert cooperation are not implemented "
            "or proven by real-host isolation tests. Production launch is disabled."
        ),
        "limitations": [
            "No native WFP app/descendant policy or durable crash-time barrier",
            "No verified WFP-vs-WinDivert redirect interoperability",
            "No real Windows Chrome/Edge/Firefox network and profile acceptance",
        ],
    }
