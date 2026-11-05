"""One bounded retry of a proven failed initial Hub navigation.

The injected peers object must hold and revalidate app/job/listener identities.
check() returns True when owned/current and broker ready, None while waiting,
and False when ownership or the protection lifecycle no longer permits recovery.
No background scheduling or native permission changes are performed here.
"""
from dataclasses import dataclass
import time
from urllib.parse import urlsplit

from .windows_antigravity_navigation import NavigationClient, NavigationError


@dataclass(frozen=True)
class ListenerSnapshot:
    main_ports: tuple
    helper_ports: tuple


def _url(value):
    try:
        if not isinstance(value, str) or len(value) > 8192 or any(ord(c) < 32 for c in value):
            return None
        u = urlsplit(value)
        # Force validation of the port, including out-of-range values.
        port = u.port
        return u if port is None or 1 <= port <= 65535 else None
    except ValueError:
        return None


def _hub(value, ports):
    u = _url(value)
    return bool(u and u.scheme == 'https' and u.hostname == '127.0.0.1'
                and u.port in ports and u.username is None and u.password is None)


def _initial_failure(frame, ports):
    u = _url(frame.get('unreachableUrl'))
    return bool(_hub(frame.get('unreachableUrl'), ports) and u.path == '/'
                and not u.query and not u.fragment
                and frame.get('url') == 'chrome-error://chromewebdata/')


def recover_once(peers, check, deadline, *, client_factory=NavigationClient,
                 clock=time.monotonic, sleep=time.sleep):
    """Return a small status only; never return page URLs or protocol payloads.

    Caller starts this once immediately after creating its owned process. It must
    pass an absolute deadline, so delayed scheduling never extends the window.
    A failed/ambiguous reload is never retried within this invocation.
    """
    attempted = False
    result = lambda state: {'state': state, 'reload_attempted': attempted}
    try:
        if type(deadline) not in (int, float):
            return result('unavailable')
        # Validate the deadline using the same finite-number contract as transport.
        NavigationClient(1025, deadline, clock=clock)
        while clock() < deadline:
            readiness = check()
            if readiness is False:
                return result('cancelled')
            if readiness is not True:
                sleep(min(.2, max(0., deadline - clock())))
                continue
            snapshot = peers.snapshot()
            if snapshot is None or not snapshot.main_ports or not snapshot.helper_ports:
                sleep(min(.2, max(0., deadline - clock())))
                continue
            if not isinstance(snapshot, ListenerSnapshot) or len(snapshot.main_ports) > 8 or len(snapshot.helper_ports) > 8:
                return result('unavailable')
            if any(type(p) is not int or not 1025 <= p <= 65535 for p in snapshot.main_ports + snapshot.helper_ports):
                return result('unavailable')
            for port in snapshot.main_ports:
                if clock() >= deadline or check() is False or not peers.valid(snapshot):
                    return result('cancelled')
                client = client_factory(port, deadline, clock=clock)
                try:
                    targets = client.targets()
                except (NavigationError, OSError):
                    # Non-CDP app listeners are not permission to probe other hosts.
                    continue
                candidates = [t for t in targets if t.get('type') == 'page' and
                              (_hub(t.get('url'), snapshot.helper_ports) or
                               t.get('url') == 'chrome-error://chromewebdata/')]
                if len(candidates) > 1:
                    return result('ambiguous')
                if not candidates:
                    continue
                with client.connect(candidates[0].get('webSocketDebuggerUrl')) as session:
                    frame = session.frame()
                    if not peers.valid(snapshot) or check() is False:
                        return result('cancelled')
                    if not frame.get('unreachableUrl') and _hub(frame.get('url'), snapshot.helper_ports):
                        return result('not_needed')
                    if not _initial_failure(frame, snapshot.helper_ports):
                        return result('not_initial_failure')
                    if check() is not True or not peers.valid(snapshot) or clock() >= deadline:
                        return result('cancelled')
                    confirm = session.frame()
                    if confirm != frame:
                        return result('navigation_changed')
                    # Recheck after reading the confirmation; a stop/replacement
                    # never inherits an earlier permission to operate on a page.
                    if check() is not True or not peers.valid(snapshot) or clock() >= deadline:
                        return result('cancelled')
                    attempted = True
                    session.reload()
                    target_port = _url(frame['unreachableUrl']).port
                    while clock() < deadline:
                        if check() is not True or not peers.valid(snapshot):
                            return result('cancelled')
                        current = session.frame()
                        # A response may race with stop, core replacement, or the
                        # absolute deadline. Never credit a stale success read.
                        if clock() >= deadline:
                            return result('reload_unverified')
                        if check() is not True or not peers.valid(snapshot):
                            return result('cancelled')
                        if (not current.get('unreachableUrl') and current.get('id') == frame.get('id')
                                and current.get('loaderId') != frame.get('loaderId')
                                and _hub(current.get('url'), (target_port,))):
                            return result('recovered')
                        sleep(min(.2, max(0., deadline - clock())))
                    return result('reload_unverified')
            sleep(min(.2, max(0., deadline - clock())))
        return result('expired')
    except Exception:
        # Protocol, native, and readiness failures are not grounds for loosening
        # protection or falling back to keyboard input/general debugging.
        return result('reload_unverified' if attempted else 'unavailable')
