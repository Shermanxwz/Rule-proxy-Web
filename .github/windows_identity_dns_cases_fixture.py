"""Three declared DNS cases on one owned exclusive loopback UDP53 socket.

No forwarder, system resolver, arbitrary endpoint, query retry or deadline
renewal. Per-case observations are sticky even when send or cleanup fails.
"""
import importlib.util
import math
from pathlib import Path
import socket
import threading
import time

_spec=importlib.util.spec_from_file_location('dns_cases_original_parser',Path(__file__).with_name('windows_dns_fixture.py'))
parser=importlib.util.module_from_spec(_spec);_spec.loader.exec_module(parser)
MAX_DATAGRAM=parser.MAX_DATAGRAM
MAX_DATAGRAMS=parser.MAX_DATAGRAMS
MAX_BYTES=parser.MAX_BYTES
CASES=('before','selected','after')
COUNT_KEYS=('datagrams','bytes','matched_queries','answers_sent','rejected','oversized','send_failed')
CASE_COUNT_KEYS=('matched_queries','answers_sent','rejected','send_failed')


def _number(value):
    return type(value) in (int,float) and math.isfinite(value)


class DnsCasesFixture:
    """Socket/thread ownership only; it never proves DNS broker cancellation.

    Dependency injection is for pure tests. Production uses the original
    monotonic clock, socket factory and bounded daemon thread.
    """
    def __init__(self,cases,*,deadline,socket_factory=None,thread_factory=None,clock=None):
        if type(cases) is not dict or set(cases)!=set(CASES):raise ValueError('fixture cases')
        self.names={key:parser.query_name(cases[key]) for key in CASES}
        if len(set(self.names.values()))!=3:raise ValueError('fixture distinct cases')
        self._clock=clock or time.monotonic
        now=self._now()
        if not _number(deadline) or not now<deadline<=now+120:raise ValueError('fixture deadline')
        self._deadline=deadline
        self._socket_factory=socket_factory or socket.socket
        self._thread_factory=thread_factory or threading.Thread
        self.bind_address='127.0.0.1';self.bind_port=53;self.allowed_peers=('127.0.0.1',)
        self.socket=None;self.thread=None
        self.stop=threading.Event();self.ready=threading.Event()
        self.case_query_observed={key:threading.Event() for key in CASES}
        self.query_observed=self.case_query_observed['selected']
        self.observation_lock=threading.RLock();self._close_lock=threading.Lock()
        self.counts=dict.fromkeys(COUNT_KEYS,0)
        self.cases={key:dict.fromkeys(CASE_COUNT_KEYS,0) for key in CASES}
        self.error='none';self.closed=False
        self._start_attempted=False
        self._socket_create_attempted=False;self._socket_create_returned=False
        self._socket_close_attempted=False;self._socket_close_uncertain=False;self._socket_close_confirmed=False
        self._thread_create_attempted=False;self._thread_create_returned=False
        self._thread_start_attempted=False;self._thread_start_returned=False;self._thread_uncertain=False

    @property
    def deadline(self):return self._deadline

    def _now(self):
        value=self._clock()
        if not _number(value):raise ValueError('fixture clock')
        return value

    def _remaining(self,deadline,limit=None):
        if not _number(deadline):raise ValueError('fixture deadline')
        remaining=max(0,min(deadline,self.deadline)-self._now())
        return remaining if limit is None else min(remaining,limit)

    def _fail(self,error):
        with self.observation_lock:
            if self.error=='none':self.error=error

    def start(self):
        if self._start_attempted:raise ValueError('fixture started')
        self._start_attempted=True
        try:
            if not self._remaining(self.deadline):raise TimeoutError('fixture deadline')
            if not hasattr(socket,'SO_EXCLUSIVEADDRUSE'):raise ValueError('exclusive unavailable')
            self._socket_create_attempted=True
            sock=self._socket_factory(socket.AF_INET,socket.SOCK_DGRAM)
            self.socket=sock;self._socket_create_returned=True
            sock.setsockopt(socket.SOL_SOCKET,socket.SO_EXCLUSIVEADDRUSE,1)
            if sock.getsockopt(socket.SOL_SOCKET,socket.SO_EXCLUSIVEADDRUSE)!=1:raise ValueError('exclusive readback')
            sock.bind(('127.0.0.1',53));sock.settimeout(self._remaining(self.deadline,.1))
            address=sock.getsockname()
            if type(address) is not tuple or address!=('127.0.0.1',53) or type(address[1]) is not int:
                raise ValueError('fixture endpoint')
            if not self._remaining(self.deadline):raise TimeoutError('fixture deadline')
            self._thread_create_attempted=True
            self.thread=self._thread_factory(target=self._serve,daemon=True)
            self._thread_create_returned=True;self._thread_start_attempted=True
            self.thread.start();self._thread_start_returned=True
            if not self.ready.wait(self._remaining(self.deadline,1)):raise TimeoutError('fixture ready')
            return 53
        except BaseException:
            if self._socket_create_attempted and not self._socket_create_returned:self._socket_close_uncertain=True
            if (self._thread_create_attempted and not self._thread_create_returned
                    or self._thread_start_attempted and not self._thread_start_returned):self._thread_uncertain=True
            self._fail('deadline' if self._remaining_or_zero(self.deadline)==0 else 'operation')
            raise

    def _remaining_or_zero(self,deadline,limit=None):
        try:return self._remaining(deadline,limit)
        except Exception:return 0

    def _record_oversized(self):
        with self.observation_lock:
            self.counts['datagrams']+=1;self.counts['oversized']+=1;self.counts['rejected']+=1
            self.counts['bytes']=min(MAX_BYTES,self.counts['bytes']+MAX_DATAGRAM+1)

    def _serve(self):
        sock=self.socket
        self.ready.set()
        try:
            while not self.stop.is_set() and self._now()<self.deadline:
                with self.observation_lock:
                    if self.counts['datagrams']>=MAX_DATAGRAMS or self.counts['bytes']>=MAX_BYTES:
                        self._fail('bound');return
                try:raw,peer=sock.recvfrom(MAX_DATAGRAM+1)
                except socket.timeout:continue
                except OSError as exc:
                    if self.stop.is_set():return
                    if getattr(exc,'winerror',None)==10040:self._record_oversized();continue
                    self._fail('receive');return
                with self.observation_lock:
                    self.counts['datagrams']+=1
                    size=len(raw) if type(raw) is bytes else 0
                    remaining=MAX_BYTES-self.counts['bytes']
                    self.counts['bytes']=min(MAX_BYTES,self.counts['bytes']+size)
                    if size>remaining:self.counts['rejected']+=1;self._fail('bound');return
                    if type(raw) is not bytes or not 12<=size<=MAX_DATAGRAM:
                        self.counts['rejected']+=1
                        if size>MAX_DATAGRAM:self.counts['oversized']+=1
                        continue
                    if (type(peer) is not tuple or len(peer)!=2 or peer[0]!='127.0.0.1'
                            or type(peer[1]) is not int or not 1<=peer[1]<=65535):
                        self.counts['rejected']+=1;continue
                    matched=None;response=None
                    for key in CASES:
                        try:response=parser.answer_query(raw,self.names[key])
                        except ValueError:continue
                        matched=key;break
                    if matched is None:self.counts['rejected']+=1;continue
                    self.counts['matched_queries']+=1;self.cases[matched]['matched_queries']+=1
                    # Set the independent event before any send/answer commit.
                    self.case_query_observed[matched].set()
                    if self.stop.is_set() or self._now()>=self.deadline:self._fail('deadline');return
                    try:
                        sock.settimeout(self._remaining(self.deadline,.1))
                        if sock.sendto(response,peer)!=len(response):raise OSError('short datagram')
                        self.counts['answers_sent']+=1;self.cases[matched]['answers_sent']+=1
                    except OSError:
                        self.counts['send_failed']+=1;self.cases[matched]['send_failed']+=1
                        self._fail('send');return
                    # An actual late send stays counted; lateness cannot erase it.
                    if self._now()>=self.deadline:self._fail('deadline');return
            if not self.stop.is_set():self._fail('deadline')
        except Exception:self._fail('operation')

    def _observations(self,known):
        events={key:self.case_query_observed[key].is_set() for key in CASES}
        return dict(ready=self.ready.is_set(),error=self.error,
            counts=dict(self.counts) if known else None,
            cases={key:dict(self.cases[key]) for key in CASES} if known else None,
            case_query_observed=events,selected_query_observed=events['selected'],
            byte_count_is_observed_lower_bound=True,broker_cancellation_proven=False)

    def snapshot(self,*,deadline):
        if not self.observation_lock.acquire(timeout=self._remaining(deadline,.5)):raise TimeoutError('fixture snapshot')
        try:return self._observations(True)
        finally:self.observation_lock.release()

    def finish(self,*,deadline):
        # Consume the close authority before calling close. A failure or unknown
        # readback is sticky, even if a later finish observes the process quiet.
        self.stop.set()
        with self._close_lock:
            if self.socket is not None and not self._socket_close_attempted:
                sock=self.socket;self.socket=None;self._socket_close_attempted=True
                try:
                    sock.close()
                    if sock.fileno()!=-1:raise OSError('fixture close readback')
                    self._socket_close_confirmed=True
                except Exception:self._socket_close_uncertain=True
            socket_closed=(not self._socket_create_attempted
                or self._socket_create_returned and self._socket_close_confirmed) and not self._socket_close_uncertain
        stopped=self.thread is None and not self._thread_create_attempted
        if self.thread is not None:
            try:
                self.thread.join(self._remaining_or_zero(deadline))
                stopped=not self.thread.is_alive()
            except Exception:self._thread_uncertain=True;stopped=False
        stopped=stopped and not self._thread_uncertain
        self.closed=bool(socket_closed and stopped)
        acquired=self.observation_lock.acquire(timeout=self._remaining_or_zero(deadline,.5))
        try:out=self._observations(bool(stopped and acquired))
        finally:
            if acquired:self.observation_lock.release()
        out.update(socket_close_attempted=self._socket_close_attempted,socket_close_uncertain=self._socket_close_uncertain,
            socket_closed=bool(socket_closed),thread_stopped=bool(stopped),cleanup_confirmed=self.closed)
        return out
