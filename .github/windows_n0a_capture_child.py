"""Standalone capture ownership experiment; not integrated with any Windows host.

The parent owns QEMU and the drain child independently. Exact-owned stop
attempts use one absolute deadline; unconfirmed exit forbids cleanup and
completeness. No OS syscall or successful termination has a hard-time guarantee.
This is same-privilege failure isolation, not a security sandbox.
No packet-absence or network-isolation verdict is produced.
"""
import argparse
import array
import struct
import importlib.util
import json
import os
from pathlib import Path
import selectors
import signal
import socket
import stat
import subprocess
import sys
import time

_spec=importlib.util.spec_from_file_location('capture_primitive',Path(__file__).with_name('windows_n0a_capture.py'))
primitive=importlib.util.module_from_spec(_spec);_spec.loader.exec_module(primitive)
MAX_FRAME=2048
MAX_FRAMES=64
MAX_STDERR=65536
ERRORS=primitive.ERRORS | frozenset(('ipc','ipc_budget','child_exit','child_forced','ownership','authorization'))
PHASES=('reader_open','ready','active','final')
FIXTURES=('none','close_reader','stall_fsync','exit_without_final','final_before_exit','trailing_frame','empty_trailing_frame','nested_frame')
STAT_KEYS={'v','seq','phase','header','authorized','reader_closed','fifo_eof','stderr_eof','overflow','retained','drained','records','stderr_bytes','flushed','closed','structure','qemu_dump_write_error','errors'}
BOOL_KEYS=('header','authorized','reader_closed','fifo_eof','stderr_eof','overflow','flushed','closed','structure','qemu_dump_write_error')


def unique(pairs):
    result={}
    for key,value in pairs:
        if key in result:raise ValueError('duplicate IPC key')
        result[key]=value
    return result


def decode(data,flags=0):
    if flags & socket.MSG_TRUNC or not 0<len(data)<=MAX_FRAME:raise ValueError('IPC frame bound')
    try:value=json.loads(data.decode('ascii'),object_pairs_hook=unique)
    except (ValueError,UnicodeError,RecursionError) as error:raise ValueError('IPC encoding') from None
    if type(value) is not dict:raise ValueError('IPC shape')
    return value


def encode(value):
    data=json.dumps(value,ensure_ascii=True,separators=(',',':'),allow_nan=False).encode('ascii')
    if not 0<len(data)<=MAX_FRAME:raise ValueError('IPC frame bound')
    return data


CREDENTIAL_SIZE=struct.calcsize('=iII')

class CloseLedger:
    """Linux close errors are uncertainty, never permission to retry a reused fd."""
    def __init__(self):self.uncertain=False
    def close(self,fd):
        try:os.close(fd);return True
        except OSError:self.uncertain=True;return False


def receive(channel,expected,ledger):
    # Per-record credentials are NOT SO_PEERCRED's socketpair-time cache.
    data,ancillary,flags,_=channel.recvmsg(MAX_FRAME+1,socket.CMSG_SPACE(CREDENTIAL_SIZE),socket.MSG_CMSG_CLOEXEC)
    for level,kind,payload in ancillary:
        if level==socket.SOL_SOCKET and kind==socket.SCM_RIGHTS:
            descriptors=array.array('i');descriptors.frombytes(payload[:len(payload)//descriptors.itemsize*descriptors.itemsize])
            for fd in descriptors:ledger.close(fd) # one close attempt, never retry a bare numeric fd
    if flags & (socket.MSG_TRUNC|socket.MSG_CTRUNC):raise ValueError('IPC truncation')
    if not data and not ancillary:return None # actual EOF; final+child exit still required
    if (len(ancillary)!=1 or ancillary[0][0:2]!=(socket.SOL_SOCKET,socket.SCM_CREDENTIALS)
            or len(ancillary[0][2])!=CREDENTIAL_SIZE):raise ValueError('IPC ancillary')
    credentials=struct.unpack('=iII',ancillary[0][2])
    if credentials!=expected:raise ValueError('IPC sender')
    if not data:raise ValueError('empty IPC record')
    return data


def valid_status(value,previous=None):
    if set(value)!=STAT_KEYS or type(value['v']) is not int or value['v']!=1:raise ValueError('status keys')
    if type(value['seq']) is not int or not 1<=value['seq']<=MAX_FRAMES:raise ValueError('status sequence')
    if value['phase'] not in PHASES or any(type(value[k]) is not bool for k in BOOL_KEYS):raise ValueError('status type')
    for key,limit in (('retained',primitive.CAPTURE_LIMIT),('drained',2**64-1),('records',2**32-1),('stderr_bytes',2**32-1)):
        if type(value[key]) is not int or not 0<=value[key]<=limit:raise ValueError('status count')
    if value['retained']>value['drained']:raise ValueError('status count order')
    if (type(value['errors']) is not list or any(type(v) is not str or v not in ERRORS for v in value['errors'])
            or value['errors']!=sorted(set(value['errors']))):raise ValueError('status errors')
    if previous is None:
        if value['seq']!=1 or value['phase']!='reader_open':raise ValueError('status start')
    else:
        if (value['seq']<=previous['seq'] or previous['phase']=='final'
                or PHASES.index(value['phase'])<PHASES.index(previous['phase'])):raise ValueError('status regression')
        for key in BOOL_KEYS:
            if key=='structure':continue # partial trailing packet can change this observation
            if previous[key] and not value[key]:raise ValueError('status flag regression')
        if any(value[k]<previous[k] for k in ('retained','drained','records','stderr_bytes')):raise ValueError('status count regression')
        if not set(previous['errors'])<=set(value['errors']):raise ValueError('status error regression')
    return value


def valid_command(value,last_sequence):
    if (set(value)!={'v','seq','op'} or type(value['v']) is not int or value['v']!=1
            or type(value['seq']) is not int or value['seq']!=last_sequence+1 or not 1<=value['seq']<=8
            or value['op'] not in ('arm','authorize','finalize','fixture_close_reader')):
        raise ValueError('control frame')
    return value


class DrainWorker:
    """One serialized selector loop; no QEMU handle, PID, spawn or signal API."""
    def __init__(self,root_fd,stderr_fd,status_fd,deadline,fixture='none',limit=primitive.CAPTURE_LIMIT,parent_pid=None):
        self.root_fd=root_fd;self.stderr_fd=stderr_fd;self.channel=socket.socket(fileno=status_fd)
        self.deadline=deadline;self.fixture=fixture;self.limit=limit
        self.expected_parent=(os.getppid() if parent_pid is None else parent_pid,os.getuid(),os.getgid())
        self.close_ledger=CloseLedger()
        self.read_fd=self.output_fd=None;self.selector=None
        self.errors=set();self.phase='reader_open';self.seq=0;self.command_seq=0;self.control_frames=0
        self.pending=None;self.last_sent=None;self.ipc_failed=False;self.control_eof=False
        self.armed=self.authorized=self.finalize_requested=self.reader_closed=False
        self.fifo_eof=self.stderr_eof=self.flushed=self.closed=self.overflow=False
        self.qemu_dump_write_error=False
        self.retained=self.drained=self.stderr_bytes=0;self.stderr_pending=bytearray()
        self.structure=primitive.PcapStructure()

    def fail(self,error):self.errors.add(error if error in ERRORS else 'read')

    def snapshot(self):
        return dict(v=1,seq=self.seq+1,phase=self.phase,header=self.structure.header,authorized=self.authorized,
            reader_closed=self.reader_closed,fifo_eof=self.fifo_eof,stderr_eof=self.stderr_eof,overflow=self.overflow,
            retained=self.retained,drained=self.drained,records=self.structure.records,stderr_bytes=self.stderr_bytes,
            flushed=self.flushed,closed=self.closed,structure=self.structure.complete(),qemu_dump_write_error=self.qemu_dump_write_error,errors=sorted(self.errors))

    def emit(self):
        if self.ipc_failed:return
        value=self.snapshot()
        # Reserve the final slot, and never let socket backpressure block capture drain.
        if self.seq>=MAX_FRAMES-1 and self.phase!='final':self.fail('ipc_budget');return
        if self.seq>=MAX_FRAMES:self.fail('ipc_budget');return
        try:
            data=encode(value);written=self.channel.send(data)
            if written!=len(data):raise OSError('partial status')
        except BlockingIOError:
            self.fail('ipc');self.pending=True;return
        except (OSError,ValueError):
            self.fail('ipc');self.ipc_failed=True;return
        self.seq+=1;self.last_sent=value;self.pending=None

    def _close_fd(self,name):
        fd=getattr(self,name)
        if fd is None:return
        setattr(self,name,None) # detach before Linux close; error may still release the fd
        if not self.close_ledger.close(fd):self.fail('close')

    def close_reader(self):
        if self.read_fd is not None:
            try:self.selector.unregister(self.read_fd)
            except (KeyError,ValueError):pass
            self._close_fd('read_fd')
        self.reader_closed=self.read_fd is None

    def stderr_line(self,line):
        import re
        if not line:return
        if self.authorized and re.fullmatch(rb'qemu-system-x86_64: terminating on signal 15 from pid [0-9]+(?: \([^\r\n]{1,256}\))?',line):return
        if line==b'qemu-system-x86_64: network dump write error - stopping dump':self.qemu_dump_write_error=True
        lower=line.lower()
        self.fail('stderr_capture' if any(x in lower for x in (b'dump',b'pcap',b'write error',b'short write')) else 'stderr_unknown')

    def capture(self):
        try:data=os.read(self.read_fd,primitive.CHUNK)
        except BlockingIOError:return
        except OSError:self.fail('read');self.close_reader();return
        if not data:
            self.fifo_eof=True
            if not self.authorized:self.fail('early_eof')
            self.close_reader();self.emit();return
        before=(self.structure.header,frozenset(self.errors),self.overflow)
        self.drained=min(2**64-1,self.drained+len(data))
        room=max(0,self.limit-self.retained);kept=memoryview(data[:room])
        try:
            while kept:
                size=os.write(self.output_fd,kept)
                if size<=0:raise OSError('short capture write')
                self.retained+=size;kept=kept[size:]
        except OSError:self.fail('write')
        if len(data)>room:self.overflow=True;self.fail('overflow')
        self.structure.feed(data)
        if self.structure.error:self.fail(self.structure.error)
        if before!=(self.structure.header,frozenset(self.errors),self.overflow):self.emit()

    def stderr(self):
        try:data=os.read(self.stderr_fd,primitive.CHUNK)
        except BlockingIOError:return
        except OSError:self.fail('read');return
        if not data:
            if self.stderr_pending:self.stderr_line(bytes(self.stderr_pending));self.stderr_pending.clear()
            self.stderr_eof=True;self.selector.unregister(self.stderr_fd);self._close_fd('stderr_fd');self.emit();return
        before=set(self.errors);room=max(0,MAX_STDERR-self.stderr_bytes)
        self.stderr_bytes=min(2**32-1,self.stderr_bytes+len(data))
        if len(data)>room:self.fail('stderr_bound')
        for value in data[:room]:
            if value==10:self.stderr_line(bytes(self.stderr_pending));self.stderr_pending.clear()
            elif len(self.stderr_pending)<4096:self.stderr_pending.append(value)
            else:self.fail('stderr_bound')
        if self.errors!=before:self.emit()

    def control(self):
        try:data=receive(self.channel,self.expected_parent,self.close_ledger)
        except BlockingIOError:return
        except ValueError:
            self.control_frames+=1;self.fail('ipc')
            if self.control_frames>8:
                self.fail('ipc_budget');self.control_eof=True;self.selector.unregister(self.channel)
            self.emit();return
        except OSError:data=None
        if data is None:
            self.fail('ipc');self.control_eof=True
            try:self.selector.unregister(self.channel)
            except (KeyError,ValueError):pass
            return
        self.control_frames+=1
        if self.control_frames>8:
            self.fail('ipc_budget');self.control_eof=True;self.selector.unregister(self.channel);self.emit();return
        try:value=valid_command(decode(data),self.command_seq)
        except (ValueError,UnicodeError,json.JSONDecodeError):self.fail('ipc');self.emit();return
        self.command_seq=value['seq'];op=value['op']
        if op=='arm' and not self.armed:
            self.armed=True;self.phase='ready';self.selector.register(self.read_fd,selectors.EVENT_READ,'capture');self.emit()
        elif op=='authorize' and self.armed and not self.authorized:
            self.authorized=True;self.emit()
        elif op=='finalize' and self.authorized:
            self.finalize_requested=True
        elif op=='fixture_close_reader' and self.fixture=='close_reader' and self.structure.header:
            self.close_reader();self.fail('read');self.emit()
        else:self.fail('ipc');self.emit()

    def run(self):
        try:
            if os.getppid()!=self.expected_parent[0]:raise ValueError('parent changed')
            root=os.fstat(self.root_fd)
            if not stat.S_ISDIR(root.st_mode) or root.st_uid!=os.getuid() or stat.S_IMODE(root.st_mode)&0o077:raise ValueError('root')
            self.channel.setblocking(False);os.set_blocking(self.stderr_fd,False)
            self.output_fd=os.open('capture.pcap',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=self.root_fd)
            self.read_fd=os.open('capture.fifo',os.O_RDONLY|os.O_NONBLOCK|os.O_NOFOLLOW,dir_fd=self.root_fd)
            info=os.fstat(self.read_fd)
            if not stat.S_ISFIFO(info.st_mode) or info.st_uid!=os.getuid():raise ValueError('fifo')
            with selectors.DefaultSelector() as self.selector:
                self.selector.register(self.channel,selectors.EVENT_READ,'control')
                self.selector.register(self.stderr_fd,selectors.EVENT_READ,'stderr')
                self.emit()
                while time.monotonic()<self.deadline:
                    if self.finalize_requested and (self.fifo_eof or self.reader_closed) and self.stderr_eof:break
                    for key,_ in self.selector.select(min(.05,max(0,self.deadline-time.monotonic()))):
                        getattr(self,key.data)()
                    if self.pending:self.emit()
                else:self.fail('deadline')
                if self.fixture=='exit_without_final':return 4
                if self.fixture=='stall_fsync':time.sleep(3600) # explicit nondeployable fixture, parent must kill
                if self.output_fd is not None:
                    try:os.fsync(self.output_fd);self.flushed=True
                    except OSError:self.fail('flush')
                self.close_reader();self._close_fd('output_fd');self._close_fd('stderr_fd');self._close_fd('root_fd')
                if self.close_ledger.uncertain:self.fail('close')
                self.closed=all(x is None for x in (self.read_fd,self.output_fd,self.stderr_fd,self.root_fd)) and not self.close_ledger.uncertain
                self.phase='final';self.emit()
                # One nonblocking retry window inside the original deadline, never a renewed deadline.
                while self.pending and time.monotonic()<self.deadline:
                    time.sleep(min(.01,max(0,self.deadline-time.monotonic())));self.emit()
                if self.fixture=='trailing_frame':self.channel.send(b'{}')
                if self.fixture=='empty_trailing_frame':self.channel.send(b'');self.channel.send(b'{}')
                if self.fixture=='nested_frame':self.channel.send(b'['*1000+b'0'+b']'*1000)
                if self.fixture=='final_before_exit':time.sleep(3600)
                return 0 if not self.errors and self.closed else 4
        except BaseException:
            self.fail('creation');return 4
        finally:
            for name in ('read_fd','output_fd','stderr_fd','root_fd'):self._close_fd(name)
            self.channel.close()


class CaptureOwner:
    """Parent-only process owner. Register this object before calling start()."""
    def __init__(self,owned_directory,*,deadline):
        if type(deadline) not in (int,float) or not time.monotonic()<deadline<float('inf'):raise ValueError('deadline')
        self.root=Path(owned_directory);self.deadline=deadline
        self.fifo_path=self.root/'capture.fifo';self.output_path=self.root/'capture.pcap'
        self.root_fd=self.stderr_read=self.stderr_write=self.dummy_fd=None
        self.channel=self.child_channel=None;self.child=self.process=None
        self.child_spawn_attempted=self.qemu_spawn_attempted=False
        self.close_ledger=CloseLedger()
        self.status=None;self.control_seq=0;self.status_frames=0;self.errors=set();self.ipc_eof=False
        self.fixture='none';self.limit=primitive.CAPTURE_LIMIT
        self.qemu_forced=self.child_forced=False;self.live_at_shutdown=False
        self.authorization_confirmed=False;self.final=None
        self.ready_observed=self.header_observed=False

    @classmethod
    def for_test(cls,root,*,deadline,mode='none',byte_limit=primitive.CAPTURE_LIMIT):
        if mode not in FIXTURES or type(byte_limit) is not int or not 24<=byte_limit<=primitive.CAPTURE_LIMIT:raise ValueError('fixture')
        result=cls(root,deadline=deadline);result.fixture=mode;result.limit=byte_limit;return result

    def fail(self,error):self.errors.add(error if error in ERRORS else 'ownership')

    def _close(self,name):
        value=getattr(self,name)
        if value is None:return
        setattr(self,name,None)
        if isinstance(value,socket.socket):
            try:value.close()
            except OSError:self.close_ledger.uncertain=True;self.fail('close')
        elif not self.close_ledger.close(value):self.fail('close')

    def poll_status(self,deadline=None):
        if self.channel is None or self.ipc_eof:return self.status
        deadline=min(self.deadline,time.monotonic() if deadline is None else deadline)
        while True:
            try:data=receive(self.channel,None if self.child is None else (self.child.pid,os.getuid(),os.getgid()),self.close_ledger)
            except BlockingIOError:
                if time.monotonic()>=deadline:break
                try:
                    with selectors.DefaultSelector() as selector:
                        selector.register(self.channel,selectors.EVENT_READ)
                        selector.select(min(.05,max(0,deadline-time.monotonic())))
                except (OSError,ValueError):self.fail('ipc');self.ipc_eof=True;break
                continue
            except ValueError:
                self.status_frames+=1;self.fail('ipc')
                if self.status_frames>MAX_FRAMES:self.fail('ipc_budget');self.ipc_eof=True
                break
            except OSError:self.fail('ipc');self.ipc_eof=True;break
            if data is None:
                self.ipc_eof=True
                if self.status is None or self.status['phase']!='final':self.fail('ipc')
                break
            self.status_frames+=1
            if self.status_frames>MAX_FRAMES:self.fail('ipc_budget');self.ipc_eof=True;break
            try:self.status=valid_status(decode(data),self.status)
            except (ValueError,UnicodeError,json.JSONDecodeError):self.fail('ipc');break
            if self.status['header']:self._close('dummy_fd')
            # Drain every queued datagram even at a zero-wait poll; total frames
            # are bounded independently. Final alone cannot hide trailing input.
        return self.status

    def command(self,op,deadline):
        if self.channel is None or self.ipc_eof or self.control_seq>=8:self.fail('ipc');return False
        frame=encode(dict(v=1,seq=self.control_seq+1,op=op));deadline=min(deadline,self.deadline)
        while time.monotonic()<deadline:
            try:
                if self.channel.send(frame)!=len(frame):raise OSError('partial control')
                self.control_seq+=1;return True
            except BlockingIOError:
                time.sleep(min(.01,max(0,deadline-time.monotonic())))
            except OSError:break
        self.fail('ipc');return False

    def wait(self,predicate,deadline):
        deadline=min(deadline,self.deadline)
        while time.monotonic()<deadline:
            self.poll_status()
            if self.errors or self.ipc_eof:return False
            if predicate(self.status):return True
            try:
                if self.child is not None and self.child.poll() is not None:self.fail('child_exit');return False
            except BaseException:self.fail('child_exit');return False
            self.poll_status(min(deadline,time.monotonic()+.05))
        self.fail('deadline');return False

    def start(self):
        if self.child_spawn_attempted:raise ValueError('already started')
        try:
            info=self.root.lstat()
            if not stat.S_ISDIR(info.st_mode) or info.st_uid!=os.getuid() or stat.S_IMODE(info.st_mode)&0o077 or self.root.resolve()!=self.root.absolute():raise ValueError('root')
            self.root_fd=os.open(self.root,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
            os.mkfifo('capture.fifo',0o600,dir_fd=self.root_fd)
            self.stderr_read,self.stderr_write=os.pipe()
            self.channel,self.child_channel=socket.socketpair(socket.AF_UNIX,socket.SOCK_SEQPACKET)
            self.channel.setblocking(False)
            self.channel.setsockopt(socket.SOL_SOCKET,socket.SO_PASSCRED,1)
            self.child_channel.setsockopt(socket.SOL_SOCKET,socket.SO_PASSCRED,1)
            args=[sys.executable,'-I','-S','-B',str(Path(__file__).resolve()),'--worker',
                  '--root-fd',str(self.root_fd),'--stderr-fd',str(self.stderr_read),'--status-fd',str(self.child_channel.fileno()),
                  '--deadline',str(self.deadline),'--parent-pid',str(os.getpid())]
            if self.fixture!='none' or self.limit!=primitive.CAPTURE_LIMIT:args+=['--fixture',self.fixture,'--byte-limit',str(self.limit)]
            self.child_spawn_attempted=True
            self.child=subprocess.Popen(args,stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,
                close_fds=True,pass_fds=(self.root_fd,self.stderr_read,self.child_channel.fileno()))
            self._close('child_channel');self._close('stderr_read');self._close('root_fd')
            if not self.wait(lambda s:s is not None and s['phase']=='reader_open',min(self.deadline,time.monotonic()+2)):raise RuntimeError('reader handshake')
            self.dummy_fd=os.open(self.fifo_path,os.O_WRONLY|os.O_NONBLOCK|os.O_NOFOLLOW)
            if not self.command('arm',min(self.deadline,time.monotonic()+1)):raise RuntimeError('arm')
            if not self.wait(lambda s:s is not None and s['phase']=='ready',min(self.deadline,time.monotonic()+1)):raise RuntimeError('ready')
            self.ready_observed=True
        except BaseException:self.fail('creation');raise
        return self

    def spawn(self,argv,*,pass_fds=()):
        if self.qemu_spawn_attempted or self.status is None or self.status['phase']!='ready' or self.errors or time.monotonic()>=self.deadline:raise ValueError('spawn admission')
        if type(pass_fds) is not tuple or len(pass_fds)>4 or len(set(pass_fds))!=len(pass_fds) or any(type(v) is not int or v<0 for v in pass_fds):raise ValueError('descriptor whitelist')
        for fd in pass_fds:os.fstat(fd)
        self.qemu_spawn_attempted=True
        try:
            self.process=subprocess.Popen(argv,stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=self.stderr_write,
                close_fds=True,pass_fds=pass_fds)
        except BaseException:self.fail('spawn');raise
        finally:self._close('stderr_write')
        return self.process

    def wait_header(self,deadline):
        self.header_observed=self.wait(lambda s:s is not None and s['header'] and not s['errors'],deadline)
        return self.header_observed

    def fixture_close_reader(self,deadline):
        if self.fixture!='close_reader':raise ValueError('fixture only')
        return self.command('fixture_close_reader',deadline) and self.wait(lambda s:s is not None and s['reader_closed'],deadline)

    def _poll(self,process):
        try:
            code=process.poll();return code if type(code) is int else None
        except BaseException:self.fail('process_wait');return None

    def _stop(self,process,deadline,term_seconds,kind):
        if process is None:return True,None
        code=self._poll(process)
        if code is None:
            try:process.send_signal(signal.SIGTERM)
            except BaseException:self.fail('terminate')
            try:process.wait(timeout=max(0,min(term_seconds,deadline-time.monotonic())))
            except subprocess.TimeoutExpired:pass
            except BaseException:self.fail('process_wait')
            code=self._poll(process)
            if code is None:
                setattr(self,kind+'_forced',True)
                try:process.kill()
                except BaseException:self.fail('kill')
                try:process.wait(timeout=max(0,min(1,deadline-time.monotonic())))
                except BaseException:self.fail('process_wait')
                code=self._poll(process)
        return code is not None,code

    def finish(self,*,cleanup_deadline):
        if self.final is not None:return dict(self.final)
        deadline=min(cleanup_deadline,self.deadline)
        self.poll_status()
        self.live_at_shutdown=self.process is not None and self._poll(self.process) is None
        if self.status is not None and self.live_at_shutdown:
            ack_deadline=min(deadline-3,time.monotonic()+.5)
            self.authorization_confirmed=self.command('authorize',ack_deadline) and self.wait(lambda s:s is not None and s['authorized'],ack_deadline)
            if not self.authorization_confirmed:self.fail('authorization')
        qemu_deadline=max(time.monotonic(),deadline-3)
        qemu_exit,qemu_code=self._stop(self.process,qemu_deadline,min(15,max(0,qemu_deadline-time.monotonic()-1)),'qemu')
        self._close('stderr_write')
        if qemu_exit:self._close('dummy_fd')
        if self.authorization_confirmed:self.command('finalize',min(deadline-1,time.monotonic()+.25))
        # Drain final status without allowing it to substitute for observed child exit.
        drain_deadline=max(time.monotonic(),deadline-1)
        while self.child is not None and time.monotonic()<drain_deadline:
            self.poll_status(min(drain_deadline,time.monotonic()+.05))
            if self._poll(self.child) is not None:break
        child_code=self._poll(self.child) if self.child is not None else None
        child_exit=self.child is None or child_code is not None
        if not child_exit:
            self.child_forced=True;self.fail('child_forced')
            child_exit,child_code=self._stop(self.child,deadline,min(.25,max(0,deadline-time.monotonic()-.25)),'child')
        self.poll_status()
        for name in ('root_fd','stderr_read','stderr_write','dummy_fd','child_channel','channel'):self._close(name)
        if self.close_ledger.uncertain:self.fail('close')
        descriptors=not self.close_ledger.uncertain and all(getattr(self,k) is None for k in ('root_fd','stderr_read','stderr_write','dummy_fd','child_channel','channel'))
        final_status=self.status is not None and self.status['phase']=='final'
        cleanup=qemu_exit and child_exit and descriptors
        status=self.status
        complete=(cleanup and self.ready_observed and self.header_observed and not self.errors and self.live_at_shutdown and self.authorization_confirmed
            and self.ipc_eof and qemu_code==0 and child_code==0 and not self.qemu_forced and not self.child_forced and final_status
            and not status['errors'] and status['header'] and status['structure'] and status['fifo_eof'] and status['stderr_eof']
            and status['closed'] and status['flushed'] and not status['overflow'])
        result=dict(schema_version=1,execution_model='owned_child',fixture=self.fixture!='none' or self.limit!=primitive.CAPTURE_LIMIT,
            ready_observed=self.ready_observed,header_verified=self.header_observed,
            shutdown_authorized=self.authorization_confirmed,producer_live_at_shutdown=self.live_at_shutdown,
            qemu_started=self.process is not None,qemu_exit_observed=self.process is not None and qemu_exit,qemu_exit_code=qemu_code,qemu_forced=self.qemu_forced,
            child_started=self.child is not None,child_exit_observed=self.child is not None and child_exit,child_exit_code=child_code,child_forced=self.child_forced,
            final_status_observed=final_status,status_eof=self.ipc_eof,descriptors_closed=descriptors,
            cleanup_confirmed=cleanup,drain_complete=bool(complete),errors=sorted(self.errors),
            capture=status,root_removal_attempted=False,packet_absence_proven=False)
        if cleanup:self.final=result
        return dict(result)


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--worker',action='store_true')
    for name in ('root-fd','stderr-fd','status-fd'):parser.add_argument('--'+name,type=int,required=True)
    parser.add_argument('--deadline',type=float,required=True);parser.add_argument('--parent-pid',type=int,required=True)
    parser.add_argument('--fixture',choices=FIXTURES,default='none');parser.add_argument('--byte-limit',type=int,default=primitive.CAPTURE_LIMIT)
    args=parser.parse_args()
    if not args.worker or not 24<=args.byte_limit<=primitive.CAPTURE_LIMIT:return 2
    return DrainWorker(args.root_fd,args.stderr_fd,args.status_fd,args.deadline,args.fixture,args.byte_limit,args.parent_pid).run()

if __name__=='__main__':raise SystemExit(main())
