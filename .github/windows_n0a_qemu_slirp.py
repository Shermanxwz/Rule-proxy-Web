"""Linux mapped-file/package provenance, not resident-code or source equivalence.

Only observes the caller's exact owned Popen. No process reopening, QMP, ldd,
map_files, guest execution, package changes, or networking is performed here.
"""
from __future__ import annotations
import hashlib
import os
from pathlib import Path
import re
import select
import stat
import subprocess
import time

MAP_LIMIT = 2 * 1024 * 1024
FILE_LIMIT = 128 * 1024 * 1024
PACKAGE_LIMIT = 2 * 1024 * 1024
# Preserve ownership after uncertainty; never retry a possibly reused descriptor.
RETAINED_OWNERS = []


def check_deadline(deadline):
    if time.monotonic() >= deadline: raise TimeoutError('deadline')


def close_fd(record):
    if record['close_attempted']: return record['closed']
    record['close_attempted']=True
    if record['fd'] is None: return True
    try:
        os.close(record['fd']);record['closed']=True
    except Exception:
        record['uncertain']=True
    return record['closed']


def bounded_read(path, limit, deadline, ledger):
    check_deadline(deadline)
    record={'fd':None,'close_attempted':False,'closed':False,'uncertain':False}
    ledger.append(record)
    try:
        record['fd']=os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
        data=bytearray()
        while True:
            check_deadline(deadline)
            part=os.read(record['fd'],min(65536,limit+1-len(data)))
            check_deadline(deadline)
            if not part: break
            data.extend(part)
            if len(data)>limit: raise ValueError('bound')
        return bytes(data)
    finally:
        if not close_fd(record): raise OSError('read_close_uncertain')


def start_time(data):
    # comm may contain spaces or parentheses; fields following its final ')' are fixed.
    tail = data.rsplit(b') ', 1)
    fields = tail[1].split() if len(tail) == 2 else []
    if len(fields) < 20 or not fields[19].isdigit():
        raise ValueError('process_stat')
    return int(fields[19])


def mapped_slirp(data, deadline=None):
    entries = set()
    for line in data.decode('utf-8', 'strict').splitlines():
        if deadline is not None: check_deadline(deadline)
        fields = line.split(None, 5)
        if len(fields) != 6:
            continue
        path = fields[5]
        if 'libslirp' not in path:
            continue
        if not re.fullmatch(r'/[^\x00-\x20]*?/libslirp\.so\.[0-9]+(?:\.[0-9]+)*', path):
            raise ValueError('mapping_path')
        device = fields[3].split(':')
        if len(device) != 2 or not all(re.fullmatch('[0-9a-fA-F]+', x) for x in device) or not fields[4].isdigit():
            raise ValueError('mapping_identity')
        inode = int(fields[4])
        if inode <= 0:
            raise ValueError('mapping_inode')
        entries.add((path, int(device[0], 16), int(device[1], 16), inode))
    if len(entries) != 1:
        raise ValueError('mapping_unique')
    return next(iter(entries))


def signature(info):
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns, info.st_mode)


def hash_fd(fd, deadline):
    check_deadline(deadline)
    before = os.fstat(fd)
    if not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= FILE_LIMIT:
        raise ValueError('backing_type_size')
    sha, md5 = hashlib.sha256(), hashlib.md5()
    offset = 0
    while offset < before.st_size:
        if time.monotonic() >= deadline:
            raise TimeoutError('deadline')
        data = os.pread(fd, min(65536, before.st_size-offset), offset)
        if not data:
            raise ValueError('short_read')
        sha.update(data); md5.update(data); offset += len(data)
    check_deadline(deadline)
    if os.pread(fd, 1, offset) or signature(before) != signature(os.fstat(fd)):
        raise ValueError('backing_changed')
    check_deadline(deadline)
    return sha.hexdigest(), md5.hexdigest(), signature(before)


def observe_process(record):
    process=record['process']
    if process is None: return False
    try:
        code=process.poll()
        if code is not None: record['exit_observed']=True
    except Exception: record['uncertain']=True
    return record['exit_observed']


def stop_process(record, deadline):
    process=record['process']
    if process is None: return not record['spawn_attempted']
    observe_process(record)
    if not record['exit_observed'] and not record['kill_attempted']:
        record['kill_attempted']=True
        try: process.kill()
        except Exception: record['uncertain']=True
    # Independent wait/final observation even after poll or kill failure.
    if not record['exit_observed']:
        try:
            process.wait(timeout=max(0.0,deadline-time.monotonic()))
            record['exit_observed']=True
        except Exception: record['uncertain']=True
    observe_process(record)
    return record['exit_observed'] and not record['uncertain']


def new_process_record():
    return {'process':None,'spawn_attempted':False,'stream_close_attempted':False,
            'stream_closed':False,'uncertain':False,'exit_observed':False,'kill_attempted':False}


def command(args, deadline, children):
    check_deadline(deadline)
    end=min(deadline,time.monotonic()+3)
    record=new_process_record();children.append(record)
    record['spawn_attempted']=True
    try:
        record['process']=subprocess.Popen(args,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,
                                          stderr=subprocess.DEVNULL,close_fds=True)
    except Exception:
        record['uncertain']=True
        raise
    process=record['process'];data=bytearray()
    try:
        while True:
            check_deadline(end)
            ready,_,_=select.select([process.stdout],[],[],max(0.0,end-time.monotonic()))
            if not ready: raise TimeoutError('package_deadline')
            part=os.read(process.stdout.fileno(),4097-len(data))
            check_deadline(end)
            if not part: break
            data.extend(part)
            if len(data)>4096: raise ValueError('package_output_bound')
        code=process.wait(timeout=max(0.0,end-time.monotonic()))
        record['exit_observed']=True
        if code!=0: raise ValueError('package_command')
        return bytes(data).decode('ascii','strict')
    finally:
        stop_process(record,deadline)
        if not record['stream_close_attempted']:
            record['stream_close_attempted']=True
            try: process.stdout.close();record['stream_closed']=True
            except Exception: record['uncertain']=True
        if record['uncertain'] or not record['exit_observed'] or not record['stream_closed']:
            raise OSError('command_cleanup_uncertain')


def package(path, expected, md5, deadline, children, ledger):
    check_deadline(deadline)
    owner = command(['/usr/bin/dpkg-query','-S',path],deadline,children).strip()
    # dpkg may report the unsuffixed owner, but architecture is independently queried.
    if owner not in (expected+': '+path, expected+':amd64: '+path):
        raise ValueError('package_owner')
    text = command(['/usr/bin/dpkg-query','-W','-f=${binary:Package}\t${Architecture}\t${Version}\t${db:Status-Status}',expected+':amd64'],deadline,children)
    fields = text.split('\t')
    if len(fields)!=4 or fields[0] not in (expected,expected+':amd64') or fields[1]!='amd64' or fields[3]!='installed' or not re.fullmatch(r'[0-9][A-Za-z0-9.+:~\-]{0,127}',fields[2]):
        raise ValueError('package_metadata')
    choices=[Path('/var/lib/dpkg/info')/(expected+suffix+'.md5sums') for suffix in (':amd64','')]
    available=[x for x in choices if x.exists()]
    if len(available)!=1:
        raise ValueError('package_integrity_file')
    matches=[]
    for line in bounded_read(available[0],PACKAGE_LIMIT,deadline,ledger).decode('utf-8','strict').splitlines():
        check_deadline(deadline)
        parts=line.split(None,1)
        if len(parts)==2 and parts[1]==path.lstrip('/'):
            matches.append(parts[0])
    if matches!=[md5]:
        raise ValueError('package_integrity')
    check_deadline(deadline)
    return {'name':expected,'architecture':'amd64','version':fields[2], 'local_integrity_verified':True}


class MappedQemu:
    def __init__(self, *, process, expected_executable, deadline):
        self.process=process; self.expected=str(Path(expected_executable).resolve(strict=True)); self.deadline=deadline
        self.fds={}; self.children=[]; self.transient=[]; self.admit_attempted=False; self.original=None; self.files={}; self.failure=False; self.close_attempted=False; self.recheck_attempted=False
        self.facts={'schema_version':1,'admitted':False,'pre_stop_verified':False,'close_confirmed':False,
                    'qemu':None,'libslirp':None,'failure':False,'resident_bytes_verified':False,'source_equivalence_verified':False}

    def _identity(self):
        if time.monotonic()>=self.deadline: raise TimeoutError('deadline')
        if self.process.poll() is not None or type(self.process.pid) is not int or self.process.pid<=0:
            raise ValueError('process_not_live')
        root=Path('/proc')/str(self.process.pid)
        started=start_time(bounded_read(root/'stat',8192,self.deadline,self.transient))
        executable=os.readlink(root/'exe')
        if executable!=self.expected: raise ValueError('executable_path')
        info=os.stat(root/'exe')
        mapping=mapped_slirp(bounded_read(root/'maps',MAP_LIMIT,self.deadline,self.transient),self.deadline)
        check_deadline(self.deadline)
        if self.process.poll() is not None: raise ValueError('process_exited')
        return started,info.st_dev,info.st_ino,mapping

    def admit(self):
        try:
            if self.admit_attempted or self.close_attempted or self.failure: raise ValueError('admission_repeated')
            self.admit_attempted=True
            first=self._identity(); self.original=first
            mapping=first[3]
            for name,path,expected in (('qemu',self.expected,'qemu-system-x86'),('libslirp',mapping[0],'libslirp0')):
                fd=os.open(path,os.O_RDONLY|os.O_CLOEXEC|os.O_NOFOLLOW)
                self.fds[name]=fd
                sha,md5,sig=hash_fd(fd,self.deadline)
                if name=='qemu' and sig[:2]!=(first[1],first[2]): raise ValueError('exe_inode')
                if name=='libslirp' and (os.major(sig[0]),os.minor(sig[0]),sig[1])!=mapping[1:]: raise ValueError('library_inode')
                metadata=package(path,expected,md5,self.deadline,self.children,self.transient)
                self.files[name]=(path,sha,md5,sig)
                self.facts[name]={'sha256':sha,**metadata}
            self._backing_bracket()
            if self._identity()!=first: raise ValueError('identity_changed')
            self.facts['admitted']=True
            return True
        except Exception:
            self.failure=True; self.facts['failure']=True
            return False

    def recheck_before_stop(self):
        try:
            if not self.facts['admitted'] or self.failure or self.close_attempted or self.recheck_attempted: raise ValueError('not_admitted')
            self.recheck_attempted=True
            if self._identity()!=self.original: raise ValueError('identity_changed')
            for name,(path,sha,md5,sig) in self.files.items():
                current=os.stat(path,follow_symlinks=False)
                if signature(current)!=sig: raise ValueError('path_changed')
                if hash_fd(self.fds[name],self.deadline)!=(sha,md5,sig): raise ValueError('backing_changed')
                expected='qemu-system-x86' if name=='qemu' else 'libslirp0'
                if {'sha256':sha,**package(path,expected,md5,self.deadline,self.children,self.transient)}!=self.facts[name]: raise ValueError('package_changed')
            self._backing_bracket()
            if self._identity()!=self.original: raise ValueError('identity_changed')
            self.facts['pre_stop_verified']=True
            return True
        except Exception:
            self.failure=True; self.facts['failure']=True; self.facts['pre_stop_verified']=False
            return False

    def _backing_bracket(self):
        for name,(path,sha,md5,sig) in self.files.items():
            check_deadline(self.deadline)
            if signature(os.fstat(self.fds[name]))!=sig or signature(os.stat(path,follow_symlinks=False))!=sig:
                raise ValueError('backing_changed')
        check_deadline(self.deadline)

    def close(self, cleanup_deadline=None):
        if self.close_attempted: return self.facts['close_confirmed']
        self.close_attempted=True; clean=True
        for name in list(self.fds):
            fd=self.fds.pop(name)
            try: os.close(fd)
            except Exception: clean=False
        deadline=self.deadline if cleanup_deadline is None else cleanup_deadline
        for record in self.children:
            if not stop_process(record,deadline) or not record['stream_closed']: clean=False
        for record in self.transient:
            if record['uncertain'] or (record['fd'] is not None and not record['closed']): clean=False
        self.facts['close_confirmed']=clean
        if not clean:
            self.failure=True; self.facts['failure']=True
            RETAINED_OWNERS.append(self)
        return clean

    def snapshot(self):
        return {**self.facts, 'qemu':dict(self.facts['qemu']) if self.facts['qemu'] else None,
                'libslirp':dict(self.facts['libslirp']) if self.facts['libslirp'] else None}
