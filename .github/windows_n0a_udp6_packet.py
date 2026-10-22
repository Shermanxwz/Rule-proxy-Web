"""Pure inactive IPv6 UDP byte/manifest contract. No transport or actor actions.

Expected binding/control/cleanup/capture facts are future caller attestations;
this module does not authenticate them. Exact payloads are byte observations,
not actor attribution or valid delivery. Direct-UDP checksums, option TLV semantics and AH
authentication are NOT validated. No QPC/PCAP clock mapping or reassembly.
RFC8200 base/Hop/Destination/Routing framing and RFC4302 AH length framing only.
Hop-by-Hop must be first; Routing requires Segments Left zero. Fragment including
atomic, ESP, unknown/opaque/non-UDP headers at the fixed destination refuse
absence unless the strict trace-calibrated ND profile applies.
IPv4 and unrelated IPv6/NDP are out of scope. No jumbo/zero-length IPv6.
MAX_FRAME is a conservative support cap, not the maximum legal Ethernet frame.
https://www.rfc-editor.org/rfc/rfc8200 https://www.rfc-editor.org/rfc/rfc4302
"""
import hashlib
import json
import re
import struct

MAX_MANIFEST = 65536
MAX_PCAP = 64 * 1024 * 1024
MAX_RECORDS = 262144
MAX_SNAPLEN = 262144  # Actual producer header; not a promise to decode jumbo frames.
MAX_FRAME = 65536
MAX_EXTENSIONS = 8
MAX_EXTENSION_BYTES = 256
DESTINATION = bytes.fromhex('fec00000000000000000000000000002')
BINDING_KEYS = {'run_nonce', 'case_nonce', 'actor_sha256', 'executor_sha256',
                'actor_source_sha256', 'identity_source_sha256', 'source_commit',
                'actor_report_sha256', 'ordinary_report_sha256', 'build', 'ubr'}
ENDPOINT_KEYS = {'vm_mac', 'destination_ipv6', 'destination_port', 'scope_id'}
CAPTURE_KEYS = {'sha256', 'bytes', 'header_before_cases', 'shutdown_after_terminal',
                'fifo_eof', 'stderr_eof', 'dump_error', 'overflow', 'truncated',
                'fsynced', 'fd_closed', 'qemu_exited_orderly', 'qemu_killed',
                'sink_status', 'sink_exit_code'}
POSITIVE_CAPTURE = {'header_before_cases', 'shutdown_after_terminal', 'fifo_eof',
                    'stderr_eof', 'fsynced', 'fd_closed', 'qemu_exited_orderly'}
NEGATIVE_CAPTURE = {'dump_error', 'overflow', 'truncated', 'qemu_killed'}


def _integer(value, low, high):
    return type(value) is int and low <= value <= high


def _port(row):
    # Future producer may normalize native unavailable zero only when uninvoked.
    return (_integer(row['source_port'], 1, 65535)
            or (row['source_port'] is None and row['send_invoked'] is False))


def _hex(value, length):
    return type(value) is str and re.fullmatch('[0-9a-f]{%d}' % length, value) is not None


def _object(value, keys):
    return type(value) is dict and set(value) == keys


def _pairs(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError('manifest')
        value[key] = item
    return value


def validate_manifest(raw, expected):
    """Return private validated structure plus collision flag; never log result.

    The expected digest binds ALL flow rows, not merely self-declared hashes.
    A collision is retained separately so positive payload observations survive,
    but it always prevents an absence conclusion.
    """
    if type(raw) is not bytes or not 0 < len(raw) <= MAX_MANIFEST:
        raise ValueError('manifest')
    if not _object(expected, {'binding', 'endpoint', 'manifest_sha256', 'controls_verified', 'cleanup_verified'}):
        raise ValueError('binding')
    if any(type(expected[key]) is not bool for key in ('controls_verified', 'cleanup_verified')):
        raise ValueError('binding')
    if not _hex(expected['manifest_sha256'], 64) or hashlib.sha256(raw).hexdigest() != expected['manifest_sha256']:
        raise ValueError('binding')
    try:
        value = json.loads(raw.decode('utf-8', 'strict'), object_pairs_hook=_pairs,
                           parse_constant=lambda _: (_ for _ in ()).throw(ValueError('manifest')))
    except (ValueError, UnicodeError, RecursionError):
        raise ValueError('manifest') from None
    if not _object(value, {'schema_version', 'protocol', 'binding', 'endpoint', 'selected', 'ordinary'}) or type(value['schema_version']) is not int or value['schema_version'] != 1 or value['protocol'] != 'udp6':
        raise ValueError('manifest')
    binding = value['binding']
    if not _object(binding, BINDING_KEYS):
        raise ValueError('manifest')
    for key in BINDING_KEYS - {'build', 'ubr'}:
        size = 32 if key.endswith('nonce') else 40 if key == 'source_commit' else 64
        if not _hex(binding[key], size):
            raise ValueError('manifest')
    if type(binding['build']) is not int or binding['build'] != 26300 or type(binding['ubr']) is not int or binding['ubr'] != 9457:
        raise ValueError('manifest')
    endpoint = value['endpoint']
    if not _object(endpoint, ENDPOINT_KEYS) or not _hex(endpoint['vm_mac'], 12) or endpoint['destination_ipv6'] != 'fec0::2' or type(endpoint['scope_id']) is not int or endpoint['scope_id'] != 0 or not _integer(endpoint['destination_port'], 1025, 65535):
        raise ValueError('manifest')
    mac = bytes.fromhex(endpoint['vm_mac'])
    if mac == b'\0' * 6 or mac[0] & 1:
        raise ValueError('manifest')
    if (not _object(expected['binding'], BINDING_KEYS) or not _object(expected['endpoint'], ENDPOINT_KEYS)
            or any(type(binding[key]) is not type(expected['binding'][key]) for key in BINDING_KEYS)
            or any(type(endpoint[key]) is not type(expected['endpoint'][key]) for key in ENDPOINT_KEYS)
            or binding != expected['binding'] or endpoint != expected['endpoint']):
        raise ValueError('binding')
    selected, ordinary = value['selected'], value['ordinary']
    if type(selected) is not list or len(selected) != 3 or type(ordinary) is not list or not 3 <= len(ordinary) <= 42:
        raise ValueError('manifest')
    for index, row in enumerate(selected):
        if not _object(row, {'index', 'source_port', 'send_invoked'}) or type(row['index']) is not int or row['index'] != index or not _port(row) or type(row['send_invoked']) is not bool:
            raise ValueError('manifest')
    # Existing actor lifecycle: final after exchange is the terminal witness.
    # Samples span the QPC window; they are NOT all asserted to be inside it.
    phases = ['before'] + ['sample'] * (len(ordinary) - 2) + ['after']
    for index, (row, phase) in enumerate(zip(ordinary, phases)):
        if (not _object(row, {'phase', 'index', 'source_port', 'send_invoked', 'nonce_verified'})
                or row['phase'] != phase or type(row['index']) is not int or row['index'] != (index-1 if phase == 'sample' else 0)
                or not _port(row)
                or type(row['send_invoked']) is not bool or type(row['nonce_verified']) is not bool):
            raise ValueError('manifest')
    ports = [row['source_port'] for row in selected + ordinary if row['source_port'] is not None]
    return value, len(set(ports)) != len(ports)


def payload(nonce, phase, index):
    """Exact private native frame; caller must pass validated schema values."""
    return ('N0AU6 %s %s %d\n' % (nonce, phase, index)).encode('ascii')


def _diagnostic_new():
    return dict(v=3, opaque_next_header_counts=[0]*256, truncated_counts=[0,0,0],
                icmp_type_code_counts={}, icmp_omitted_event_count=0,
                checksum_counts=[0]*3, quote_counts=[0]*4,
                quote_detail_counts=[0]*14, raw_selected_nonce_match=set(),ndp=[0,0,0,0,0,0,0,0,0,False])


def _diagnostic_checksum(source, destination, body, protocol):
    pseudo = bytes(source)+bytes(destination)+struct.pack('!I3xB',len(body),protocol)
    data=pseudo+bytes(body)
    if len(data)%2: data+=b'\0'
    total=sum(struct.unpack('!%dH'%(len(data)//2),data))
    while total>>16: total=(total&65535)+(total>>16)
    return total==65535


def _diagnostic_icmp(diagnostic, ip, position, manifest):
    """Reached-NH58 bytes only; neither authenticity nor original delivery proof.

    Raw substring scan precedes NEW quote/checksum checks, not existing outer
    framing admission. Error Types1..4 use framing only, with no Code semantics.
    Only complete classic quotes qualify for checksum/tuple correlation.
    """
    body=bytes(ip[position:]);nonce=manifest['binding']['case_nonce']
    for row in manifest['selected']:
        if payload(nonce,'contained',row['index']) in body:
            diagnostic['raw_selected_nonce_match'].add(row['index'])
    pairs=diagnostic['icmp_type_code_counts']
    if len(body)>=2:
        pair=(body[0],body[1])
        if pair in pairs: pairs[pair]+=1
        elif len(pairs)<2: pairs[pair]=1
        else: diagnostic['icmp_omitted_event_count']+=1
    outer=2 if position!=40 or len(body)<4 else (0 if _diagnostic_checksum(ip[8:24],ip[24:40],body,58) else 1)
    diagnostic['checksum_counts'][outer]+=1
    quote_class=3;quote=body[8:]
    if position==40 and len(body)>=8 and body[0] in (1,2,3,4) and not (body[0] in (1,3) and body[4]!=0):
        if quote and quote[0]>>4!=6: quote_class=2
        elif len(quote)<40: quote_class=1
        else:
            length=int.from_bytes(quote[4:6],'big');total=40+length
            if length==0 or quote[6]!=17 or len(quote)>total: quote_class=3
            elif length<8: quote_class=2
            elif len(quote)<48: quote_class=1
            else:
                udp_length=int.from_bytes(quote[44:46],'big')
                if udp_length<8 or udp_length!=length: quote_class=2
                elif len(quote)<total: quote_class=1
                else: quote_class=0
    diagnostic['quote_counts'][quote_class]+=1
    if quote_class!=0:return
    detail=diagnostic['quote_detail_counts'];udp=quote[40:]
    inner=0 if int.from_bytes(udp[6:8],'big')!=0 and _diagnostic_checksum(quote[8:24],quote[24:40],udp,17) else 1
    detail[inner]+=1
    matches=[]
    for selected,rows in ((True,manifest['selected']),(False,manifest['ordinary'])):
        for row in rows:
            phase='contained' if selected else row['phase']
            if bytes(udp[8:])==payload(nonce,phase,row['index']):matches.append((selected,row))
    kind=3 if matches and matches[0][0] else 4 if matches else 5
    detail[kind]+=1
    source,destination=struct.unpack_from('!HH',udp);port=manifest['endpoint']['destination_port']
    ports=[r['source_port'] for r in manifest['selected']+manifest['ordinary'] if r['source_port'] is not None]
    tuple_kind=8
    if matches:
        row=matches[0][1];local=row['source_port']
        # Conservative fixture correlation, not universal UDP address/port validity.
        guest=bytes(ip[8:24])
        ambiguous_source=(guest in (b'\0'*16,b'\0'*15+b'\1') or guest[0]==255
                          or guest[:12]==b'\0'*10+b'\xff\xff' or guest==DESTINATION)
        if len(matches)!=1 or local is None or local==port or ambiguous_source or len(set(ports))!=len(ports):tuple_kind=9
        elif quote[8:24]==ip[8:24] and quote[24:40]==DESTINATION and source==local and destination==port:tuple_kind=6
        elif quote[24:40]==ip[8:24] and quote[8:24]==DESTINATION and destination==local and source==port:tuple_kind=7
    detail[tuple_kind]+=1
    relation=ip[24:40]==quote[8:24]
    detail[10 if relation else 11]+=1
    if outer==0 and inner==0 and kind in (3,4) and tuple_kind in (6,7) and relation:
        detail[12 if kind==3 else 13]+=1


def _nd_usable(address):
    return (address not in (b'\0'*16,b'\0'*15+b'\1',DESTINATION)
            and address[0]!=255 and address[:12]!=b'\0'*10+b'\xff\xff')


def _nd_witness(data,manifest):
    """First sequential pass; fixed row map, no frame retention or capture copy."""
    state=dict(bits=0,exact=0,valid=0,invalid=0,source=None,source_state=0,ready=False)
    rows={payload(manifest['binding']['case_nonce'],r['phase'],r['index']):r for r in manifest['ordinary']}
    seen={};mac=bytes.fromhex(manifest['endpoint']['vm_mac']);port=manifest['endpoint']['destination_port']
    ports=[r['source_port'] for r in manifest['ordinary']+manifest['selected']]
    if None in ports or len(set(ports))!=len(ports):state['bits']|=1<<17
    if not all(r['send_invoked'] and r['nonce_verified'] for r in manifest['ordinary']):state['bits']|=1<<13
    if type(data)is not bytes or len(data)>MAX_PCAP or len(data)<24:
        state['bits']|=1<<18;return state
    formats={b'\xd4\xc3\xb2\xa1':('<',1000000),b'\xa1\xb2\xc3\xd4':('>',1000000),
             b'\x4d\x3c\xb2\xa1':('<',1000000000),b'\xa1\xb2\x3c\x4d':('>',1000000000)}
    if data[:4] not in formats:state['bits']|=1<<18;return state
    endian,scale=formats[data[:4]]
    major,minor,_,_,snaplen,link=struct.unpack_from(endian+'HHIIII',data,4)
    if (major,minor)!=(2,4) or not 1<=snaplen<=MAX_SNAPLEN or link!=1:
        state['bits']|=1<<18;return state
    view=memoryview(data);offset=24;records=0
    while offset<len(view):
        if records>=MAX_RECORDS or len(view)-offset<16:state['bits']|=1<<18;break
        _,fraction,captured,original=struct.unpack_from(endian+'IIII',view,offset);offset+=16
        if fraction>=scale or captured>snaplen or captured>original or captured>MAX_FRAME or len(view)-offset<captured:
            state['bits']|=1<<18;break
        if captured!=original:state['bits']|=1<<18
        frame=view[offset:offset+captured];offset+=captured;records+=1
        if len(frame)<14:state['bits']|=1<<18;continue
        if frame[6:12]!=mac:continue
        ether=int.from_bytes(frame[12:14],'big')
        if ether in (0x0800,0x0806):continue
        if ether!=0x86dd:state['bits']|=1<<18;continue
        ip=frame[14:]
        if len(ip)<40 or ip[0]>>4!=6 or int.from_bytes(ip[4:6],'big')==0 or len(ip)!=40+int.from_bytes(ip[4:6],'big'):
            state['bits']|=1<<18;continue
        if ip[24:40]!=DESTINATION:continue
        # A relevant non-direct layout cannot be a checksum-qualified witness;
        # do not hide an exact duplicate behind extensions from permanent taint.
        if ip[6] in (0,43,60,51,44,50):state['bits']|=1<<0
        if ip[6]!=17:continue
        udp=ip[40:]
        if len(udp)<8 or int.from_bytes(udp[4:6],'big')!=len(udp):state['bits']|=1<<18;continue
        if int.from_bytes(udp[2:4],'big')!=port:continue
        row=rows.get(bytes(udp[8:]))
        if row is None or int.from_bytes(udp[:2],'big')!=row['source_port']:continue
        state['exact']+=1;address=bytes(ip[8:24])
        if not _nd_usable(address):state['bits']|=1<<16
        elif state['source'] is None:state['source']=address;state['source_state']=1
        elif address!=state['source']:state['source_state']=2;state['bits']|=1<<15
        if int.from_bytes(udp[6:8],'big')!=0 and _diagnostic_checksum(ip[8:24],ip[24:40],udp,17):
            state['valid']+=1;seen.setdefault((row['phase'],row['index']),records)
        else:state['invalid']+=1;state['bits']|=1<<14
    indices=[seen.get((r['phase'],r['index'])) for r in manifest['ordinary']]
    if not all(type(i)is int for i in indices) or (all(type(i)is int for i in indices) and indices[-1]<=max(indices[:-1])):
        state['bits']|=1<<13
    if state['source_state']!=1:state['bits']|=1<<13
    state['ready']=not state['bits']
    return state


def _nd_profile(diagnostic,frame,ip,position,manifest,witness):
    """Strict fixture ND exception, not general RFC validity or OS ownership."""
    body=ip[position:];ndp=diagnostic['ndp']
    shared=manifest['binding']['case_nonce'].encode('ascii') in bytes(frame)
    if len(body)<1 or body[0] not in (135,136):return False
    if shared:ndp[9]=True
    bits=witness['bits'];rejected=False;kind=int(body[0])
    if position!=40:bits|=1<<0
    if len(body)<24:bits|=1<<1;rejected=True
    if ip[7]!=255:bits|=1<<2;rejected=True
    if len(body)>=2 and body[1]!=0:bits|=1<<3;rejected=True
    if position==40:
        if len(body)<4 or not _diagnostic_checksum(ip[8:24],ip[24:40],body,58):bits|=1<<4;rejected=True
    # Raw exact frame and shared nonce observations precede qualification.
    if any(payload(manifest['binding']['case_nonce'],'contained',r['index']) in bytes(body) for r in manifest['selected']):bits|=1<<11
    if shared:bits|=1<<12
    if len(body)>=24:
        target=bytes(body[8:24]);source=bytes(ip[8:24]);guest=witness['source']
        if target[0]==255 or (kind==135 and source==b'\0'*16):bits|=1<<5;rejected=True
        if kind==135:
            if source!=guest or target!=DESTINATION:bits|=1<<6
            if bytes(body[4:8])!=b'\0'*4:bits|=1<<7
        else:
            if source!=guest or target!=guest:bits|=1<<6
            flags=int.from_bytes(body[4:8],'big')
            if flags&0x80000000 or not flags&0x40000000 or flags&0x1fffffff:bits|=1<<7
        # Parse framing before rejecting otherwise legal but unsupported options.
        cursor=24;options=0
        while cursor<len(body):
            if len(body)-cursor<2 or body[cursor+1]==0 or cursor+int(body[cursor+1])*8>len(body):
                bits|=1<<8;rejected=True;break
            size=int(body[cursor+1])*8;options+=1
            if options!=1 or size!=8 or body[cursor]!=(1 if kind==135 else 2):bits|=1<<9
            elif body[cursor+2:cursor+8]!=bytes.fromhex(manifest['endpoint']['vm_mac']):bits|=1<<10
            cursor+=size
        if len(body) not in (24,32):bits|=1<<9
    ndp[4]|=bits
    if rejected:ndp[2]+=1;return False
    if bits:ndp[3]+=1;return False
    ndp[0 if kind==135 else 1]+=1
    return True


def decode_pcap(data, manifest):
    """Bounded byte observation, not delivery or authenticated actor attribution.

    ARP/IPv4/unrelated IPv6 destinations are outside this runner-IPv6-UDP scope.
    Guest unsupported encapsulation and relevant fragments prevent absence.
    Exact selected payload on a wrong port survives as an unbound observation.
    """
    result = dict(selected_seen=set(), selected_bound=set(), ordinary_first={},
                  unknown_packets=0, records=0, reasons=set(),
                  decoder_diagnostic=_diagnostic_new())
    # Diagnostic only: exact public Next Header enum counts; truncation order is
    # header_tail, captured_ne_original, body_tail. Counters do not admit frames;
    # only the explicit strict ND profile return can exempt its own opaque event.
    diagnostic = result['decoder_diagnostic']
    witness = _nd_witness(data,manifest)
    diagnostic['ndp'][4:9]=[witness['bits'],witness['exact'],witness['valid'],witness['invalid'],witness['source_state']]
    def bad(reason): result['reasons'].add(reason)
    if type(data) is not bytes or len(data) > MAX_PCAP:
        bad('capture_bound'); return result
    if len(data) < 24:
        bad('header'); return result
    formats = {b'\xd4\xc3\xb2\xa1': ('<', 1000000), b'\xa1\xb2\xc3\xd4': ('>', 1000000),
               b'\x4d\x3c\xb2\xa1': ('<', 1000000000), b'\xa1\xb2\x3c\x4d': ('>', 1000000000)}
    if data[:4] not in formats:
        bad('header'); return result
    endian, scale = formats[data[:4]]
    major, minor, _, _, snaplen, link = struct.unpack_from(endian+'HHIIII', data, 4)
    if (major, minor) != (2, 4) or not 1 <= snaplen <= MAX_SNAPLEN or link != 1:
        bad('header'); return result
    endpoint = manifest['endpoint']; nonce = manifest['binding']['case_nonce']
    mac = bytes.fromhex(endpoint['vm_mac'])
    selected = {payload(nonce,'contained',r['index']): r for r in manifest['selected']}
    ordinary = {payload(nonce,r['phase'],r['index']): r for r in manifest['ordinary']}
    ports = {r['source_port'] for r in manifest['selected']+manifest['ordinary'] if r['source_port'] is not None}
    view = memoryview(data); offset = 24
    while offset < len(data):
        if result['records'] >= MAX_RECORDS:
            bad('record_bound'); break
        if len(data)-offset < 16:
            diagnostic['truncated_counts'][0] += 1
            bad('truncated'); break
        _, fraction, captured, original = struct.unpack_from(endian+'IIII',data,offset)
        offset += 16
        if fraction >= scale or captured > snaplen or captured > original:
            bad('record'); break
        if captured != original:
            diagnostic['truncated_counts'][1] += 1
            bad('truncated')
        if captured > MAX_FRAME:
            bad('frame_bound'); break
        if len(data)-offset < captured:
            diagnostic['truncated_counts'][2] += 1
            bad('truncated'); break
        frame=view[offset:offset+captured]; offset+=captured; result['records']+=1
        if len(frame)<14:
            bad('ethernet'); continue
        if frame[6:12] != mac: continue
        ether=int.from_bytes(frame[12:14],'big')
        if ether in (0x0806,0x0800): continue
        if ether != 0x86dd:
            bad('encapsulation'); continue
        ip=frame[14:]
        if len(ip)<40 or ip[0]>>4 != 6:
            bad('ipv6'); continue
        length=int.from_bytes(ip[4:6],'big')
        if length==0:
            bad('jumbo_unsupported'); continue
        total=40+length
        if total!=len(ip):
            bad('ipv6'); continue
        if ip[24:40]!=DESTINATION: continue
        next_header=ip[6];position=40;extension_count=0;extension_bytes=0;unsupported=False
        while next_header!=17:
            if next_header==44:
                bad('fragment');unsupported=True;break
            if next_header not in (0,43,60,51):
                diagnostic['opaque_next_header_counts'][next_header] += 1
                if next_header==58:
                    _diagnostic_icmp(diagnostic, ip, position, manifest)
                    if _nd_profile(diagnostic,frame,ip,position,manifest,witness):unsupported=True;break
                bad('opaque_protocol');unsupported=True;break
            if extension_count>=MAX_EXTENSIONS:
                bad('extension_bound');unsupported=True;break
            if next_header==0 and position!=40:
                bad('hop_order');unsupported=True;break
            if total-position<2:
                bad('extension');unsupported=True;break
            size=(int(ip[position+1])+2)*4 if next_header==51 else (int(ip[position+1])+1)*8
            if size<(12 if next_header==51 else 8) or position+size>total:
                bad('extension');unsupported=True;break
            if extension_bytes+size>MAX_EXTENSION_BYTES:
                bad('extension_bound');unsupported=True;break
            if next_header==43 and ip[position+3]!=0:
                bad('routing_unsupported');unsupported=True;break
            next_header=ip[position];position+=size;extension_count+=1;extension_bytes+=size
        if unsupported: continue
        udp=ip[position:total]
        if len(udp)<8:
            bad('udp'); continue
        source,destination,length,_=struct.unpack_from('!HHHH',udp)
        if destination != endpoint['destination_port']: continue
        if length<8 or length!=len(udp):
            bad('udp'); continue
        body=bytes(udp[8:])
        if body in selected:
            row=selected[body]; result['selected_seen'].add(row['index'])
            if source==row['source_port']: result['selected_bound'].add(row['index'])
            else: bad('payload_port_mismatch')
        elif body in ordinary and source==ordinary[body]['source_port']:
            result['ordinary_first'].setdefault((ordinary[body]['phase'],ordinary[body]['index']),result['records'])
        else:
            bad('payload_mismatch')
        if source not in ports:
            result['unknown_packets']+=1; bad('unknown_flow')
    if not result['records']: bad('empty')
    return result


def project_decoder_diagnostic(value, records):
    """Closed v2 diagnostic only; all verdicts ignore these counters."""
    if not _object(value,set(_diagnostic_new())) or type(value['v']) is not int or value['v']!=3 or not _integer(records,0,MAX_RECORDS):return None
    counts=value['opaque_next_header_counts'];truncated=value['truncated_counts']
    if type(counts)is not list or len(counts)!=256 or any(not _integer(n,0,MAX_RECORDS) for n in counts) or sum(counts)>records:return None
    if type(truncated)is not list or len(truncated)!=3 or not _integer(truncated[0],0,1) or not _integer(truncated[2],0,1) or not _integer(truncated[1],0,min(MAX_RECORDS,records+1)):return None
    pairs=value['icmp_type_code_counts'];omitted=value['icmp_omitted_event_count'];events=counts[58]
    if type(pairs)is not dict or len(pairs)>2 or not _integer(omitted,0,events):return None
    if any(type(k)is not tuple or len(k)!=2 or any(not _integer(n,0,255) for n in k) or not _integer(v,1,events) for k,v in pairs.items()):return None
    if sum(pairs.values())+omitted>events or (omitted and len(pairs)!=2):return None
    arrays=[]
    for key,size in (('checksum_counts',3),('quote_counts',4),('quote_detail_counts',14)):
        row=value[key]
        if type(row)is not list or len(row)!=size or any(not _integer(n,0,events) for n in row):return None
        arrays.append(row)
    checksum,quote,detail=arrays
    if sum(checksum)!=events or sum(quote)!=events:return None
    if any(sum(detail[a:b])!=quote[0] for a,b in ((0,3),(3,6),(6,10),(10,12))):return None
    if sum(detail[12:])>min(quote[0],checksum[0],detail[0],detail[6]+detail[7],detail[10]) or detail[12]>detail[3] or detail[13]>detail[4]:return None
    raw=value['raw_selected_nonce_match']
    if type(raw)is not set or any(not _integer(n,0,2) for n in raw) or (raw and not events):return None
    ndp=value['ndp']
    if (type(ndp)is not list or len(ndp)!=10 or any(not _integer(n,0,events) for n in ndp[:4])
            or sum(ndp[:4])>events or not _integer(ndp[4],0,0x7ffff)
            or any(not _integer(n,0,records) for n in ndp[5:8]) or ndp[6]+ndp[7]!=ndp[5]
            or not _integer(ndp[8],0,2) or type(ndp[9])is not bool):return None
    if sum(ndp[:2]) and (ndp[4]&0x7e001 or ndp[7]!=0 or ndp[6]==0 or ndp[8]!=1):return None
    nonzero=[[n,c] for n,c in enumerate(counts) if c];omitted_nh=nonzero[2:]
    return dict(v=3,opaque_next_header_counts=nonzero[:2],omitted_category_count=len(omitted_nh),
                omitted_event_count=sum(r[1] for r in omitted_nh),detail_complete=not omitted_nh,
                truncated_counts=list(truncated),icmp_type_code_counts=[[a,b,c] for (a,b),c in sorted(pairs.items())],
                icmp_omitted_event_count=omitted,icmp_detail_complete=not omitted,
                checksum_counts=list(checksum),quote_counts=list(quote),quote_detail_counts=list(detail),
                raw_selected_nonce_match=[bool(raw),len(raw)],ndp=list(ndp))


def evaluate(data, manifest_bytes, expected, capture):
    """Pure future-controller contract. No caller authentication is created here."""
    public=dict(schema_version=2,protocol='udp6',scope='runner_ipv6_udp_payload',status='inconclusive',manifest_valid=False,
                binding_contract_matched=False,ports_unique=False,
                controls_contract=False,cleanup_contract=False,all_selected_sends_invoked=False,
                ports_complete=False,
                capture_complete_contract=False,decoder_complete=False,ordinary_payload_controls=False,
                selected_payload_observed=None,selected_bound_payload_observed=None,
                selected_payload_count=0,unknown_flow_packets=0,records=0,reasons=[],
                decoder_diagnostic=None,
                bounded_no_selected_udp_datagram=False,actor_attribution_established=False,
                isolation_acceptance=False,checksums_validated=False,qpc_timestamp_mapping_used=False)
    try: manifest,collision=validate_manifest(manifest_bytes,expected)
    except ValueError as error:
        public['reasons']=['binding' if str(error)=='binding' else 'manifest']; return public
    public['manifest_valid']=public['binding_contract_matched']=True
    public['ports_unique']=not collision
    public['ports_complete']=all(r['source_port'] is not None for r in manifest['selected']+manifest['ordinary'])
    public['controls_contract']=expected['controls_verified']
    public['cleanup_contract']=expected['cleanup_verified']
    public['all_selected_sends_invoked']=all(r['send_invoked'] for r in manifest['selected'])
    decoded=decode_pcap(data,manifest); reasons=decoded['reasons']
    public['decoder_diagnostic']=project_decoder_diagnostic(decoded['decoder_diagnostic'], decoded['records'])
    public['decoder_complete']=not reasons
    public['selected_payload_observed']=bool(decoded['selected_seen'])
    public['selected_bound_payload_observed']=bool(decoded['selected_bound'])
    public['selected_payload_count']=len(decoded['selected_seen'])
    public['unknown_flow_packets']=decoded['unknown_packets'];public['records']=decoded['records']
    if collision: reasons.add('port_collision')
    if not public['ports_complete']: reasons.add('port_unavailable')
    if not expected['controls_verified']: reasons.add('controls')
    if not expected['cleanup_verified']: reasons.add('cleanup')
    if not public['all_selected_sends_invoked']: reasons.add('send_unattempted')
    capture_ok=(_object(capture,CAPTURE_KEYS) and type(data) is bytes and len(data)<=MAX_PCAP
                and _hex(capture.get('sha256'),64) and capture['sha256']==hashlib.sha256(data).hexdigest()
                and _integer(capture.get('bytes'),24,MAX_PCAP) and capture['bytes']==len(data)
                and all(capture[k] is True for k in POSITIVE_CAPTURE)
                and all(capture[k] is False for k in NEGATIVE_CAPTURE)
                and type(capture['sink_status']) is str and capture['sink_status']=='complete'
                and type(capture['sink_exit_code']) is int and capture['sink_exit_code']==0)
    public['capture_complete_contract']=capture_ok
    if not capture_ok: reasons.add('capture_lifecycle')
    indices=[decoded['ordinary_first'].get((r['phase'],r['index'])) for r in manifest['ordinary']]
    controls=(all(type(i) is int for i in indices) and indices[-1]>max(indices[:-1])
              and all(r['send_invoked'] and r['nonce_verified'] for r in manifest['ordinary']))
    public['ordinary_payload_controls']=controls
    if not controls: reasons.add('ordinary_payload')
    if not reasons:
        if public['selected_payload_observed']: public['status']='selected_payload_observed'
        else:
            public['status']='bounded_no_selected_udp_datagram'
            public['bounded_no_selected_udp_datagram']=True
    public['reasons']=sorted(reasons)
    return public
