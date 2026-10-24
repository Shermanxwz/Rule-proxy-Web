"""Pure, source-bound physical validation of A5 parent memory receipts.

The pinned core is supplied by the caller. This module acquires no API/library,
clock, process or target. Failed/late raw returns remain valid partial evidence;
only the complete original physical graph can establish a positive fact.
"""
from pathlib import Path
import re
import struct

U64 = (1 << 64)-1
RAW_KEYS = {'operation','returned','value','error_captured','failure_error_valid',
            'error','exception','fields','raw_bytes','raw_sha256'}


def validate_memory_records(m,j,c,root,selected):
    require=m.require
    root=Path(root)
    empty=dict(base=None,memory_complete=False,payload_pointer=False,payload_readonly=False,config=None)
    config_sha=m.sha(m.encode(c))
    def integer(value,low=0,high=U64):
        return type(value) is int and low<=value<=high
    def same_scope(value):
        require(type(value) is dict and type(value.get('schema_version')) is int and value['schema_version']==1
            and value.get('scope')==m.SCOPE and value.get('run')==c['run']
            and value.get('config_sha256')==config_sha,'a5_mem_scope')
    def physical(descriptor,directory,name):
        require(type(descriptor) is dict and set(descriptor)=={'name','text','sha256'}
            and descriptor['name']==name and type(descriptor['text']) is str
            and len(descriptor['text'])<=m.MAX_REPORT and m.base.ac.digest(descriptor['sha256']),'a5_mem_record')
        raw=descriptor['text'].encode('ascii')
        require(m.sha(raw)==descriptor['sha256'] and m.local.bounded(
            m.launcher.checked_path(root/directory/name,inside=root),m.MAX_REPORT)==raw,'a5_mem_physical')
        value=m.decode(raw);same_scope(value);return value
    roots={};intents={}
    for directory,key in (('journal','intents'),('returns','returns')):
        rows=j[key];require(type(rows) is list and len(rows)<=256,'a5_mem_root_bound')
        for index,descriptor in enumerate(rows):
            require(type(descriptor) is dict and type(descriptor.get('name')) is str
                and re.fullmatch(r'[0-9]{3}-[a-z0-9-]{1,64}\.json',descriptor['name']),'a5_mem_root_name')
            value=physical(descriptor,directory,descriptor['name'])
            require(descriptor['name']=='%03d-%s.json'%(index,value['action'])
                and integer(value.get('qpc')),'a5_mem_root_index')
            table=intents if key=='intents' else roots
            require(descriptor['sha256'] not in table,'a5_mem_duplicate_root')
            table[descriptor['sha256']]=(descriptor,value)
    for action in ('base-probe','memory-sequence','config-carrier'):
        require(sum(v['action']==action for _,v in roots.values())<=1
            and sum(v['action']==action for _,v in intents.values())<=1,'a5_mem_root_once')
    def root_return(descriptor,action):
        require(type(descriptor) is dict and descriptor.get('sha256') in roots
            and roots[descriptor['sha256']][0]==descriptor,'a5_mem_return_member')
        value=roots[descriptor['sha256']][1]
        require(set(value)=={'schema_version','scope','run','config_sha256','intent_sha256','action','qpc','data'}
            and value['action']==action and value['intent_sha256'] in intents,'a5_mem_return_action')
        intent=intents[value['intent_sha256']][1]
        require(intent['action']==action and integer(intent['qpc']) and intent['qpc']<=value['qpc'],'a5_mem_return_intent')
        return value,intent
    rows=j['memory_records']
    require(type(rows) is list and len(rows)<=128,'a5_mem_bound')
    api_rows=j['api_calls'];api_intents=j['api_intents']
    require(type(api_rows) is list and len(api_rows)<=128 and type(api_intents) is list and len(api_intents)<=128,'a5_mem_api_bound')
    # Only the two API operations this validator consumes are interpreted here.
    # The task/resource validator owns the other parent API records.
    apis={}
    for index,descriptor in enumerate(api_rows):
        value=physical(descriptor,'api-calls','%03d-return.json'%index)
        require(set(value)=={'schema_version','scope','run','config_sha256','index','call','output'}
            and type(value['index']) is int and value['index']==index and type(value['call']) is dict,'a5_mem_API_wrapper')
        call=value['call'];operation=call.get('operation')
        if operation not in ('NtQueryInformationProcess(PBI48)','a5_copy_config_v1'):continue
        require(operation not in apis,'a5_mem_API_once')
        required={'operation','arguments','deadline_qpc','admission_known','entered_qpc','entered','returned','raw_return','error','error_captured',
            'native_exception','error_exception','outputs','output_error','post_call_qpc','clock_known','timely','clock_error',
            'intent_sha256','output_bytes','output_sha256'}
        require(required<=set(call)<=required|{'adoption_failed'} and call['entered'] is True
            and all(type(call[k]) is bool for k in ('admission_known','returned','error_captured','clock_known','timely'))
            and (integer(call['error'],0,0xffffffff) if call['error_captured'] else call['error'] is None)
            and all(call[k] is None or type(call[k]) is str for k in ('native_exception','error_exception','output_error','clock_error'))
            and type(call['arguments']) is dict,'a5_mem_API_shape')
        raw=m.read_binary(root,value['output'],4096)
        require(value['output']['name']=='api-%03d.bin'%index
            and call.get('output_bytes')==len(raw) and call.get('output_sha256')==m.sha(raw),'a5_mem_API_raw')
        matches=[]
        for n,entry in enumerate(api_intents):
            if entry['sha256']==call.get('intent_sha256'):
                intent=physical(entry,'api-calls','%03d-intent.json'%n)
                require(set(intent)=={'schema_version','scope','run','config_sha256','index','operation','arguments','qpc'}
                    and intent['index']==n and intent['operation']==operation and intent['arguments']==call['arguments'],'a5_mem_API_intent')
                matches.append(intent)
        require(len(matches)==1,'a5_mem_API_intent_once')
        apis[operation]=(call,raw,matches[0])
    if selected is None or j['window'] is None:
        require(not rows and not apis and all(j[k] is None for k in ('base_provenance','memory_summary','payload','config_binary')),'a5_mem_no_selected')
        return empty
    window=j['window'];require(type(window) is dict and set(window)=={'start','end'},'a5_mem_window')
    start,end=window['start'],window['end'];f=c['frequency']
    require(integer(start,c['start_qpc'],m.work_cutoff(c)-1) and type(end) is int
        and end==min(start+8*f,m.work_cutoff(c)) and start<end,'a5_mem_original_window')
    epoch=dict(frequency=f,root_start=c['start_qpc'],root_deadline=c['root_deadline_qpc'],
        work_deadline=m.work_cutoff(c),window_start=start,window_end=end)
    pi_return,_=root_return(selected['receipt'],'create-selected')
    pi=pi_return['data']['raw_pi']
    require(type(pi) is list and len(pi)==4 and integer(pi[0],1,U64-1)
        and pi[2]==selected['pid'] and integer(selected['created'],1),'a5_mem_process')
    process=pi[0]
    for operation,action in (('NtQueryInformationProcess(PBI48)','base-probe'),('a5_copy_config_v1','config-carrier')):
        if operation not in apis:continue
        call,raw,api_intent=apis[operation]
        matches=[value for _,value in intents.values() if value['action']==action]
        require(len(matches)==1 and integer(matches[0]['qpc'],start,end-1)
            and integer(api_intent['qpc'],start,end-1) and integer(call['entered_qpc'],start,end-1)
            and matches[0]['qpc']<=api_intent['qpc']<=call['entered_qpc'] and call['deadline_qpc']==end,'a5_mem_API_outer_intent')
    bindings=dict(run=c['run'],source_sha256=c['source_sha256'],config_sha256=config_sha,
        plan_sha256=c['recovery_plan_sha256'],pi_returned_sha256=selected['receipt']['sha256'],
        base_provenance_sha256=j['base_provenance']['sha256'] if j['base_provenance'] is not None else None)
    image=m.local.bounded(m.launcher.checked_path(Path(c['curl_path'])),8*1024*1024)
    require(len(image)==c['artifacts']['curl']['bytes'] and m.sha(image)==c['artifacts']['curl']['sha256'],'a5_mem_fixed_image')
    pe=m.builder.verify_fixed_pe(image)
    private_path=str(m.artifact_paths(root)['shim'])
    def mapped_before(base):
        # Independent physical reader: fixed disk header plus the exact PEB-
        # bound ImageBase value observed before any allowed import mutation.
        header=bytearray(pe.header)
        struct.pack_into('<Q',header,304,base)
        return bytes(header)
    def in_window(value):return integer(value,start,end-1)
    def api_good(value):
        call,raw,intent=value
        return (call.get('admission_known') is True and call.get('entered') is True and call.get('returned') is True and call.get('error_captured') is True
            and integer(call.get('error'),0,0xffffffff) and call.get('native_exception') is None
            and call.get('error_exception') is None and call.get('output_error') is None
            and call.get('clock_error') is None and not call.get('adoption_failed',False)
            and call.get('deadline_qpc')==end and call.get('clock_known') is True and call.get('timely') is True
            and in_window(intent.get('qpc')) and in_window(call.get('entered_qpc')) and in_window(call.get('post_call_qpc'))
            and intent['qpc']<=call['entered_qpc']<=call['post_call_qpc'])
    def mbi(raw):
        return {key:struct.unpack_from(fmt,raw,at)[0] for key,at,fmt in (
            ('base',0,'<Q'),('allocation_base',8,'<Q'),('allocation_protect',16,'<I'),
            ('partition_id',20,'<H'),('region_bytes',24,'<Q'),('state',32,'<I'),('protect',36,'<I'),('type',40,'<I'))}
    def raw_validate(raw,data,operation,size):
        require(type(raw) is dict and set(raw)==RAW_KEYS and raw['operation']==operation
            and all(type(raw[k]) is bool for k in ('returned','error_captured','failure_error_valid'))
            and (raw['value'] is None or integer(raw['value'],-(1<<31)))
            and (raw['exception'] is None or type(raw['exception']) is str and len(raw['exception'])<=128)
            and type(raw['fields']) is dict,'a5_mem_Raw_shape')
        require((integer(raw['error'],0,0xffffffff) if raw['error_captured'] else raw['error'] is None)
            and raw['raw_bytes']==len(data) and raw['raw_sha256']==m.sha(data)
            and raw['failure_error_valid']==(raw['returned'] and raw['exception'] is None
                and raw['error_captured'] and raw['value']==0),'a5_mem_Raw_binding')
        fields=raw['fields']
        if operation=='query':require(len(data)==48 and fields==mbi(data),'a5_mem_MBI48')
        elif operation in ('read','write'):
            require(set(fields)=={'transferred'} and integer(fields['transferred'])
                and len(data)==(size if operation=='read' else 0),'a5_mem_transfer_fields')
        elif operation=='protect':require(set(fields)=={'old_protect'} and integer(fields['old_protect'],0,0xffffffff) and not data,'a5_mem_old_protect')
        else:require(operation=='allocate' and not fields and not data,'a5_mem_allocation_raw')
        return (raw['returned'] and raw['exception'] is None and raw['error_captured'] and type(raw['value']) is int
            and (raw['value']==48 if operation=='query' else raw['value']!=0)
            and (fields['transferred']==size if operation in ('read','write') else True))
    def timing(record,intent_qpc):
        require(in_window(record['entered_qpc']) and record['entered_qpc']>=intent_qpc
            and type(record['return_clock_known']) is bool and type(record['timely']) is bool
            and (record['clock_error'] is None or type(record['clock_error']) is str),'a5_mem_clock_shape')
        if record['return_clock_known']:
            require(integer(record['returned_qpc']) and record['clock_error'] is None,'a5_mem_known_clock')
            timely=record['entered_qpc']<=record['returned_qpc']<end
        else:
            require(record['returned_qpc'] is None and type(record['clock_error']) is str,'a5_mem_unknown_clock')
            timely=False
        require(record['timely']==timely,'a5_mem_timely_raw')
        return timely
    probes=[];calls=[];pending=None;gate_rows=[];mutation=None;last=start;coordinator_last=start;positions={}
    memory_events=[]
    for index,descriptor in enumerate(rows):
        value=physical(descriptor,'memory','%03d.json'%index)
        require(set(value)=={'schema_version','scope','run','config_sha256','index','record','output'}
            and type(value['index']) is int and value['index']==index,'a5_mem_wrapper')
        record=value['record'];data=m.read_binary(root,value['output'],4096)
        require(value['output']['name']=='memory-%03d.bin'%index and type(record) is dict,'a5_mem_binary_index')
        kind=record.get('kind');reference=descriptor['sha256']
        require(reference not in positions,'a5_mem_duplicate')
        positions[reference]=index
        if kind in ('a4-probe-intent','a4-probe-return'):
            if kind=='a4-probe-intent':
                require(pending is None and not data and set(record)=={'kind','operation','arguments','qpc'}
                    and record['operation'] in ('read','query','protect') and in_window(record['qpc'])
                    and record['qpc']>=last,'a5_probe_intent')
                pending=('probe',reference,record);last=record['qpc']
            else:
                require(pending is not None and pending[0]=='probe' and record['intent_sha256']==pending[1]
                    and set(record)=={'kind','operation','arguments','intent_sha256','entered_qpc','raw','returned_qpc','return_clock_known','timely','clock_error'}
                    and record['operation']==pending[2]['operation'] and record['arguments']==pending[2]['arguments'],'a5_probe_return')
                args=record['arguments'];require(type(args) is dict and set(args)=={'process','address','bytes','argument'}
                    and args['process']==process and integer(args['address'],1) and integer(args['bytes'],1,4096),'a5_probe_arguments')
                good=raw_validate(record['raw'],data,record['operation'],args['bytes'])
                good=timing(record,pending[2]['qpc']) and good
                probes.append(dict(record=record,data=data,sha256=reference,intent=pending[2],good=good))
                last=record['returned_qpc'] if record['return_clock_known'] else last;pending=None
            continue
        common={'schema_version','scope','bindings','epoch'}
        require(type(record.get('schema_version')) is int and record['schema_version']==1 and record.get('scope')=='A5-fixed-two-descriptor-memory-v1'
            and record.get('epoch')==epoch and record.get('bindings')==bindings
            and bindings['base_provenance_sha256'] is not None,'a5_memory_context')
        memory_events.append((kind,reference))
        if kind=='memory-call-intent':
            require(pending is None and not data and set(record)==common|{'kind','index','operation','arguments','qpc',
                'input_sha256' if record.get('operation')=='write' else 'argument'}
                and type(record['index']) is int and record['index']==len(calls)
                and record['operation'] in ('allocate','query','read','write','protect')
                and in_window(record['qpc']) and record['qpc']>=last,'a5_memory_intent')
            pending=('memory',reference,record);last=record['qpc']
        elif kind=='memory-call-return':
            require(pending is not None and pending[0]=='memory' and record['intent_sha256']==pending[1]
                and set(record)==common|{'kind','index','intent_sha256','entered_qpc','returned_qpc','return_clock_known','timely','clock_error','raw'}
                and record['index']==len(calls),'a5_memory_return')
            intent=pending[2];operation=intent['operation'];args=intent['arguments']
            require(type(args) is dict and args.get('process')==process and integer(args.get('address'),1)
                and integer(args.get('bytes'),1,4096),'a5_memory_arguments')
            good=raw_validate(record['raw'],data,operation,args['bytes'])
            good=timing(record,intent['qpc']) and good
            calls.append(dict(record=record,data=data,intent=intent,sha256=reference,good=good))
            last=record['returned_qpc'] if record['return_clock_known'] else last;pending=None
        elif kind=='external-held-gate':
            require(pending is None and not data and set(record)==common|{'kind','label','gate_sha256','before_qpc','after_qpc'}
                and record['label'] in ('before-memory','after-publication')
                and [x[0]['label'] for x in gate_rows]==([] if record['label']=='before-memory' else ['before-memory'])
                and in_window(record['before_qpc']) and in_window(record['after_qpc'])
                and last<=record['before_qpc']<=record['after_qpc'],'a5_memory_gate_clock')
            require(record['gate_sha256'] in roots,'a5_memory_gate_physical')
            gate,gate_intent=root_return(roots[record['gate_sha256']][0],'memory-held-'+record['label'])
            require(gate['data'] in selected['held_checks'] and record['before_qpc']<=gate_intent['qpc']
                <=gate['data']['qpc']<=gate['qpc']<=record['after_qpc'],'a5_memory_gate_binding')
            gate_rows.append((record,reference));last=record['after_qpc']
        elif kind=='remote-mutation-intent':
            require(pending is None and mutation is None and len(calls)==6
                and set(record)==common|{'kind','qpc','actual_base','arena_address','arena_bytes','arena_sha256',
                    'header_before_sha256','header_after_sha256','private_path_sha256','base_provenance_sha256','gate_sha256'}
                and in_window(record['qpc']) and record['qpc']>=last,'a5_mutation_once')
            mutation=(record,data,reference);last=record['qpc']
        else:require(False,'a5_memory_kind')
        coordinator_last=last
    # Actual image base comes only from the source-bound PBI/PEB read, never
    # the preferred image base in the fixed PE optional header.
    pbi=apis.get('NtQueryInformationProcess(PBI48)');peb=None;actual=None
    if pbi is not None:
        call,data,intent=pbi
        require(call['arguments']==dict(process=process,information_class=0,bytes=48)
            and type(call['outputs']) is dict and ((set(call['outputs'])=={'returned_length'}
            and integer(call['outputs']['returned_length'],0,0xffffffff) and len(data)==48)
            or (call['output_error'] is not None and call['outputs']=={} and not data)),'a5_mem_PBI_shape')
        if api_good(pbi) and call['raw_return']==0 and call['outputs'].get('returned_length')==48:
            candidate=struct.unpack_from('<Q',data,8)[0]
            if struct.unpack_from('<Q',data,32)[0]==selected['pid'] and 0x10000<=candidate<(1<<47)-32:peb=candidate
    require(len(probes)<=8,'a5_probe_graph_bound')
    if probes:
        require(peb is not None,'a5_probe_requires_PBI')
        first=probes[0];args=first['record']['arguments']
        require(first['record']['operation']=='read' and args==dict(process=process,address=peb,bytes=32,argument=0)
            and first['intent']['qpc']>=pbi[0]['post_call_qpc'],'a5_probe_PEB_binding')
        if first['good']:
            candidate=struct.unpack_from('<Q',first['data'],16)[0]
            if 0x10000<=candidate<(1<<47)-m.builder.SIZE_IMAGE and candidate%65536==0:actual=candidate
        if len(probes)>1:require(actual is not None,'a5_probe_actual_base')
    def covers(region,address,size):
        return m.memory.Coordinator._covers(region,address,size)
    def header_region(fields,base):
        return (covers(fields,base,4096) and fields['allocation_base']==base and fields['state']==0x1000
            and fields['type']==0x1000000 and fields['protect']==2)
    def arena_region(fields,address,protection):
        return (fields['base']==address and fields['allocation_base']==address and covers(fields,address,4096)
            and fields['state']==0x1000 and fields['type']==0x20000
            and fields['allocation_protect']==4 and fields['protect']==protection)
    base_good=len(probes)>=3 and actual is not None
    for number,probe in enumerate(probes[:3]):
        record=probe['record'];args=record['arguments']
        if number==0:semantic=actual is not None
        elif number==1:
            require(record['operation']=='query' and args==dict(process=process,address=actual,bytes=48,argument=0),'a5_probe_base_query')
            semantic=header_region(record['raw']['fields'],actual)
        else:
            require(record['operation']=='read' and args==dict(process=process,address=actual,bytes=m.builder.SIZE_HEADERS,argument=0),'a5_probe_base_header')
            semantic=probe['data']==mapped_before(actual)
        good=probe['good'] and semantic;base_good=base_good and good
        if not good:require(len(probes)<=number+1 and not calls and not memory_events,'a5_probe_stopped_prefix')
    base_receipt=None
    if j['base_provenance'] is not None:
        value,intent=root_return(j['base_provenance'],'base-probe');base_receipt=value
        require(base_good and in_window(intent['qpc']) and integer(value['qpc'],start)
            and intent['qpc']<=pbi[0]['entered_qpc'] and probes[2]['record']['returned_qpc']<=value['qpc'],'a5_base_causal')
        expected=dict(information_class=0,pbi_bytes=48,peb_probe_bytes=32,
            peb_layout='local-amd64-internal-offset16-not-public-stable',peb=peb,actual_base=actual,
            peb_return_sha256=probes[0]['sha256'],query_return_sha256=probes[1]['sha256'],header_return_sha256=probes[2]['sha256'],
            pid=selected['pid'],created=selected['created'],header_sha256=m.sha(mapped_before(actual)))
        require(value['data']==expected,'a5_base_provenance')
        empty['base']=actual
    require(not memory_events or base_receipt is not None,'a5_memory_requires_base')
    patch=None;all_calls_good=False;bytes_good=False
    if base_receipt is not None:
        patch=m.builder.build_import_patch(image,actual,private_path)
        original=pe.original_tables
        lookup=m.memory._table_span(original.descriptors,original.lookup_tables,0)
        iat=m.memory._table_span(original.descriptors,original.IAT_tables,4)
        def span_bytes(span,tables):
            rva,size,entries=span;value=bytearray(size)
            for at,count,index in entries:
                require(count==len(tables[index]),'a5_table_span_count');value[at-rva:at-rva+count]=tables[index]
            return bytes(value)
        original_lookup=span_bytes(lookup,original.lookup_tables);original_iat=span_bytes(iat,original.IAT_tables)
        arena=patch.metadata.arena_address
        graph=[('query',actual,48,0),('query',arena,48,0),('read',actual,m.builder.SIZE_HEADERS,0),
            ('read',actual+m.builder.IMPORT_RVA,m.builder.IMPORT_BYTES,0),('read',actual+lookup[0],lookup[1],0),
            ('read',actual+iat[0],iat[1],0),('allocate',arena,4096,0),('query',arena,48,0),
            ('write',arena,4096,patch.arena),('read',arena,4096,0),('protect',arena,4096,2),('query',arena,48,0),
            ('protect',actual,4096,4),('write',actual+m.builder.IMPORT_HEADER_OFFSET,4,patch.header_patch),
            ('read',actual+m.builder.IMPORT_HEADER_OFFSET,4,0),('protect',actual,4096,2),('query',actual,48,0),
            ('read',actual,m.builder.SIZE_HEADERS,0),('read',arena,4096,0),
            ('read',actual+m.builder.IMPORT_RVA,m.builder.IMPORT_BYTES,0),('read',actual+lookup[0],lookup[1],0),
            ('read',actual+iat[0],iat[1],0),('query',arena,48,0)]
        require(len(calls)<=23,'a5_memory_call_graph_bound')
        def graph_intent(intent,index):
            require(index<23,'a5_memory_once_graph');operation,address,size,argument=graph[index]
            args=dict(process=process,address=address,bytes=size)
            if operation=='allocate':args.update(allocation_type=0x3000,protection=4)
            elif operation=='protect':args['new_protection']=argument
            elif operation=='query':args['buffer_bytes']=48
            require(intent['operation']==operation and intent['arguments']==args,'a5_memory_call_graph')
            if operation=='write':require(intent['input_sha256']==m.sha(argument),'a5_memory_write_intent')
            else:require(type(intent['argument']) is int and intent['argument']==argument,'a5_memory_call_argument')
        for index,entry in enumerate(calls):
            graph_intent(entry['intent'],index);raw=entry['record']['raw'];semantic=True
            if index in (0,16):semantic=header_region(raw['fields'],actual)
            elif index==1:semantic=raw['fields']['state']==0x10000 and covers(raw['fields'],arena,4096)
            elif index==6:semantic=raw['value']==arena
            elif index==7:semantic=arena_region(raw['fields'],arena,4)
            elif index in (11,22):semantic=arena_region(raw['fields'],arena,2)
            elif index in (10,15):semantic=raw['fields']['old_protect']==4
            elif index==12:semantic=raw['fields']['old_protect']==2
            elif index==9:semantic=entry['data']==patch.arena
            elif index==14:semantic=entry['data']==patch.header_patch
            elif index==5:
                semantic=[x['data'] for x in calls[2:6]]==[mapped_before(actual),original.descriptors,original_lookup,original_iat]
            elif index==21:
                semantic=[x['data'] for x in calls[17:22]]==[patch.expected_header,patch.arena,original.descriptors,original_lookup,original_iat]
                bytes_good=semantic and all(x['good'] for x in calls[17:22])
            entry['qualified']=entry['good'] and semantic
            if not entry['qualified']:require(len(calls)==index+1 and pending is None,'a5_memory_stopped_prefix')
        if pending is not None and pending[0]=='memory':graph_intent(pending[2],len(calls))
        if calls:
            require(gate_rows and gate_rows[0][0]['label']=='before-memory'
                and positions[gate_rows[0][1]]<positions[calls[0]['record']['intent_sha256']]
                and probes[2]['record']['returned_qpc']<=gate_rows[0][0]['before_qpc'],'a5_memory_before_gate')
        if len(gate_rows)==2:
            require(len(calls)==23 and positions[calls[-1]['sha256']]<positions[gate_rows[1][1]],'a5_memory_after_gate')
        if mutation is not None:
            record,data,reference=mutation
            require(data==patch.arena and record['actual_base']==actual and record['arena_address']==arena
                and record['arena_bytes']==4096 and record['arena_sha256']==m.sha(patch.arena)
                and record['header_before_sha256']==m.sha(mapped_before(actual)) and record['header_after_sha256']==m.sha(patch.expected_header)
                and record['private_path_sha256']==patch.metadata.private_path_sha256
                and record['base_provenance_sha256']==j['base_provenance']['sha256']
                and gate_rows and record['gate_sha256']==gate_rows[0][0]['gate_sha256'],'a5_mutation_binding')
        if len(calls)>6:
            require(mutation is not None and positions[mutation[2]]<positions[calls[6]['record']['intent_sha256']],'a5_mutation_precedes_allocate')
        all_calls_good=len(calls)==23 and all(x['qualified'] for x in calls)
    if j['memory_summary'] is not None:
        value,intent=root_return(j['memory_summary'],'memory-sequence');data=value['data']
        keys={'status','failure','mutation_intent_sha256','mutation_attempted','allocation_state','memory_bytes_match',
            'memory_sequence_complete','controls_unknown','actual_base','arena_address','remote_lifetime','actual_ready',
            'resume_authorized','config_GUID_injection_complete','external_identity_gates_verified_by_this_module',
            'actual_loader_or_transport_qualified','call_count','gates','epoch','bindings'}
        require(type(data) is dict and set(data)==keys and base_receipt is not None and patch is not None,'a5_memory_summary_schema')
        flags=('mutation_attempted','memory_bytes_match','memory_sequence_complete','controls_unknown','actual_ready',
            'resume_authorized','config_GUID_injection_complete','external_identity_gates_verified_by_this_module','actual_loader_or_transport_qualified')
        require(all(type(data[k]) is bool for k in flags) and not any(data[k] for k in flags[4:])
            and data['status'] in ('stopped','complete-memory-sequence')
            and (data['failure'] is None or type(data['failure']) is str)
            and data['status']==('complete-memory-sequence' if data['failure'] is None else 'stopped')
            and data['memory_sequence_complete']==(data['failure'] is None)
            and data['epoch']==epoch and data['bindings']==bindings and data['actual_base']==actual
            and data['arena_address']==patch.metadata.arena_address,'a5_memory_summary_binding')
        require(type(data['call_count']) is int and len(calls)<=data['call_count']<=len(calls)+(1 if pending and pending[0]=='memory' else 0)
            and data['gates']==[[r['label'],r['gate_sha256'],reference] for r,reference in gate_rows]
            and data['mutation_intent_sha256']==(mutation[2] if mutation else None)
            and data['allocation_state'] in ('not-entered','entered-outcome-unknown','known-null-return','known-exact-retained','unknown-wrong-address')
            and data['remote_lifetime']==('retained-until-exact-supervised-target-exit' if data['mutation_attempted'] else 'no-mutation-entered'),'a5_memory_summary_facts')
        require(not data['memory_bytes_match'] or bytes_good,'a5_memory_bytes_claim')
        if len(calls)>6:
            raw=calls[6]['record']['raw'];state='entered-outcome-unknown'
            if raw['returned'] and integer(raw['value']):
                state='known-null-return' if raw['value']==0 else ('known-exact-retained' if raw['value']==patch.metadata.arena_address else 'unknown-wrong-address')
            require(data['mutation_attempted'] and data['allocation_state']==state,'a5_memory_allocation_state')
        require(not(data['mutation_attempted'] and not data['memory_sequence_complete'] and data['allocation_state']!='known-null-return')
            or data['controls_unknown'],'a5_memory_unknown_mutation')
        unknown_call=any(not x['record']['raw']['returned'] or x['record']['raw']['exception'] is not None
            or not x['record']['raw']['error_captured'] or not x['record']['return_clock_known']
            or not x['record']['timely'] for x in calls)
        require(not unknown_call or data['controls_unknown'],'a5_memory_unknown_raw')
        require(integer(intent['qpc'],start) and integer(value['qpc'],start) and base_receipt['qpc']<=intent['qpc']
            and (not gate_rows or intent['qpc']<=gate_rows[0][0]['before_qpc'])
            and value['qpc']>=coordinator_last,'a5_memory_summary_causal')
        if data['memory_sequence_complete']:
            require(all_calls_good and pending is None and len(gate_rows)==2 and mutation is not None
                and data['call_count']==23 and data['memory_bytes_match'] and not data['controls_unknown']
                and data['allocation_state']=='known-exact-retained','a5_memory_complete_physical')
            empty['memory_complete']=in_window(intent['qpc']) and in_window(value['qpc']) and in_window(base_receipt['qpc'])
    config=None;copy=apis.get('a5_copy_config_v1');pointer=None
    if j['config_binary'] is not None:
        require(empty['memory_complete'] and type(j['mapping']) is dict,'a5_config_requires_memory')
        config=m.read_binary(root,j['config_binary'],2048)
        require(j['config_binary']['name']=='a4-config.bin' and len(config)==2048,'a5_config_extent')
        m.trace_reader.validate_config(config,schema_metadata=m.trace_reader.SCHEMA_METADATA)
        require(j['mapping']['child_handle']==selected['inherited_handles'][0]
            and config==m.pack_config(c,selected,window,j['mapping']['child_handle'],m.artifact_paths(root)['shim'],Path(c['curl_path']).parent/'WS2_32.dll'),'a5_config_exact')
        empty['config']=config
    if copy is not None:
        call,raw,copy_intent=copy
        require(config is not None and call['arguments']==dict(process=process,config_sha256=m.sha(config),bytes=2048)
            and call['outputs']=={} and (len(raw)==32 or (call['output_error'] is not None and not raw)),'a5_payload_API_input')
        size,version,flags,error,returned_pointer,seh,reserved=struct.unpack('<4IQ2I',raw) if len(raw)==32 else (0,0,0,0,0,0,0)
        require(((call['returned'] is True and type(call['raw_return']) is int and call['raw_return'] in (0,1,2))
            or (call['returned'] is False and call['raw_return'] is None)) and flags & ~31==0,'a5_payload_Result32')
        known=(call['returned'] is True and call['native_exception'] is None and call['output_error'] is None
            and call['raw_return']==0 and size==32 and version==1 and flags==3 and error==0 and seh==0 and reserved==0 and returned_pointer!=0)
        empty['payload_pointer']=known
        if known and 0x10000+456<=returned_pointer<(1<<47)-2048 and (returned_pointer-456)%4096==0:pointer=returned_pointer
    payload_probes=probes[3:]
    if payload_probes:
        require(empty['memory_complete'] and copy is not None and api_good(copy) and pointer is not None,'a5_payload_requires_carrier')
        expected=m.payload_framing(config);allocation=pointer-456
        graph=[('read',len(expected),0),('query',48,0),('protect',4096,2),('query',48,0),('read',len(expected),0)]
        for index,probe in enumerate(payload_probes):
            operation,size,argument=graph[index];record=probe['record']
            require(record['operation']==operation and record['arguments']==dict(process=process,address=allocation,bytes=size,argument=argument)
                and probe['intent']['qpc']>=copy[0]['post_call_qpc'],'a5_payload_probe_graph')
            semantic=True
            if index in (0,4):semantic=probe['data']==expected
            elif index==1:semantic=arena_region(record['raw']['fields'],allocation,4)
            elif index==2:semantic=record['raw']['fields']['old_protect']==4
            elif index==3:
                fields=record['raw']['fields'];semantic=(fields['base']==allocation and fields['allocation_base']==allocation
                    and covers(fields,allocation,4096) and fields['state']==0x1000 and fields['type']==0x20000 and fields['protect']==2)
            probe['qualified']=probe['good'] and semantic
            if not probe['qualified']:require(len(payload_probes)==index+1 and pending is None,'a5_payload_stopped_prefix')
    if j['payload'] is not None:
        value,intent=root_return(j['payload'],'config-carrier');data=value['data']
        require(pointer is not None and len(payload_probes)==5 and all(x['qualified'] for x in payload_probes)
            and in_window(intent['qpc']) and integer(value['qpc'],start)
            and j['memory_summary'] is not None and roots[j['memory_summary']['sha256']][1]['qpc']<=intent['qpc']
            <=copy[0]['entered_qpc'] and payload_probes[-1]['record']['returned_qpc']<=value['qpc'],'a5_payload_complete_causal')
        expected=m.payload_framing(config)
        require(data==dict(pointer=pointer,allocation_base=pointer-456,framing_bytes=len(expected),config_sha256=m.sha(config),
            framing_sha256=m.sha(expected),first_read_sha256=payload_probes[0]['sha256'],query_sha256=payload_probes[1]['sha256'],
            protect_sha256=payload_probes[2]['sha256'],readonly_query_sha256=payload_probes[3]['sha256'],
            readonly_read_sha256=payload_probes[4]['sha256'],readonly_verified=True),'a5_payload_summary_raw')
        empty['payload_readonly']=in_window(value['qpc'])
    if pending is not None and pending[0]=='probe':
        intent=pending[2];index=len(probes)
        require(index<8,'a5_probe_pending_bound')
        if index==0:
            require(peb is not None,'a5_probe_pending_PBI');operation,address,size,argument='read',peb,32,0
        elif index in (1,2):
            require(actual is not None,'a5_probe_pending_base')
            operation,address,size,argument=('query',actual,48,0) if index==1 else ('read',actual,m.builder.SIZE_HEADERS,0)
        else:
            require(empty['memory_complete'] and copy is not None and api_good(copy) and pointer is not None,'a5_probe_pending_carrier')
            expected=m.payload_framing(config)
            operation,size,argument=[('read',len(expected),0),('query',48,0),('protect',4096,2),('query',48,0),('read',len(expected),0)][index-3]
            address=pointer-456
        require(intent['operation']==operation and intent['arguments']==dict(process=process,address=address,bytes=size,argument=argument),'a5_probe_pending_graph')
    require(not selected['resumed'] or empty['memory_complete'] and empty['payload_readonly'],'a5_memory_before_Resume')
    return empty
