"""Portable production control/hash/Win32 serializer tests; never run Win32 APIs."""
import hashlib
import importlib.util
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest
ROOT=Path(__file__).resolve().parents[1]
NATIVE=ROOT/'.github/native'
def owner():
 s=importlib.util.spec_from_file_location('pipe_dns_native_ticket',ROOT/'.github/windows_identity_lpac_pipe_dns_origin.py');m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
PREFIX=r'''#define RULEPROXY_LPAC_PIPE_DNS_PORTABLE 1
#include "windows_identity_lpac_pipe_dns_front_actor.cpp"
#include <cstdio>
#include <cstdlib>
unsigned checks=0;void checked(bool v,unsigned line){++checks;if(!v){std::fprintf(stderr,"line%u\n",line);std::exit(1);}}
#define check(v) checked((v),__LINE__)
using namespace lpac_pipe_dns;
'''
class PortableTests(unittest.TestCase):
 def compiled(self,body):
  compiler=shutil.which('cl.exe') if os.name=='nt' else shutil.which('c++');self.assertIsNotNone(compiler,'installed compiler developer shell required')
  with tempfile.TemporaryDirectory() as td:
   root=Path(td).resolve();src=root/'fake.cpp';src.write_bytes((PREFIX+body).encode('utf-8'));exe=root/('fake.exe' if os.name=='nt' else 'fake')
   args=([compiler,'/nologo','/std:c++17','/W4','/WX','/EHsc','/MT','/O2','/I'+str(NATIVE),'/Fo'+str(root/'fake.obj'),'/Fe'+str(exe),str(src)] if os.name=='nt' else [compiler,'-std=c++17','-Wall','-Wextra','-Werror','-O2','-I',str(NATIVE),str(src),'-o',str(exe)])
   built=subprocess.run(args,cwd=root,capture_output=True,text=True,encoding='utf-8',errors='replace',timeout=60);self.assertEqual(built.returncode,0,built.stdout+built.stderr)
   ran=subprocess.run([str(exe)],cwd=root,capture_output=True,text=True,encoding='utf-8',errors='replace',timeout=15);self.assertEqual(ran.returncode,0,ran.stdout+ran.stderr);self.assertRegex(ran.stdout,r'LPD_PORTABLE_ASSERTIONS [1-9][0-9]*');print(ran.stdout.strip())
 def test_Python_canonical128_and_production_decoder_plan_mutations(self):
  m=owner();c=dict(run='1'*32,case='2'*32,dns_selected_case='3'*32);pair=dict(start=10000,end=20000,frequency=1000);c['frequency']=1000;c['start_qpc']=1000
  query=m.ticket(c,pair,6,12000);finish=m.ticket(c,pair,255,20000)
  body='const std::array<std::uint8_t,128> query={'+','.join(map(str,query))+'};\nconst std::array<std::uint8_t,128> finish={'+','.join(map(str,finish))+'};\n'
  body+=r'''std::vector<std::wstring> args(){return {LR"(C:\Owned\front.exe)",L"pipe-dns-front",std::wstring(32,L'1'),std::wstring(32,L'2'),LR"(C:\Owned\ipc.json)",L"40",L"44",L"10000",L"1000",L"20000",L"S-1-5-21-1",L"S-1-15-2-1-2-3-4-5-6-7",L"0",L"54321",std::wstring(32,L'3'),LR"(C:\Owned\go.bin)",LR"(C:\Owned\dns.json)",LR"(C:\Owned\finish.bin)",LR"(C:\Owned\final.json)"};}
int main(){auto a=args();Plan p;check(plan(a,p));Command out;check(decode(query.data(),128,p.binding,1,10001,out)&&out.operation==6&&out.deadline==12000);
check(decode(finish.data(),128,p.binding,2,10001,out)&&out.operation==255&&out.deadline==20000);
for(unsigned seq:{1u,2u}){const auto original=seq==1?query:finish;
 for(std::size_t n=0;n<128;++n)check(!decode(original.data(),n,p.binding,seq,10001,out));
 std::array<std::uint8_t,129> extra{};for(std::size_t i=0;i<128;++i)extra[i]=original[i];check(!decode(extra.data(),129,p.binding,seq,10001,out));
 for(std::size_t i=0;i<128;++i)for(unsigned bit=0;bit<8;++bit){auto v=original;v[i]^=static_cast<std::uint8_t>(1u<<bit);const bool okay=decode(v.data(),128,p.binding,seq,10001,out);const auto d=le(v.data()+88,8);
  const bool alternative=seq==1&&i>=88&&i<96&&d>10001&&d<=12001;check(okay==alternative);}
 check(!decode(original.data(),128,p.binding,seq,20000,out));check(!decode(original.data(),128,p.binding,seq==1?2u:1u,10001,out));}
check(!decode(query.data(),128,p.binding,1,12000,out));auto wrong=p.binding;wrong.run[0]^=1;check(!decode(query.data(),128,wrong,1,10001,out));wrong=p.binding;wrong.frequency=0;check(!decode(query.data(),128,wrong,1,10001,out));
for(auto item:std::vector<std::pair<unsigned,std::wstring>>{{1,L"pipe-front"},{12,L"1"},{5,L"0"},{5,L"-1"},{5,L"9223372036854775808"},{6,L"40"},{7,L"9223372036854775800"},{8,L"0"},{8,L"1000000001"},{9,L"20001"},{13,L"49152"},{13,L"65536"},{2,L"ABC"},{14,std::wstring(32,L'2')}}){auto v=a;v[item.first]=item.second;check(!plan(v,p));}
a.pop_back();check(!plan(a,p));a=args();a.push_back(L"extra");check(!plan(a,p));a=args();std::wstring text;for(const auto& v:a){if(!text.empty())text+=L' ';text+=L'"'+v+L'"';}
std::vector<std::wstring> decoded;check(arguments(text.c_str(),decoded)&&decoded==a);for(auto suffix:{L" extra",L"\"",L" x\"bad"}){decoded.clear();check(!arguments((text+suffix).c_str(),decoded));}
std::printf("LPD_PORTABLE_ASSERTIONS %u\n",checks);return 0;}
'''
  self.compiled(body)
 def test_self_contained_SHA_vectors_padding_report_newline_and_multiblock(self):
  body='int main(){check(sha256("")=="'+hashlib.sha256(b'').hexdigest()+'");\n'
  for n in (1,3,55,56,63,64,65,119,120,127,128,1024,10000):
   raw=bytes((i*31+17)%256 for i in range(n));expected=hashlib.sha256(raw).hexdigest();body+='{std::string v;for(unsigned i=0;i<'+str(n)+'u;++i)v+=static_cast<char>((i*31+17)%256);check(sha256(v)=="'+expected+'");}\n'
  for raw,lit in ((b'abc','abc'),(b'{"stage":"report"}\n','{\"stage\":\"report\"}\n')):
   # C++ string escaping is independent of the production hash implementation.
   import json
   body+='check(sha256('+json.dumps(raw.decode('ascii'))+')=="'+hashlib.sha256(raw).hexdigest()+'");\n'
  body+=r'std::printf("LPD_PORTABLE_ASSERTIONS %u\n",checks);return 0;}';self.compiled(body)
 def test_real_Win32_result_serializer_expression_compiles_and_matches_closed_JSON(self):
  # Compile the complete function verbatim from the otherwise excluded Win32
  # branch. Keep boolean's real const-char-pointer return type: changing that
  # fake to std::string would conceal literal-plus-pointer build failures.
  import json
  src=(NATIVE/'windows_identity_lpac_pipe_dns_front_actor.cpp').read_text(encoding='utf-8')
  begin=src.index('std::string result_json(');end=src.index('\nint run(',begin)
  function=src[begin:end]
  self.assertEqual(function.count('std::string result_json('),1)
  body=r'''namespace ruleproxy_dns_standard {struct Result {
 bool configured=false,called=false,completed=false,pending=false,answer_match=false;
 bool records_released=false,context_retained=false,within_deadline=false;
 std::uint32_t api_status=0,query_status=0;unsigned record_count=0;
 std::uint64_t start_qpc=0,end_qpc=0;};}
namespace bridge_pipe {const char* boolean(bool v){return v?"true":"false";}}
namespace lpac_pipe_dns {
'''+function+'\n}\nint main(){\n'
  flags=('configured','called','completed','pending','answer_match','records_released','context_retained','within_deadline')
  vectors=[]
  for bits in range(256):
   v={k:bool(bits&(1<<i)) for i,k in enumerate(flags)}
   v.update(api_status=0,query_status=5,record_count=1,start_qpc=1000,end_qpc=2000);vectors.append(v)
  for n in (0,1,2147483648,4294967295):
   v=dict.fromkeys(flags,False);v.update(api_status=n,query_status=n,record_count=n,start_qpc=0,end_qpc=18446744073709551615);vectors.append(v)
  for v in vectors:
   body+='{ruleproxy_dns_standard::Result r;'
   for key,value in v.items():
    literal=('true' if value else 'false') if type(value) is bool else str(value)+('ull' if key.endswith('_qpc') else 'u')
    body+='r.'+key+'='+literal+';'
   expected=json.dumps(v,separators=(',',':'))
   body+='check(result_json(r)=='+json.dumps(expected)+');}\n'
  body+=r'std::printf("LPD_PORTABLE_ASSERTIONS %u\n",checks);return 0;}'
  self.compiled(body)
 def test_selected_source_uses_typed_identity_failure_no_socket_and_exact19argv(self):
  src=(NATIVE/'windows_identity_lpac_pipe_dns_front_actor.cpp').read_text(encoding='utf-8');header=(NATIVE/'windows_identity_lpac_pipe_dns_contract.hpp').read_text(encoding='utf-8')
  self.assertIn('if(!self(dns_identity,p))failure="identity";else result=ruleproxy_dns_standard::query',src);self.assertNotIn('return 4',src);self.assertIn('a.size()!=19',header);self.assertIn('a[12]!=L"0"',header)
  for word in ('WSAStartup(', 'socket(', 'WSASocket(', 'sendto(', 'CreateProcessW(', 'BCrypt', 'CryptAcquire', 'registryRead', 'privateNetworkClientServer'):self.assertNotIn(word,src)
  self.assertLess(src.index('probe.cleanup()'),src.index('Command go;'));self.assertLess(src.index('command(paths[1]'),src.index('ruleproxy_dns_standard::query'));self.assertIn('sha256(ipc)',src);self.assertIn('sha256(dns)',src);self.assertIn('if(!write(paths[2],dns))',src)
if __name__=='__main__':unittest.main()
