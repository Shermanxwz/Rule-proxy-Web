#pragma once
#include "ProcessSecurityEnvironment_generated.h"
#include <string>
#include <vector>
#include <cstdint>

namespace pb {
namespace layout = ProcessSecurityEnvironmentLayout;
inline bool path_utf8(const std::uint16_t* p, std::uint32_t n, std::string& out) {
    out.clear();
    if (!p || n<3 || n>1024 || !((p[0]>='A'&&p[0]<='Z')||(p[0]>='a'&&p[0]<='z'))
        || p[1]!=':' || p[2]!='\\') return false;
    for (std::uint32_t i=0;i<n;++i) {
        std::uint32_t c=p[i];
        if (!c || c<32 || c=='"' || c=='/' || (c==':' && i!=1)) return false;
        if (c>=0xd800 && c<=0xdbff) {
            if (++i==n || p[i]<0xdc00 || p[i]>0xdfff) return false;
            c=0x10000+((c-0xd800)<<10)+(p[i]-0xdc00);
        } else if (c>=0xdc00 && c<=0xdfff) return false;
        if (c<0x80) out.push_back(static_cast<char>(c));
        else if (c<0x800) { out.push_back(char(0xc0|(c>>6))); out.push_back(char(0x80|(c&63))); }
        else if (c<0x10000) { out.push_back(char(0xe0|(c>>12))); out.push_back(char(0x80|((c>>6)&63))); out.push_back(char(0x80|(c&63))); }
        else { out.push_back(char(0xf0|(c>>18))); out.push_back(char(0x80|((c>>12)&63))); out.push_back(char(0x80|((c>>6)&63))); out.push_back(char(0x80|(c&63))); }
    }
    if (out.find("\\..\\")!=std::string::npos || out.find("\\.\\")!=std::string::npos
        || out.size()<4 || out.back()=='\\' || out.substr(out.size()-3)=="\\.."
        || out.substr(out.size()-2)=="\\.") return false;
    return true;
}
inline std::vector<std::uint8_t> build_spec(const std::string& inputs) {
    flatbuffers::FlatBufferBuilder b(1024);
    const auto caps=b.CreateString("privateNetworkClientServer");
    std::vector<flatbuffers::Offset<flatbuffers::String>> paths{b.CreateString(inputs)};
    const auto ro=b.CreateVector(paths);
    const auto egress=layout::CreateEndpointPolicy(b,layout::FilterAction_deny);
    const auto ingress=layout::CreateIngressPolicy(b,layout::FilterAction_deny,layout::FilterAction_deny);
    const auto network=layout::CreateNetworkPolicy(b,0,egress,0,ingress);
    const layout::SchemaVersion version(1,1);
    const auto root=layout::CreateProcessSecurityEnvironment(b,&version,caps,true,0x3ff,0,ro,0,network,0);
    layout::FinishProcessSecurityEnvironmentBuffer(b,root);
    return {b.GetBufferPointer(),b.GetBufferPointer()+b.GetSize()};
}
template<class T> inline bool no_extra_fields(const T* t, unsigned fields) {
    if (!t) return false;
    const auto bytes=reinterpret_cast<const std::uint8_t*>(t);
    const auto distance=flatbuffers::ReadScalar<flatbuffers::soffset_t>(bytes);
    const auto vt=bytes-distance;
    return flatbuffers::ReadScalar<flatbuffers::voffset_t>(vt)<=4+2*fields;
}
inline bool verify_spec(const std::uint8_t* bytes, std::uint32_t n, const std::string& inputs) {
    if (!bytes || n<16 || n>65536) return false;
    flatbuffers::Verifier v(bytes,n,16,64);
    if (!layout::VerifyProcessSecurityEnvironmentBuffer(v)) return false;
    const auto r=layout::GetProcessSecurityEnvironment(bytes);
    if (!no_extra_fields(r,9) || !r->version() || r->version()->major()!=1 || r->version()->minor()!=1
        || !r->capabilities() || r->capabilities()->str()!="privateNetworkClientServer"
        || !r->disallow_win32k_system_calls() || r->ui_restrictions()!=0x3ff
        || r->fs_read_write() || r->fs_deny() || r->fs_enumerate()
        || !r->fs_read_only() || r->fs_read_only()->size()!=1
        || r->fs_read_only()->Get(0)->str()!=inputs) return false;
    const auto net=r->network_policy();
    if (!no_extra_fields(net,4) || net->proxy() || net->allowed_appcontainer_peer()) return false;
    const auto e=net->egress(); const auto i=net->ingress();
    if (!no_extra_fields(e,3) || e->default_action()!=layout::FilterAction_deny || e->allow() || e->deny()
        || !no_extra_fields(i,2) || i->default_action()!=layout::FilterAction_deny
        || i->host_loopback()!=layout::FilterAction_deny) return false;
    // The owner pins the exact original bytes independently. Semantic verification
    // admits valid alternate FlatBuffer layouts; it never substitutes rebuilt bytes.
    return true;
}
}
