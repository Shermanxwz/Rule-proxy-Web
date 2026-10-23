// Genuine zero-cap LPAC cooperative byte source/sink. No socket/DNS APIs.
#define RULEPROXY_IDENTITY_ONLY 1
#define wmain lpac_stream_unused_identity_entry
#include "windows_identity_actor.cpp"
#undef wmain
#define RULEPROXY_LPAC_STREAM_WINDOWS_HELPERS 1
#include "windows_identity_lpac_stream_contract.hpp"

namespace lpac_stream {
struct FrontAPI {
    Clock& clock;Pipes& pipes;File& input;File& output;
    bool sample(){return clock.sample();}
    IO pipe_read(std::uint8_t* p,std::size_t n){return pipes.read(clock,p,std::min<std::size_t>(n,127));}
    IO pipe_write(const std::uint8_t* p,std::size_t n){return pipes.write(clock,p,std::min<std::size_t>(n,113));}
    IOState connect(){clock.fail("protocol");return IOState::error;}
    IO consume(const std::uint8_t* p,std::size_t n){return output.write(clock,p,std::min<std::size_t>(n,257));}
    IOState finish_inbound(){return output.flush(clock)?IOState::progress:IOState::error;}
    IO produce(std::uint8_t* p,std::size_t n){return input.read(clock,p,std::min<std::size_t>(n,383));}
    bool close_writer(){return pipes.writer.close(clock);}
};
int front(const std::vector<std::wstring>& args){
    Plan p;if(!parse_plan(args,p)||p.role!=L"stream-front")return 2;
    Clock clock(p);Pipes pipes(p);File input,output;Node node(p.config);Observations identity;Slot report_file;
    report_file.value=CreateFileW(p.report.c_str(),GENERIC_WRITE,0,nullptr,CREATE_NEW,FILE_ATTRIBUTE_NORMAL,nullptr);
    if(report_file.value==INVALID_HANDLE_VALUE){report_file.value=nullptr;pipes.cleanup(clock);return 3;}
    try{
        if(clock.sample()){
            identity=ObserveNativeIdentity();const bool time=clock.sample();if(!admitted(identity,p))clock.fail("identity");
            if(time&&!clock.failure&&pipes.prepare(clock)
                &&input.open(clock,p.root/L"selected-inputs"/L"request.bin",false,p.request)
                &&output.open(clock,p.root/L"selected-report"/L"response.raw",true)){
                FrontAPI api{clock,pipes,input,output};
                while(!clock.failure&&!node.failure()&&!node.complete()){const bool progress=step(node,api);if(!progress&&!clock.failure&&!node.failure())Sleep(1);}
                if(node.failure()&&!clock.failure)clock.fail("protocol");if(!node.complete()&&!clock.failure)clock.fail("protocol");
            }
        }
    }catch(...){clock.fail("configuration");node.fail("external");}
    input.cleanup(clock);output.cleanup(clock);pipes.cleanup(clock);
    const auto body=report(p,clock,identity,&node,&pipes,&input,nullptr,&output,"null",false);
    if(!write_report(report_file,clock,body))return 3;return clock.failure?5:0;
}
} // namespace lpac_stream
int WINAPI wWinMain(HINSTANCE,HINSTANCE,PWSTR,int){
    try{std::vector<std::wstring> args;if(!lpac_stream::arguments(GetCommandLineW(),args))return 2;return lpac_stream::front(args);}catch(...){return 6;}
}
