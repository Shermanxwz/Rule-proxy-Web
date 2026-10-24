// Ordinary file/struct harness only. No Windows include, DLL or target.
#include "../.github/native/windows_identity_lpac_curl_a5_startup_find.hpp"
#include <fstream>
#include <iostream>
#include <stdexcept>
unsigned assertions=0;
void check(bool value){++assertions;if(!value)throw std::runtime_error("cross ABI assertion");}
int main(int argc,char** argv){
    try{
        check(argc==2);a5startup::Config2048 original{};
        std::ifstream input(argv[1],std::ios::binary);check(input.good());
        input.read(reinterpret_cast<char*>(&original),sizeof(original));check(input.gcount()==2048);
        char extra=0;input.read(&extra,1);check(input.gcount()==0);
        const auto frequency=original.frequency,now=original.window_start;
        check(a5startup::config_shape(original,frequency,now));
        // Mutate the actual Python-produced bytes, not a second C++ encoder.
        for(unsigned which=0;which<9;++which){auto bad=original;
            if(which==0)bad.pipe_read=bad.pipe_write;
            if(which==1)bad.pipe_write=bad.trace_handle;
            if(which==2)bad.http_profile=2;
            if(which==3)bad.reserved[187]=1;
            if(which==4)bad.reserved1=1;
            if(which==5)++bad.work_deadline;
            if(which==6)++bad.window_end;
            if(which==7)++bad.frequency;
            if(which==8)bad.request_body=8064;
            check(!a5startup::config_shape(bad,frequency,now));
        }
        check(!a5startup::config_shape(original,frequency,original.window_end));
        check(!a5startup::config_shape(original,frequency,original.window_start-1));
        std::cout<<"a5-cross-abi assertions: "<<assertions<<"\n";return 0;
    }catch(const std::exception& error){std::cerr<<error.what()<<" at "<<assertions<<"\n";return 1;}
}
