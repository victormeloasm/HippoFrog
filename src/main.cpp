
#include <cstdio>
#include <cstring>
#include <string>

#include "hf/cmds.hpp"

static void usage(){
    std::puts(
"HippoFrog CLI (v2.2)\n"
"Usage:\n"
"  HippoFrog --generate-keys\n"
"  HippoFrog --validate-keys\n"
"  HippoFrog --b\n"
"  HippoFrog --encrypt <file>\n"
"  HippoFrog --decrypt <file.hf>\n"
    );
}

int main(int argc, char** argv){
    if(argc<2){ usage(); return 1; }
    std::string cmd = argv[1];
    try{
        if(cmd=="--generate-keys") return hf::cmd_generate();
        if(cmd=="--validate-keys") return hf::cmd_validate();
        if(cmd=="--b") return hf::cmd_bench();
        if(cmd=="--encrypt"){
            if(argc<3){ usage(); return 1; }
            return hf::cmd_encrypt(argv[2]);
        }
        if(cmd=="--decrypt"){
            if(argc<3){ usage(); return 1; }
            return hf::cmd_decrypt(argv[2]);
        }
    }catch(const std::exception& e){
        std::fprintf(stderr,"fatal: %s\n", e.what());
        return 2;
    }
    usage();
    return 1;
}
