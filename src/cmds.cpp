
#include <iostream>
#include <string>
#include <vector>
#include <filesystem>
#include "hf/backend.hpp"
#include "hf/cmds.hpp"

using namespace hf;

static void usage(){
    std::cout << "HippoFrog CLI (secure)\n"
              << "Usage:\n"
              << "  HippoFrog --generate-keys\n"
              << "  HippoFrog --validate-keys\n"
              << "  HippoFrog --b\n"
              << "  HippoFrog --encrypt <file>\n"
              << "  HippoFrog --decrypt <file.hf>\n";
}

int hf::run_cli(int argc, char** argv){
    if(argc < 2){ usage(); return 1; }
    std::string cmd = argv[1];
    const std::string keydir = "keys";
    std::filesystem::create_directories(keydir);

    if(cmd == std::string("--generate-keys")){
        return cmd_generate_keys(keydir);
    } else if(cmd == std::string("--validate-keys")){
        return cmd_validate_keys(keydir);
    } else if(cmd == std::string("--b")){
        return cmd_benchmark(keydir, 3);
    } else if(cmd == std::string("--encrypt")){
        if(argc != 3){ usage(); return 1; }
        std::string in = argv[2];
        std::string out = in + ".hf";
        return cmd_encrypt(keydir, in, out);
    } else if(cmd == std::string("--decrypt")){
        if(argc != 3){ usage(); return 1; }
        std::string in = argv[2];
        std::string out = in;
        if(out.size()>3 && out.substr(out.size()-3)==".hf"){
            out = out.substr(0, out.size()-3);
        }else{
            out += ".dec";
        }
        return cmd_decrypt(keydir, in, out);
    } else {
        usage(); return 1;
    }
}
