
#pragma once
#include <string>

namespace hf {
int cmd_generate();
int cmd_validate();
int cmd_bench();
int cmd_encrypt(const std::string& file);
int cmd_decrypt(const std::string& file);
}
