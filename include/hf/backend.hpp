
#pragma once
#include <string>

namespace hf {

// Returns 0 on success, non-zero on error.
int cmd_generate_keys(const std::string& keydir);
int cmd_validate_keys(const std::string& keydir);
int cmd_benchmark(const std::string& keydir, int seconds);
int cmd_encrypt(const std::string& keydir, const std::string& in_path, const std::string& out_path);
int cmd_decrypt(const std::string& keydir, const std::string& in_path, const std::string& out_path);

} // namespace hf
