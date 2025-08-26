
#pragma once
#include <vector>
#include <string>

namespace hf {

struct KeyPair {
    std::vector<unsigned char> priv_pem;
    std::vector<unsigned char> pub_pem;
    std::vector<unsigned char> pub_compressed; // 33-byte uncompressed if needed
};

class Backend {
public:
    virtual ~Backend() = default;
    virtual bool generate_keypair(KeyPair& kp, const char* rng_info) = 0;
    virtual bool validate_keypair(const std::vector<unsigned char>& priv_pem,
                                  const std::vector<unsigned char>& pub_pem,
                                  const char* rng_info) = 0;
    virtual bool ecdh(std::vector<unsigned char>& shared,
                      const std::vector<unsigned char>& priv_pem,
                      const std::vector<unsigned char>& peer_pub_pem,
                      const char* rng_info) = 0;

    virtual bool spki_from_compressed(std::vector<unsigned char>& spki_pem,
                                      const std::vector<unsigned char>& comp_bytes) = 0;
    virtual bool compressed_from_spki(std::vector<unsigned char>& comp_bytes,
                                      const std::vector<unsigned char>& spki_pem) = 0;
    virtual bool subgroup_check_spki(const std::vector<unsigned char>& spki_pem) = 0;
};

} // namespace hf
