
#include <chrono>
#include <cstring>
#include <iostream>
#include <vector>
#include <openssl/rand.h>
#include <sys/stat.h>
#include "hf/params.hpp"
#include "hf/util.hpp"
#include "hf/crypto.hpp"
#include "hf/ec.hpp"
#include "hf/backend.hpp"

using namespace hf;

namespace {

// ---- Deterministic header packing (no struct memcpy) ----
// Layout (4+1+3+32+32+12+2 = 86 bytes):
//   [0..3]   "HFv1"
//   [4]      VERSION (1)
//   [5..7]   reserved (0)
//   [8..39]  param_hash (32)
//   [40..71] salt (32)
//   [72..83] iv (12)
//   [84..85] eph_len (LE uint16 = 67)
static std::vector<uint8_t> pack_header(const std::vector<uint8_t>& ph,
                                        const std::vector<uint8_t>& salt,
                                        const std::vector<uint8_t>& iv,
                                        uint16_t eph_len_le) {
    std::vector<uint8_t> h;
    h.reserve(86);
    h.insert(h.end(), {'H','F','v','1'});
    h.push_back(1);
    h.insert(h.end(), 3, 0);
    h.insert(h.end(), ph.begin(), ph.end());
    h.insert(h.end(), salt.begin(), salt.end());
    h.insert(h.end(), iv.begin(), iv.end());
    h.push_back(static_cast<uint8_t>(eph_len_le & 0xFF));
    h.push_back(static_cast<uint8_t>((eph_len_le >> 8) & 0xFF));
    return h;
}

static bool parse_header(const std::vector<uint8_t>& buf, size_t& off,
                         std::vector<uint8_t>& ph,
                         std::vector<uint8_t>& salt,
                         std::vector<uint8_t>& iv,
                         uint16_t& eph_len_le) {
    const size_t need = 86;
    if (buf.size() < off + need) return false;
    if (std::memcmp(buf.data()+off, "HFv1", 4) != 0) return false;
    off += 4;
    if (buf[off++] != 1) return false;
    off += 3; // reserved

    ph.resize(32);
    std::memcpy(ph.data(), buf.data()+off, 32); off += 32;
    salt.resize(32);
    std::memcpy(salt.data(), buf.data()+off, 32); off += 32;
    iv.resize(12);
    std::memcpy(iv.data(), buf.data()+off, 12); off += 12;

    eph_len_le = static_cast<uint16_t>(buf[off]) |
                 static_cast<uint16_t>(static_cast<uint16_t>(buf[off+1]) << 8);
    off += 2;
    return true;
}

// AAD = header || eph
static std::vector<uint8_t> make_aad(const std::vector<uint8_t>& header86,
                                     const std::vector<uint8_t>& eph){
    std::vector<uint8_t> aad;
    aad.reserve(header86.size() + eph.size());
    aad.insert(aad.end(), header86.begin(), header86.end());
    aad.insert(aad.end(), eph.begin(), eph.end());
    return aad;
}

// RNG wrapper: RAND_bytes returns 1 on success; anything else is failure.
static bool rand_bytes(std::vector<uint8_t>& out, size_t n){
    out.resize(n);
    if(n==0) return true;
    return RAND_bytes(out.data(), static_cast<int>(n)) == 1;
}

} // namespace

int hf::cmd_generate_keys(const std::string& keydir){
    std::unique_ptr<EC_GROUP, OpenSSLDeleter> g(build_group());
    if(!g){ std::cerr << "EC_GROUP build failed\n"; return 2; }
    std::vector<uint8_t> d, Q;
    if(!generate_keypair(g.get(), d, Q)){ std::cerr << "keygen failed\n"; return 2; }
    // write compressed pub
    if(!write_file(keydir + "/pub.comp", Q)){ std::cerr << "write pub.comp failed\n"; return 2; }
    // write PEMs
    if(!write_priv_pem(keydir + "/priv.pem", g.get(), d)){ std::cerr << "write priv.pem failed\n"; return 2; }
#if defined(__unix__) || defined(__APPLE__)
    ::chmod((keydir + "/priv.pem").c_str(), 0600);
#endif
    if(!write_pub_pem(keydir + "/pub.pem", g.get(), Q)){ std::cerr << "write pub.pem failed\n"; return 2; }
    // wipe
    secure_clean(d.data(), d.size());
    std::cout << "Generated keys in " << keydir << "\n";
    return 0;
}

int hf::cmd_validate_keys(const std::string& keydir){
    std::unique_ptr<EC_GROUP, OpenSSLDeleter> g(build_group());
    if(!g){ std::cerr << "EC_GROUP build failed\n"; return 2; }
    // read pub.pem -> compressed on ours
    std::vector<uint8_t> pem_comp;
    if(!read_pub_pem_compressed_on_ours(g.get(), keydir + "/pub.pem", pem_comp)){
        std::cerr << "Failed to parse pub.pem\n"; return 2;
    }
    if(!validate_public(g.get(), pem_comp)){
        std::cerr << "pub.pem invalid (on-curve/subgroup)\n"; return 2;
    }
    // read pub.comp and compare
    auto disk_comp = read_file(keydir + "/pub.comp");
    if(disk_comp.size()!=COMPRESSED_LEN || !validate_public(g.get(), disk_comp)){
        std::cerr << "pub.comp invalid\n"; return 2;
    }
    if(disk_comp != pem_comp){
        std::cerr << "pub.comp != compressed(pub.pem) — re-export pub.comp from PEM\n"; return 2;
    }
    std::cout << "Keys validate: OK\n";
    return 0;
}

int hf::cmd_benchmark(const std::string& keydir, int seconds){
    std::unique_ptr<EC_GROUP, OpenSSLDeleter> g(build_group());
    if(!g){ std::cerr << "EC_GROUP build failed\n"; return 2; }
    // Load recipient pub (self) from pub.pem
    std::vector<uint8_t> Qrec;
    if(!read_pub_pem_compressed_on_ours(g.get(), keydir + "/pub.pem", Qrec)){
        std::cerr << "Need a valid keys/pub.pem. Run --generate-keys first.\n"; return 2;
    }
    // Benchmark: ECDH derive loops/sec
    using clock=std::chrono::steady_clock;
    auto start = clock::now();
    size_t iters=0;
    while(std::chrono::duration_cast<std::chrono::seconds>(clock::now()-start).count() < seconds){
        std::vector<uint8_t> d, epub, sharedx;
        if(!generate_keypair(g.get(), d, epub)) return 2;
        if(!ecdh_x(g.get(), d, Qrec, sharedx)) return 2;
        secure_clean(d.data(), d.size());
        secure_clean(sharedx.data(), sharedx.size());
        ++iters;
    }
    const double secs = static_cast<double>(seconds);
    const double ops_per_sec = secs > 0.0 ? static_cast<double>(iters) / secs : 0.0;
    std::cout << "ECDH derivations: " << iters << " in " << secs
              << " s  => " << ops_per_sec << " ops/s\n";
    return 0;
}

int hf::cmd_encrypt(const std::string& keydir, const std::string& in_path, const std::string& out_path){
    std::unique_ptr<EC_GROUP, OpenSSLDeleter> g(build_group());
    if(!g){ std::cerr << "EC_GROUP build failed\n"; return 2; }
    // Recipient pub.pem -> compressed on ours
    std::vector<uint8_t> Qrec;
    if(!read_pub_pem_compressed_on_ours(g.get(), keydir + "/pub.pem", Qrec)){
        std::cerr << "Failed to read recipient pub.pem\n"; return 2;
    }
    if(!validate_public(g.get(), Qrec)){ std::cerr << "Recipient pub invalid\n"; return 2; }
    auto pt = read_file(in_path);
    if(pt.empty()){ std::cerr << "Input empty or unreadable\n"; return 2; }

    // Ephemeral key
    std::vector<uint8_t> epriv, epub;
    if(!generate_keypair(g.get(), epriv, epub)){ std::cerr << "Ephemeral keygen failed\n"; return 2; }
    // Shared x
    std::vector<uint8_t> sharedx;
    if(!ecdh_x(g.get(), epriv, Qrec, sharedx)){ std::cerr << "ECDH derive failed\n"; return 2; }

    // KDF
    std::vector<uint8_t> salt; if(!rand_bytes(salt, 32)){ std::cerr << "RNG salt failed\n"; return 2; }
    auto ph = param_hash();
    std::vector<uint8_t> info = ph;
    info.insert(info.end(), INFO_LABEL, INFO_LABEL + std::strlen(INFO_LABEL));
    std::vector<uint8_t> key;
    if(!hkdf_sha256(key, 32, sharedx, salt, info)){ std::cerr << "HKDF failed\n"; return 2; }
    // IV
    std::vector<uint8_t> iv; if(!rand_bytes(iv, 12)){ std::cerr << "RNG iv failed\n"; return 2; }

    auto header = pack_header(ph, salt, iv, static_cast<uint16_t>(COMPRESSED_LEN));
    auto aad = make_aad(header, epub);
    std::vector<uint8_t> ct, tag;
    if(!aes256gcm_encrypt(key, iv, aad, pt, ct, tag)){ std::cerr << "GCM encrypt failed\n"; return 2; }

    // Serialize file: header(86) | eph | ct | tag | [8-byte BE ct_len]
    std::vector<uint8_t> out;
    out.insert(out.end(), header.begin(), header.end());
    out.insert(out.end(), epub.begin(), epub.end());
    out.insert(out.end(), ct.begin(), ct.end());
    out.insert(out.end(), tag.begin(), tag.end());
    uint8_t clen_be[8]; be64enc(clen_be, (uint64_t)ct.size());
    out.insert(out.end(), clen_be, clen_be+8);

    int ok = write_file(out_path, out) ? 0 : 2;
    secure_clean(epriv.data(), epriv.size());
    secure_clean(key.data(), key.size());
    secure_clean(sharedx.data(), sharedx.size());
    if(ok==0) std::cout << "Wrote " << out_path << "\n";
    return ok;
}

int hf::cmd_decrypt(const std::string& keydir, const std::string& in_path, const std::string& out_path){
    std::unique_ptr<EC_GROUP, OpenSSLDeleter> g(build_group());
    if(!g){ std::cerr << "EC_GROUP build failed\n"; return 2; }
    auto buf = read_file(in_path);
    const size_t min = (4+1+3+32+32+12+2) + COMPRESSED_LEN + 16 + 8;
    if(buf.size() < min){ std::cerr << "Input too small\n"; return 2; }
    size_t off=0;
    std::vector<uint8_t> phdr, salt, iv; uint16_t eph_le=0;
    if(!parse_header(buf, off, phdr, salt, iv, eph_le)){ std::cerr << "Bad header\n"; return 2; }
    if(eph_le != COMPRESSED_LEN){ std::cerr << "Bad eph_len\n"; return 2; }
    auto ph = param_hash();
    if(phdr != ph){ std::cerr << "param_hash mismatch\n"; return 2; }

    std::vector<uint8_t> eph(COMPRESSED_LEN);
    std::memcpy(eph.data(), buf.data()+off, COMPRESSED_LEN); off += COMPRESSED_LEN;
    if(!validate_public(g.get(), eph)){ std::cerr << "Ephemeral invalid\n"; return 2; }

    if(buf.size() < off + 16 + 8){ std::cerr << "Truncated\n"; return 2; }
    uint64_t clen = be64dec(&buf[buf.size()-8]);
    if(off + clen + 16 + 8 != buf.size()){ std::cerr << "Length mismatch\n"; return 2; }
    size_t ct_off = off;
    size_t tag_off = off + (size_t)clen;

    std::vector<uint8_t> ct((size_t)clen);
    std::memcpy(ct.data(), buf.data()+ct_off, (size_t)clen);
    std::vector<uint8_t> tag(16);
    std::memcpy(tag.data(), buf.data()+tag_off, 16);

    // Load priv.pem → get d (BE)
    std::vector<uint8_t> d_be;
    {
        uptr<BIO> bio(BIO_new_file((keydir + "/priv.pem").c_str(), "r"));
        if(!bio){ std::cerr << "Cannot open priv.pem\n"; return 2; }
        uptr<EC_KEY> k(PEM_read_bio_ECPrivateKey(bio.get(), nullptr, nullptr, nullptr));
        if(!k){ std::cerr << "Invalid priv.pem\n"; return 2; }
        const BIGNUM* d = EC_KEY_get0_private_key(k.get());
        if(!d){ std::cerr << "Missing private scalar\n"; return 2; }
        int nbits = BN_num_bits(d);
        size_t nbytes = (size_t)((nbits + 7)/8);
        d_be.assign(nbytes, 0);
        BN_bn2binpad(d, d_be.data(), (int)nbytes);
    }

    // ECDH derive x
    std::vector<uint8_t> sharedx;
    if(!ecdh_x(g.get(), d_be, eph, sharedx)){ std::cerr << "ECDH derive failed\n"; return 2; }

    std::vector<uint8_t> info = ph;
    info.insert(info.end(), INFO_LABEL, INFO_LABEL + std::strlen(INFO_LABEL));
    std::vector<uint8_t> key;
    auto iv_copy = iv;
    auto salt_copy = salt;
    if(!hkdf_sha256(key, 32, sharedx, salt_copy, info)){ std::cerr << "HKDF failed\n"; return 2; }

    auto header = pack_header(ph, salt, iv, static_cast<uint16_t>(COMPRESSED_LEN));
    auto aad = make_aad(header, eph);
    std::vector<uint8_t> pt;
    if(!aes256gcm_decrypt(key, iv_copy, aad, ct, tag, pt)){ std::cerr << "GCM auth/decrypt failed\n"; return 2; }

    int ok = write_file(out_path, pt) ? 0 : 2;
    secure_clean(key.data(), key.size());
    secure_clean(sharedx.data(), sharedx.size());
    secure_clean(d_be.data(), d_be.size());
    if(ok==0) std::cout << "Wrote " << out_path << "\n";
    return ok;
}
