
#include <cstdio>
#include <cstdlib>
#include <cstring> // FIX: for std::memcpy / std::memcmp
#include <string>
#include <vector>
#include <memory>
#include <array>
#include <fstream>
#include <sstream>
#include <chrono>
#include <openssl/rand.h>
#include <openssl/sha.h>

#include "hf/backend.hpp"
#include "hf/params.hpp"
#include "hf/crypto.hpp"

extern "C" hf::Backend* hf_make_backend();

namespace hf {

static std::unique_ptr<Backend> make_backend(){
    return std::unique_ptr<Backend>(hf_make_backend());
}

static std::vector<unsigned char> read_file(const std::string& path){
    std::ifstream f(path, std::ios::binary);
    if(!f) return {};
    f.seekg(0, std::ios::end); size_t n=(size_t)f.tellg(); f.seekg(0);
    std::vector<unsigned char> buf(n);
    f.read((char*)buf.data(), n);
    return buf;
}
static bool write_file(const std::string& path, const std::vector<unsigned char>& data){
    std::ofstream f(path, std::ios::binary);
    if(!f) return false;
    f.write((const char*)data.data(), (std::streamsize)data.size());
    return true;
}

int cmd_generate(){
    auto be = make_backend();
    hf::KeyPair kp;
    if(!be->generate_keypair(kp, "OS-RNG")){ std::fprintf(stderr,"keygen failed\n"); return 1; }
    system("mkdir -p keys >/dev/null 2>&1");
    if(!write_file("keys/priv.pem", kp.priv_pem)){ std::fprintf(stderr,"write priv.pem failed\n"); return 1; }
    if(!write_file("keys/pub.pem", kp.pub_pem)){ std::fprintf(stderr,"write pub.pem failed\n"); return 1; }
    if(!write_file("keys/pub.comp", kp.pub_compressed)){ std::fprintf(stderr,"write pub.comp failed\n"); return 1; }
    std::printf("OK: keys/priv.pem + keys/pub.pem + keys/pub.comp\n");
    return 0;
}

int cmd_validate(){
    auto be = make_backend();
    auto prv = read_file("keys/priv.pem");
    auto pub = read_file("keys/pub.pem");
    if(prv.empty() || pub.empty()){ std::fprintf(stderr,"missing keys\n"); return 1; }
    if(!be->validate_keypair(prv, pub, "OS-RNG")){ std::fprintf(stderr,"invalid keypair\n"); return 1; }
    std::printf("OK: keypair valid\n");
    return 0;
}

int cmd_bench(){
    auto be = make_backend();
    // simple ECDH loop
    auto prv = read_file("keys/priv.pem");
    auto pub = read_file("keys/pub.pem");
    if(prv.empty() || pub.empty()){ std::fprintf(stderr,"missing keys (generate first)\n"); return 1; }
    const int iters = 1000;
    std::vector<unsigned char> ss;
    auto t0 = std::chrono::high_resolution_clock::now();
    for(int i=0;i<iters;i++){
        if(!be->ecdh(ss, prv, pub, "OS-RNG")){ std::fprintf(stderr,"ecdh failed\n"); return 1; }
    }
    auto t1 = std::chrono::high_resolution_clock::now();
    double ms = std::chrono::duration<double, std::milli>(t1-t0).count();
    std::printf("ECDH %d iters: %.2f ms total, %.3f ms/op, %.2f ops/s\n",
        iters, ms, ms/iters, 1000.0/(ms/iters));
    return 0;
}

// ---- File format ----
struct __attribute__((packed)) Header {
    char magic[4];      // "HFv1"
    uint8_t version;    // 1
    uint8_t reserved[3];
    unsigned char param_hash[32];
    unsigned char salt[32];
    unsigned char iv[12];
    uint16_t eph_len;   // compressed ephemeral size
};

int cmd_encrypt(const std::string& file){
    auto be = make_backend();
    auto prv = read_file("keys/priv.pem");
    auto pub = read_file("keys/pub.pem");
    if(prv.empty() || pub.empty()){ std::fprintf(stderr,"missing keys (generate first)\n"); return 1; }

    auto plain = read_file(file);
    if(plain.empty()){ std::fprintf(stderr,"input file empty or not found\n"); return 1; }

    // ephemeral key
    hf::KeyPair eph;
    if(!be->generate_keypair(eph, "OS-RNG")){ std::fprintf(stderr,"ephemeral keygen failed\n"); return 1; }

    // shared secret
    std::vector<unsigned char> ss;
    if(!be->ecdh(ss, eph.priv_pem, pub, "OS-RNG")){ std::fprintf(stderr,"ecdh failed\n"); return 1; }

    // HKDF => 32 byte key
    std::vector<unsigned char> salt(32); RAND_bytes(salt.data(), 32);
    auto ph = hf::param_hash();

    std::vector<unsigned char> info; info.reserve(32+4+1);
    info.insert(info.end(), ph.begin(), ph.end());
    const char ctx[] = "HippoFrog v2.2 AES-256-GCM";
    info.insert(info.end(), ctx, ctx+sizeof(ctx)-1);

    auto key = hf::hkdf_sha256(ss, salt, info, 32);
    std::vector<unsigned char> iv(12); RAND_bytes(iv.data(), 12);

    // Build header (without eph yet)
    Header h{};
    h.magic[0]='H'; h.magic[1]='F'; h.magic[2]='v'; h.magic[3]='1';
    h.version = 1;
    std::memcpy(h.param_hash, ph.data(), 32);
    std::memcpy(h.salt, salt.data(), 32);
    std::memcpy(h.iv, iv.data(), 12);
    if(eph.pub_compressed.size()>65535){ std::fprintf(stderr,"ephemeral too long\n"); return 1; }
    h.eph_len = (uint16_t)eph.pub_compressed.size();

    // AAD = header bytes + ephemeral compressed
    std::vector<unsigned char> aad(sizeof(Header));
    std::memcpy(aad.data(), &h, sizeof(Header));
    aad.insert(aad.end(), eph.pub_compressed.begin(), eph.pub_compressed.end());

    std::vector<unsigned char> ciphertext;
    std::array<unsigned char,16> tag{};
    hf::aes256gcm_encrypt(key, iv, aad, plain, ciphertext, tag);

    // Output layout: [Header][eph_len bytes][ciphertext][tag]
    std::vector<unsigned char> out;
    out.resize(sizeof(Header));
    std::memcpy(out.data(), &h, sizeof(Header));
    out.insert(out.end(), eph.pub_compressed.begin(), eph.pub_compressed.end());
    out.insert(out.end(), ciphertext.begin(), ciphertext.end());
    out.insert(out.end(), tag.begin(), tag.end());

    std::string ofile = file + ".hf";
    if(!write_file(ofile, out)){ std::fprintf(stderr,"write out failed\n"); return 1; }
    std::printf("OK: %s\n", ofile.c_str());
    return 0;
}

int cmd_decrypt(const std::string& file){
    auto be = make_backend();
    auto prv = read_file("keys/priv.pem");
    if(prv.empty()){ std::fprintf(stderr,"missing keys/priv.pem\n"); return 1; }

    auto blob = read_file(file);
    if(blob.size() < sizeof(Header)+16){ std::fprintf(stderr,"file too small\n"); return 1; }

    Header h{};
    std::memcpy(&h, blob.data(), sizeof(Header));
    if(!(h.magic[0]=='H' && h.magic[1]=='F' && h.magic[2]=='v' && h.magic[3]=='1' && h.version==1)){
        std::fprintf(stderr,"bad header\n"); return 1;
    }
    size_t pos = sizeof(Header);
    if(blob.size() < pos + h.eph_len + 16){ std::fprintf(stderr,"file corrupted\n"); return 1; }
    std::vector<unsigned char> eph_comp(blob.begin()+pos, blob.begin()+pos+h.eph_len); pos += h.eph_len;

    if(blob.size() < pos + 16){ std::fprintf(stderr,"file corrupted\n"); return 1; }
    std::array<unsigned char,16> tag{};
    std::memcpy(tag.data(), blob.data() + blob.size()-16, 16);
    std::vector<unsigned char> ciphertext(blob.begin()+pos, blob.end()-16);

    // Build SPKI from ephemeral compressed
    std::vector<unsigned char> eph_spki;
    if(!be->spki_from_compressed(eph_spki, eph_comp)){ std::fprintf(stderr,"bad ephemeral\n"); return 1; }
    if(!be->subgroup_check_spki(eph_spki)){ std::fprintf(stderr,"ephemeral subgroup check failed\n"); return 1; }

    // ECDH shared
    std::vector<unsigned char> ss;
    if(!be->ecdh(ss, prv, eph_spki, "OS-RNG")){ std::fprintf(stderr,"ecdh failed\n"); return 1; }

    // HKDF
    auto ph = hf::param_hash();
    std::vector<unsigned char> salt(h.salt, h.salt+32);
    std::vector<unsigned char> info; info.reserve(32+32);
    info.insert(info.end(), ph.begin(), ph.end());
    const char ctx[] = "HippoFrog v2.2 AES-256-GCM";
    info.insert(info.end(), ctx, ctx+sizeof(ctx)-1);
    auto key = hf::hkdf_sha256(ss, salt, info, 32);
    std::vector<unsigned char> iv(h.iv, h.iv+12);

    // Recreate AAD
    std::vector<unsigned char> aad(sizeof(Header));
    std::memcpy(aad.data(), &h, sizeof(Header));
    aad.insert(aad.end(), eph_comp.begin(), eph_comp.end());

    // Check param hash
    if(std::memcmp(h.param_hash, ph.data(), 32)!=0){
        std::fprintf(stderr,"param hash mismatch\n"); return 1;
    }

    std::vector<unsigned char> plain;
    if(!hf::aes256gcm_decrypt(key, iv, aad, ciphertext, tag, plain)){
        std::fprintf(stderr,"GCM auth failed\n"); return 1;
    }

    // Write output file (remove .hf)
    std::string out = file;
    if(out.size()>=3 && out.substr(out.size()-3)==".hf") out = out.substr(0, out.size()-3);
    else out += ".out";
    if(!write_file(out, plain)){ std::fprintf(stderr,"write output failed\n"); return 1; }
    std::printf("OK: %s\n", out.c_str());
    return 0;
}

} // namespace hf
