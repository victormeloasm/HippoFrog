
#include <cstdio>
#include <vector>
#include <string>
#include <memory>
#include <array>
#include <cassert>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/pem.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/obj_mac.h>

#include "hf/backend.hpp"
#include "hf/params.hpp"
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"

namespace {

struct BIO_free_all_del { void operator()(BIO* b) const { if(b) BIO_free(b); } };
struct EVP_PKEY_free_del { void operator()(EVP_PKEY* p) const { if(p) EVP_PKEY_free(p); } };
struct EC_GROUP_free_del { void operator()(EC_GROUP* g) const { if(g) EC_GROUP_free(g); } };
struct EC_POINT_free_del { void operator()(EC_POINT* p) const { if(p) EC_POINT_free(p); } };
struct EC_KEY_free_del   { void operator()(EC_KEY* k) const { if(k) EC_KEY_free(k); } };

using up_bio = std::unique_ptr<BIO, BIO_free_all_del>;
using up_pkey = std::unique_ptr<EVP_PKEY, EVP_PKEY_free_del>;
using up_group = std::unique_ptr<EC_GROUP, EC_GROUP_free_del>;
using up_point = std::unique_ptr<EC_POINT, EC_POINT_free_del>;
using up_eckey = std::unique_ptr<EC_KEY, EC_KEY_free_del>;

up_group make_group() {
    // Build curve from decimal strings in hf::params with proper BIGNUM handling
    BIGNUM *p = BN_new();
    BIGNUM *a = BN_new();
    BIGNUM *b = BN_new();
    if(!p || !a || !b) { if(p) BN_free(p); if(a) BN_free(a); if(b) BN_free(b); return up_group(nullptr); }
    // Parse decimal parameters
    BN_dec2bn(&p, hf::P_DEC);
    // A is provided as a signed integer in hf::A_INT
    if (hf::A_INT < 0) {
        BN_set_word(a, (unsigned long)(- (long)hf::A_INT));
        BN_set_negative(a, 1);
    } else {
        BN_set_word(a, (unsigned long)hf::A_INT);
    }
    BN_dec2bn(&b, hf::B_DEC);
    EC_GROUP* g = EC_GROUP_new_curve_GFp(p, a, b, nullptr);
    BN_free(p); BN_free(a); BN_free(b);
    if(!g) return up_group(nullptr);
    // Set generator, order, and cofactor
    BIGNUM *gx = BN_new(), *gy = BN_new(), *n = BN_new(), *h = BN_new();
    if(!gx || !gy || !n || !h) { if(gx) BN_free(gx); if(gy) BN_free(gy); if(n) BN_free(n); if(h) BN_free(h); EC_GROUP_free(g); return up_group(nullptr); }
    BN_dec2bn(&gx, hf::GX_DEC);
    BN_dec2bn(&gy, hf::GY_DEC);
    BN_dec2bn(&n,  hf::N_DEC);
    BN_set_word(h, (unsigned long)1); // cofactor h=1 (prime-order subgroup)
    EC_POINT* G = EC_POINT_new(g);
    if(!G) { BN_free(gx); BN_free(gy); BN_free(n); BN_free(h); EC_GROUP_free(g); return up_group(nullptr); }
    if(EC_POINT_set_affine_coordinates(g, G, gx, gy, nullptr) != 1) {
        EC_POINT_free(G); BN_free(gx); BN_free(gy); BN_free(n); BN_free(h); EC_GROUP_free(g); return up_group(nullptr);
    }
    if(EC_GROUP_set_generator(g, G, n, h) != 1) {
        EC_POINT_free(G); BN_free(gx); BN_free(gy); BN_free(n); BN_free(h); EC_GROUP_free(g); return up_group(nullptr);
    }
    EC_POINT_free(G); BN_free(gx); BN_free(gy); BN_free(n); BN_free(h);
    return up_group(g);
}

bool write_pem_priv(std::vector<unsigned char>& out, EC_KEY* e){
    up_bio bio(BIO_new(BIO_s_mem()));
    if(!PEM_write_bio_ECPrivateKey(bio.get(), e, nullptr, nullptr, 0, nullptr, nullptr)) return false;
    char* data=nullptr; long len = BIO_get_mem_data(bio.get(), &data);
    out.assign((unsigned char*)data, (unsigned char*)data + len);
    return true;
}
bool write_pem_pub(std::vector<unsigned char>& out, EVP_PKEY* p){
    up_bio bio(BIO_new(BIO_s_mem()));
    if(!PEM_write_bio_PUBKEY(bio.get(), p)) return false;
    char* data=nullptr; long len = BIO_get_mem_data(bio.get(), &data);
    out.assign((unsigned char*)data, (unsigned char*)data + len);
    return true;
}
EC_KEY* read_priv_from_pem(const std::vector<unsigned char>& pem){
    up_bio bio(BIO_new_mem_buf(pem.data(), (int)pem.size()));
    return PEM_read_bio_ECPrivateKey(bio.get(), nullptr, nullptr, nullptr);
}
EVP_PKEY* read_pub_from_pem(const std::vector<unsigned char>& pem){
    up_bio bio(BIO_new_mem_buf(pem.data(), (int)pem.size()));
    return PEM_read_bio_PUBKEY(bio.get(), nullptr, nullptr, nullptr);
}

bool spki_to_point(const std::vector<unsigned char>& spki_pem, EC_GROUP* g, EC_POINT* Q){
    up_pkey pk(read_pub_from_pem(spki_pem));
    if(!pk) return false;
    // Use EC_KEY for simplicity (OpenSSL 3.x marks some APIs deprecated)
    EC_KEY* e=EVP_PKEY_get1_EC_KEY(pk.get());
    if(!e) return false;
    const EC_POINT* Pub = EC_KEY_get0_public_key(e);
    if(!Pub){ EC_KEY_free(e); return false; }
    bool ok = (EC_POINT_copy(Q, Pub)==1);
    EC_KEY_free(e);
    return ok;
}

std::vector<unsigned char> point_compress(EC_GROUP* g, const EC_POINT* Q){
    std::vector<unsigned char> out(1 + (EC_GROUP_get_degree(g)+7)/8);
    size_t len = EC_POINT_point2oct(g, Q, POINT_CONVERSION_COMPRESSED, out.data(), out.size(), nullptr);
    out.resize(len);
    return out;
}

bool point_decompress(EC_GROUP* g, EC_POINT* Q, const std::vector<unsigned char>& comp){
    return EC_POINT_oct2point(g, Q, comp.data(), comp.size(), nullptr)==1;
}

bool subgroup_check_N(EC_GROUP* g, const EC_POINT* Q){
    // check Q != O, on-curve, and N*Q == O
    BIGNUM* n = BN_new(); BN_dec2bn(&n, hf::N_DEC);
    up_point T(EC_POINT_new(g));
    if(EC_POINT_is_on_curve(g, Q, nullptr) != 1){ BN_free(n); return false; }
    if(EC_POINT_mul(g, T.get(), nullptr, Q, n, nullptr) != 1){ BN_free(n); return false; }
    int atinf = EC_POINT_is_at_infinity(g, T.get());
    BN_free(n);
    return atinf==1;
}

class OpenSSLBackend final : public hf::Backend {
    up_group grp_;
public:
    OpenSSLBackend(): grp_(make_group()) {}
    EC_GROUP* grp(){ return grp_.get(); }

    bool generate_keypair(hf::KeyPair& kp, const char* /*rng_info*/) override {
        if(!grp_) return false;
        up_eckey e(EC_KEY_new());
        if(!e) return false;
        if(EC_KEY_set_group(e.get(), grp_.get())!=1) return false;
        if(EC_KEY_generate_key(e.get())!=1) return false;
        up_pkey p(EVP_PKEY_new());
        if(!p) return false;
        if(EVP_PKEY_assign_EC_KEY(p.get(), e.release())!=1) return false;
        if(!write_pem_priv(kp.priv_pem, EVP_PKEY_get1_EC_KEY(p.get()))) return false;
        if(!write_pem_pub(kp.pub_pem, p.get())) return false;

        const EC_POINT* Q = EC_KEY_get0_public_key(EVP_PKEY_get1_EC_KEY(p.get()));
        kp.pub_compressed = point_compress(grp_.get(), Q);
        return true;
    }

    bool validate_keypair(const std::vector<unsigned char>& priv_pem,
                          const std::vector<unsigned char>& pub_pem,
                          const char* /*rng_info*/) override {
        if(!grp_) return false;
        up_eckey e(read_priv_from_pem(priv_pem));
        if(!e) return false;
        const BIGNUM* d = EC_KEY_get0_private_key(e.get());
        if(!d) return false;
        // Recompute d*G and compare to SPKI public
        up_pkey pk(read_pub_from_pem(pub_pem));
        if(!pk) return false;
        EC_KEY* epk = EVP_PKEY_get1_EC_KEY(pk.get());
        if(!epk){ return false; }
        const EC_POINT* Qpub = EC_KEY_get0_public_key(epk);

        up_point R(EC_POINT_new(grp_.get()));
        if(EC_POINT_mul(grp_.get(), R.get(), d, nullptr, nullptr, nullptr)!=1){ EC_KEY_free(epk); return false; }
        int eq = EC_POINT_cmp(grp_.get(), Qpub, R.get(), nullptr);
        EC_KEY_free(epk);
        if(eq!=0) return false;
        return subgroup_check_N(grp_.get(), Qpub);
    }

    bool ecdh(std::vector<unsigned char>& shared,
              const std::vector<unsigned char>& priv_pem,
              const std::vector<unsigned char>& peer_pub_pem,
              const char* /*rng_info*/) override {
        if(!grp_) return false;
        up_eckey e(read_priv_from_pem(priv_pem));
        if(!e) return false;
        up_pkey peer(read_pub_from_pem(peer_pub_pem));
        if(!peer) return false;
        EC_KEY* ecp = EVP_PKEY_get1_EC_KEY(peer.get());
        if(!ecp) return false;
        const EC_POINT* Q = EC_KEY_get0_public_key(ecp);
        if(!Q){ EC_KEY_free(ecp); return false; }
        if(!subgroup_check_N(grp_.get(), Q)){ EC_KEY_free(ecp); return false; }

        // Compute shared = x-coordinate of d*Q
        up_point T(EC_POINT_new(grp_.get()));
        const BIGNUM* d = EC_KEY_get0_private_key(e.get());
        if(EC_POINT_mul(grp_.get(), T.get(), nullptr, Q, d, nullptr)!=1){ EC_KEY_free(ecp); return false; }
        BIGNUM* x = BN_new(); BIGNUM* y = BN_new();
        if(EC_POINT_get_affine_coordinates(grp_.get(), T.get(), x, y, nullptr)!=1){ BN_free(x); BN_free(y); EC_KEY_free(ecp); return false; }
        int nbytes = BN_num_bytes(x);
        shared.resize((size_t)nbytes);
        BN_bn2binpad(x, shared.data(), nbytes);
        BN_free(x); BN_free(y); EC_KEY_free(ecp);
        return true;
    }

    bool spki_from_compressed(std::vector<unsigned char>& spki_pem,
                              const std::vector<unsigned char>& comp_bytes) override {
        if(!grp_) return false;
        up_eckey e(EC_KEY_new());
        if(!e) return false;
        if(EC_KEY_set_group(e.get(), grp_.get())!=1) return false;
        up_point Q(EC_POINT_new(grp_.get()));
        if(!point_decompress(grp_.get(), Q.get(), comp_bytes)) return false;
        if(EC_POINT_is_on_curve(grp_.get(), Q.get(), nullptr)!=1) return false;
        if(EC_POINT_is_at_infinity(grp_.get(), Q.get())==1) return false;
        if(EC_KEY_set_public_key(e.get(), Q.get())!=1) return false;
        up_pkey p(EVP_PKEY_new());
        if(!p) return false;
        if(EVP_PKEY_assign_EC_KEY(p.get(), e.release())!=1) return false;
        // write PEM
        BIO* bio = BIO_new(BIO_s_mem());
        if(!bio) return false;
        bool ok = PEM_write_bio_PUBKEY(bio, p.get())==1;
        if(!ok){ BIO_free(bio); return false; }
        char* data=nullptr; long len = BIO_get_mem_data(bio, &data);
        spki_pem.assign((unsigned char*)data, (unsigned char*)data + len);
        BIO_free(bio);
        return true;
    }

    bool compressed_from_spki(std::vector<unsigned char>& comp_bytes,
                              const std::vector<unsigned char>& spki_pem) override {
        if(!grp_) return false;
        up_pkey pk(read_pub_from_pem(spki_pem));
        if(!pk) return false;
        EC_KEY* e = EVP_PKEY_get1_EC_KEY(pk.get());
        if(!e) return false;
        const EC_POINT* Q = EC_KEY_get0_public_key(e);
        if(!Q){ EC_KEY_free(e); return false; }
        comp_bytes = point_compress(grp_.get(), Q);
        EC_KEY_free(e);
        return true;
    }

    bool subgroup_check_spki(const std::vector<unsigned char>& spki_pem) override {
        if(!grp_) return false;
        up_pkey pk(read_pub_from_pem(spki_pem));
        if(!pk) return false;
        EC_KEY* e = EVP_PKEY_get1_EC_KEY(pk.get());
        if(!e) return false;
        const EC_POINT* Q = EC_KEY_get0_public_key(e);
        if(!Q){ EC_KEY_free(e); return false; }
        bool ok = subgroup_check_N(grp_.get(), Q);
        EC_KEY_free(e);
        return ok;
    }
};

} // anonymous

extern "C" hf::Backend* hf_make_backend(){
    return new OpenSSLBackend();
}