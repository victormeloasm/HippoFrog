
#pragma once
#include <vector>
#include <string>
#include <memory>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/pem.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include "params.hpp"
#include "util.hpp"

namespace hf {

struct OpenSSLDeleter {
    void operator()(BIGNUM* p) const { BN_free(p); }
    void operator()(BN_CTX* p) const { BN_CTX_free(p); }
    void operator()(EC_GROUP* p) const { EC_GROUP_free(p); }
    void operator()(EC_POINT* p) const { EC_POINT_free(p); }
    void operator()(EC_KEY* p) const { EC_KEY_free(p); }
    void operator()(BIO* p) const { BIO_free(p); }
};
template<class T> using uptr = std::unique_ptr<T, OpenSSLDeleter>;

inline uptr<BIGNUM> bn_from_dec(const char* s){
    BIGNUM* tmp=nullptr;
    if(BN_dec2bn(&tmp, s)==0) return uptr<BIGNUM>(nullptr);
    return uptr<BIGNUM>(tmp);
}

// Build EC_GROUP for ECCFrog522PP
inline EC_GROUP* build_group(){
    uptr<BN_CTX> ctx(BN_CTX_new()); if(!ctx) return nullptr;
    auto P  = bn_from_dec(P_DEC);
    auto A  = bn_from_dec(A_DEC);
    auto B  = bn_from_dec(B_DEC);
    auto N  = bn_from_dec(N_DEC);
    auto Gx = bn_from_dec(GX_DEC);
    auto Gy = bn_from_dec(GY_DEC);
    if(!P||!A||!B||!N||!Gx||!Gy) return nullptr;
    EC_GROUP* g = EC_GROUP_new_curve_GFp(P.get(), A.get(), B.get(), ctx.get());
    if(!g) return nullptr;
    uptr<EC_GROUP> guard(g);
    EC_POINT* G = EC_POINT_new(g); if(!G) return nullptr;
    uptr<EC_POINT> gG(G);
    if(EC_POINT_set_affine_coordinates(g, G, Gx.get(), Gy.get(), ctx.get())!=1) return nullptr;
    if(EC_GROUP_set_generator(g, G, N.get(), nullptr)!=1) return nullptr;
    if(EC_GROUP_check(g, ctx.get())!=1) return nullptr;
    guard.release();
    return g;
}

// SHA256 over decimal params (no label here; used to build param_hash)
inline std::vector<uint8_t> param_hash(){
    std::string s = std::string(P_DEC) + "|" + A_DEC + "|" + B_DEC + "|" + N_DEC + "|" + GX_DEC + "|" + GY_DEC;
    std::vector<uint8_t> out(SHA256_DIGEST_LENGTH);
    SHA256(reinterpret_cast<const unsigned char*>(s.data()), s.size(), out.data());
    return out;
}

// Serialize point (on its group) to compressed octets
inline bool point_to_oct(const EC_GROUP* g, const EC_POINT* Q, std::vector<uint8_t>& out){
    uptr<BN_CTX> ctx(BN_CTX_new()); if(!ctx) return false;
    size_t len = EC_POINT_point2oct(g, Q, POINT_CONVERSION_COMPRESSED, nullptr, 0, ctx.get());
    if(len==0) return false;
    out.resize(len);
    return EC_POINT_point2oct(g, Q, POINT_CONVERSION_COMPRESSED, out.data(), len, ctx.get())==len;
}

// Parse compressed octets on OUR group to EC_POINT*
inline uptr<EC_POINT> oct_to_point(EC_GROUP* g, const std::vector<uint8_t>& oct){
    uptr<BN_CTX> ctx(BN_CTX_new()); if(!ctx) return nullptr;
    uptr<EC_POINT> Q(EC_POINT_new(g)); if(!Q) return nullptr;
    if(EC_POINT_oct2point(g, Q.get(), oct.data(), oct.size(), ctx.get())!=1) return nullptr;
    return Q;
}

// Validate public key: canonical length, on-curve, not infinity, and subgroup [N]Q==O
inline bool validate_public(EC_GROUP* g, const std::vector<uint8_t>& oct){
    if(oct.size()!=COMPRESSED_LEN) return false;
    uptr<BN_CTX> ctx(BN_CTX_new()); if(!ctx) return false;
    uptr<EC_POINT> Q(EC_POINT_new(g)); if(!Q) return false;
    if(EC_POINT_oct2point(g, Q.get(), oct.data(), oct.size(), ctx.get())!=1) return false;
    if(EC_POINT_is_at_infinity(g, Q.get())==1) return false;
    if(EC_POINT_is_on_curve(g, Q.get(), ctx.get())!=1) return false;
    auto n = bn_from_dec(N_DEC); if(!n) return false;
    uptr<EC_POINT> R(EC_POINT_new(g)); if(!R) return false;
    if(EC_POINT_mul(g, R.get(), nullptr, Q.get(), n.get(), ctx.get())!=1) return false;
    if(EC_POINT_is_at_infinity(g, R.get())!=1) return false; // must be infinity
    return true;
}

// ECDH derive x-coordinate from private d and peer octets (validated)
inline bool ecdh_x(EC_GROUP* g, const std::vector<uint8_t>& priv_be,
                   const std::vector<uint8_t>& peer_oct, std::vector<uint8_t>& x_be){
    // parse d
    uptr<BIGNUM> d(BN_bin2bn(priv_be.data(), (int)priv_be.size(), nullptr)); if(!d) return false;
    // parse peer
    if(!validate_public(g, peer_oct)) return false;
    auto Q = oct_to_point(g, peer_oct); if(!Q) return false;
    uptr<BN_CTX> ctx(BN_CTX_new()); if(!ctx) return false;
    uptr<EC_POINT> S(EC_POINT_new(g)); if(!S) return false;
    if(EC_POINT_mul(g, S.get(), nullptr, Q.get(), d.get(), ctx.get())!=1) return false;
    if(EC_POINT_is_at_infinity(g, S.get())==1) return false;
    uptr<BIGNUM> x(BN_new()), y(BN_new()); if(!x||!y) return false;
    if(EC_POINT_get_affine_coordinates(g, S.get(), x.get(), y.get(), ctx.get())!=1) return false;
    int pbits = EC_GROUP_get_degree(g);
    size_t pbytes = (size_t)((pbits + 7)/8);
    x_be.assign(pbytes, 0);
    BN_bn2binpad(x.get(), x_be.data(), (int)pbytes);
    return true;
}

// PEM helpers for custom curve (explicit params)
inline bool write_priv_pem(const std::string& path, EC_GROUP* g, const std::vector<uint8_t>& d_be){
    uptr<EC_KEY> k(EC_KEY_new()); if(!k) return false;
    if(EC_KEY_set_group(k.get(), g)!=1) return false;
    uptr<BIGNUM> d(BN_bin2bn(d_be.data(), (int)d_be.size(), nullptr)); if(!d) return false;
    if(EC_KEY_set_private_key(k.get(), d.get())!=1) return false;
    // compute public for completeness
    uptr<BN_CTX> ctx(BN_CTX_new()); if(!ctx) return false;
    uptr<EC_POINT> Q(EC_POINT_new(g)); if(!Q) return false;
    if(EC_POINT_mul(g, Q.get(), d.get(), nullptr, nullptr, ctx.get())!=1) return false;
    if(EC_KEY_set_public_key(k.get(), Q.get())!=1) return false;
    uptr<BIO> bio(BIO_new_file(path.c_str(), "w"));
    if(!bio) return false;
    return PEM_write_bio_ECPrivateKey(bio.get(), k.get(), nullptr, nullptr, 0, nullptr, nullptr)==1;
}

inline bool write_pub_pem(const std::string& path, EC_GROUP* g, const std::vector<uint8_t>& Q_oct){
    auto Q = oct_to_point(g, Q_oct); if(!Q) return false;
    uptr<EC_KEY> k(EC_KEY_new()); if(!k) return false;
    if(EC_KEY_set_group(k.get(), g)!=1) return false;
    if(EC_KEY_set_public_key(k.get(), Q.get())!=1) return false;
    uptr<BIO> bio(BIO_new_file(path.c_str(), "w"));
    if(!bio) return false;
    return PEM_write_bio_EC_PUBKEY(bio.get(), k.get())==1;
}

inline bool read_pub_pem_compressed_on_ours(EC_GROUP* ours, const std::string& path, std::vector<uint8_t>& out_oct){
    uptr<BIO> bio(BIO_new_file(path.c_str(), "r")); if(!bio) return false;
    uptr<EC_KEY> k(PEM_read_bio_EC_PUBKEY(bio.get(), nullptr, nullptr, nullptr));
    if(!k) return false;
    const EC_GROUP* peer_g = EC_KEY_get0_group(k.get());
    const EC_POINT* peer_Q = EC_KEY_get0_public_key(k.get());
    if(!peer_g || !peer_Q) return false;
    // serialize on peer group, then parse on ours (to avoid group mixing UB)
    std::vector<uint8_t> tmp;
    {
        uptr<BN_CTX> ctx(BN_CTX_new()); if(!ctx) return false;
        size_t len = EC_POINT_point2oct(peer_g, peer_Q, POINT_CONVERSION_COMPRESSED, nullptr, 0, ctx.get());
        if(len==0) return false;
        tmp.resize(len);
        if(EC_POINT_point2oct(peer_g, peer_Q, POINT_CONVERSION_COMPRESSED, tmp.data(), len, ctx.get())!=len) return false;
    }
    // reparse onto ours to canonicalize
    auto Qours = oct_to_point(ours, tmp); if(!Qours) return false;
    if(!point_to_oct(ours, Qours.get(), out_oct)) return false;
    return true;
}

inline bool generate_keypair(EC_GROUP* g, std::vector<uint8_t>& d_be, std::vector<uint8_t>& Q_oct){
    uptr<BN_CTX> ctx(BN_CTX_new()); if(!ctx) return false;
    auto n = bn_from_dec(N_DEC); if(!n) return false;
    uptr<BIGNUM> d(BN_new()); if(!d) return false;
    do{ if(BN_rand_range(d.get(), n.get())!=1) return false; } while(BN_is_zero(d.get()));
    uptr<EC_POINT> Q(EC_POINT_new(g)); if(!Q) return false;
    if(EC_POINT_mul(g, Q.get(), d.get(), nullptr, nullptr, ctx.get())!=1) return false;
    int nbits = BN_num_bits(n.get());
    size_t nbytes = (size_t)((nbits + 7)/8);
    d_be.assign(nbytes, 0);
    BN_bn2binpad(d.get(), d_be.data(), (int)nbytes);
    if(!point_to_oct(g, Q.get(), Q_oct)) return false;
    return true;
}

} // namespace hf
