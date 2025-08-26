
#pragma once
#include <vector>
#include <string>
#include <array>
#include <stdexcept>
#include <openssl/evp.h>
#include <openssl/kdf.h>

namespace hf {

inline std::vector<unsigned char> hkdf_sha256(
    const std::vector<unsigned char>& ikm,
    const std::vector<unsigned char>& salt,
    const std::vector<unsigned char>& info,
    size_t out_len)
{
    std::vector<unsigned char> out(out_len);
    EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr);
    if(!pctx) throw std::runtime_error("HKDF ctx");
    if(EVP_PKEY_derive_init(pctx)<=0) throw std::runtime_error("HKDF init");
    if(EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_sha256())<=0) throw std::runtime_error("HKDF md");
    if(EVP_PKEY_CTX_set1_hkdf_salt(pctx, salt.data(), (int)salt.size())<=0) throw std::runtime_error("HKDF salt");
    if(EVP_PKEY_CTX_set1_hkdf_key(pctx, ikm.data(), (int)ikm.size())<=0) throw std::runtime_error("HKDF key");
    if(!info.empty()){
        if(EVP_PKEY_CTX_add1_hkdf_info(pctx, info.data(), (int)info.size())<=0) throw std::runtime_error("HKDF info");
    }
    size_t len = out.size();
    if(EVP_PKEY_derive(pctx, out.data(), &len)<=0) throw std::runtime_error("HKDF derive");
    EVP_PKEY_CTX_free(pctx);
    return out;
}

// AES-256-GCM one-shot (buffered outside)
inline void aes256gcm_encrypt(
    const std::vector<unsigned char>& key,
    const std::vector<unsigned char>& iv,
    const std::vector<unsigned char>& aad,
    const std::vector<unsigned char>& plaintext,
    std::vector<unsigned char>& ciphertext,
    std::array<unsigned char,16>& tag)
{
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if(!ctx) throw std::runtime_error("cipher ctx");
    if(EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr)<=0)
        throw std::runtime_error("enc init");
    if(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, (int)iv.size(), nullptr)<=0)
        throw std::runtime_error("ivlen");
    if(EVP_EncryptInit_ex(ctx, nullptr, nullptr, key.data(), iv.data())<=0)
        throw std::runtime_error("enc key/iv");
    int outl=0;
    if(!aad.empty()){
        if(EVP_EncryptUpdate(ctx, nullptr, &outl, aad.data(), (int)aad.size())<=0)
            throw std::runtime_error("aad");
    }
    ciphertext.resize(plaintext.size());
    if(EVP_EncryptUpdate(ctx, ciphertext.data(), &outl, plaintext.data(), (int)plaintext.size())<=0)
        throw std::runtime_error("enc update");
    int total = outl;
    if(EVP_EncryptFinal_ex(ctx, ciphertext.data()+total, &outl)<=0)
        throw std::runtime_error("enc final");
    total += outl;
    ciphertext.resize((size_t)total);
    if(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, tag.data())<=0)
        throw std::runtime_error("get tag");
    EVP_CIPHER_CTX_free(ctx);
}

inline bool aes256gcm_decrypt(
    const std::vector<unsigned char>& key,
    const std::vector<unsigned char>& iv,
    const std::vector<unsigned char>& aad,
    const std::vector<unsigned char>& ciphertext,
    const std::array<unsigned char,16>& tag,
    std::vector<unsigned char>& plaintext)
{
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if(!ctx) return false;
    if(EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr)<=0){ EVP_CIPHER_CTX_free(ctx); return false; }
    if(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, (int)iv.size(), nullptr)<=0){ EVP_CIPHER_CTX_free(ctx); return false; }
    if(EVP_DecryptInit_ex(ctx, nullptr, nullptr, key.data(), iv.data())<=0){ EVP_CIPHER_CTX_free(ctx); return false; }
    int outl=0;
    if(!aad.empty()){
        if(EVP_DecryptUpdate(ctx, nullptr, &outl, aad.data(), (int)aad.size())<=0){ EVP_CIPHER_CTX_free(ctx); return false; }
    }
    plaintext.resize(ciphertext.size());
    if(EVP_DecryptUpdate(ctx, plaintext.data(), &outl, ciphertext.data(), (int)ciphertext.size())<=0){ EVP_CIPHER_CTX_free(ctx); return false; }
    int total=outl;
    if(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, 16, const_cast<unsigned char*>(tag.data()))<=0){ EVP_CIPHER_CTX_free(ctx); return false; }
    if(EVP_DecryptFinal_ex(ctx, plaintext.data()+total, &outl)<=0){ EVP_CIPHER_CTX_free(ctx); return false; }
    total += outl;
    plaintext.resize((size_t)total);
    EVP_CIPHER_CTX_free(ctx);
    return true;
}

} // namespace hf
