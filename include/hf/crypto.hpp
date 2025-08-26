
#pragma once
#include <vector>
#include <openssl/evp.h>
#include <openssl/kdf.h>

namespace hf {

inline bool hkdf_sha256(std::vector<uint8_t>& out_key, size_t out_len,
                        const std::vector<uint8_t>& ikm,
                        const std::vector<uint8_t>& salt,
                        const std::vector<uint8_t>& info){
    out_key.assign(out_len, 0);
    EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr);
    if(!pctx) return false;
    bool ok=false;
    do{
        if(EVP_PKEY_derive_init(pctx)<=0) break;
        if(EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_sha256())<=0) break;
        if(EVP_PKEY_CTX_set1_hkdf_salt(pctx, salt.data(), (int)salt.size())<=0) break;
        if(EVP_PKEY_CTX_set1_hkdf_key(pctx, ikm.data(), (int)ikm.size())<=0) break;
        if(EVP_PKEY_CTX_add1_hkdf_info(pctx, info.data(), (int)info.size())<=0) break;
        size_t len = out_len;
        if(EVP_PKEY_derive(pctx, out_key.data(), &len)<=0) break;
        ok=true;
    }while(false);
    EVP_PKEY_CTX_free(pctx);
    if(!ok) out_key.clear();
    return ok;
}

inline bool aes256gcm_encrypt(const std::vector<uint8_t>& key,
                              const std::vector<uint8_t>& iv,
                              const std::vector<uint8_t>& aad,
                              const std::vector<uint8_t>& plaintext,
                              std::vector<uint8_t>& ciphertext,
                              std::vector<uint8_t>& tag){
    ciphertext.resize(plaintext.size());
    tag.assign(16, 0);
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if(!ctx) return false;
    bool ok=false;
    do{
        if(EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr)<=0) break;
        if(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, (int)iv.size(), nullptr)<=0) break;
        if(EVP_EncryptInit_ex(ctx, nullptr, nullptr, key.data(), iv.data())<=0) break;
        int outl=0;
        if(!aad.empty()){
            if(EVP_EncryptUpdate(ctx, nullptr, &outl, aad.data(), (int)aad.size())<=0) break;
        }
        if(EVP_EncryptUpdate(ctx, ciphertext.data(), &outl, plaintext.data(), (int)plaintext.size())<=0) break;
        int tmplen=0;
        if(EVP_EncryptFinal_ex(ctx, ciphertext.data()+outl, &tmplen)<=0) break;
        unsigned char tagbuf[16];
        if(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tagbuf)<=0) break;
        tag.assign(tagbuf, tagbuf+16);
        ok=true;
    }while(false);
    EVP_CIPHER_CTX_free(ctx);
    if(!ok){ ciphertext.clear(); tag.clear(); }
    return ok;
}

inline bool aes256gcm_decrypt(const std::vector<uint8_t>& key,
                              const std::vector<uint8_t>& iv,
                              const std::vector<uint8_t>& aad,
                              const std::vector<uint8_t>& ciphertext,
                              const std::vector<uint8_t>& tag,
                              std::vector<uint8_t>& plaintext){
    plaintext.resize(ciphertext.size());
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if(!ctx) return false;
    bool ok=false;
    do{
        if(EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr)<=0) break;
        if(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, (int)iv.size(), nullptr)<=0) break;
        if(EVP_DecryptInit_ex(ctx, nullptr, nullptr, key.data(), iv.data())<=0) break;
        int outl=0;
        if(!aad.empty()){
            if(EVP_DecryptUpdate(ctx, nullptr, &outl, aad.data(), (int)aad.size())<=0) break;
        }
        if(EVP_DecryptUpdate(ctx, plaintext.data(), &outl, ciphertext.data(), (int)ciphertext.size())<=0) break;
        if(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, (int)tag.size(), (void*)tag.data())<=0) break;
        int tmplen=0;
        if(EVP_DecryptFinal_ex(ctx, plaintext.data()+outl, &tmplen)<=0) { ok=false; break; }
        ok=true;
    }while(false);
    EVP_CIPHER_CTX_free(ctx);
    if(!ok){ plaintext.clear(); }
    return ok;
}

} // namespace hf
