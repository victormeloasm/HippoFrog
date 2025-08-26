
#pragma once
#include <cstddef>
#include <cstring>
#include <openssl/crypto.h>

namespace hf {

class SecureBuffer {
    unsigned char* ptr{nullptr};
    size_t len{0};
    size_t cap{0};
    bool using_secure{false};

public:
    ~SecureBuffer(){ clear(); }

    void clear(){
        if(ptr){
            OPENSSL_cleanse(ptr, cap);
            if(using_secure){
                OPENSSL_secure_free(ptr);
            }else{
                OPENSSL_free(ptr);
            }
        }
        ptr=nullptr; len=cap=0; using_secure=false;
    }

    unsigned char* data(){ return ptr; }
    const unsigned char* data() const { return ptr; }
    size_t size() const { return len; }

    void resize(size_t n){
        if(n<=cap){ len=n; return; }
        clear();
        // try secure heap
        unsigned char* p = (unsigned char*)OPENSSL_secure_malloc(n);
        if(p){
            using_secure=true; ptr=p; cap=n; len=n; return;
        }
        // fallback normal
        p = (unsigned char*)OPENSSL_malloc(n);
        using_secure=false; ptr=p; cap=n; len=n;
    }
};

} // namespace hf
