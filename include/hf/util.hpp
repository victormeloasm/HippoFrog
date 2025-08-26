
#pragma once
#include <vector>
#include <string>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <sstream>

namespace hf {

inline std::vector<uint8_t> read_file(const std::string& path){
    std::ifstream f(path, std::ios::binary);
    if(!f) return {};
    f.seekg(0, std::ios::end);
    std::streamsize n = f.tellg();
    f.seekg(0, std::ios::beg);
    std::vector<uint8_t> buf((size_t)n);
    if(n>0) f.read(reinterpret_cast<char*>(buf.data()), n);
    return buf;
}

inline bool write_file(const std::string& path, const std::vector<uint8_t>& data){
    std::ofstream f(path, std::ios::binary);
    if(!f) return false;
    f.write(reinterpret_cast<const char*>(data.data()), (std::streamsize)data.size());
    return (bool)f;
}

inline bool write_text(const std::string& path, const std::string& s){
    std::ofstream f(path);
    if(!f) return false;
    f << s;
    return (bool)f;
}

inline void be64enc(uint8_t out[8], uint64_t v){
    for(int i=7;i>=0;--i){ out[i]=uint8_t(v&0xff); v>>=8; }
}
inline uint64_t be64dec(const uint8_t in[8]){
    uint64_t v=0; for(int i=0;i<8;++i){ v=(v<<8)|in[i]; } return v;
}

inline std::string hex_of(const std::vector<uint8_t>& v){
    static const char* hexd="0123456789abcdef";
    std::string s; s.resize(v.size()*2);
    for(size_t i=0;i<v.size();++i){ s[2*i]=hexd[v[i]>>4]; s[2*i+1]=hexd[v[i]&0xf]; }
    return s;
}

inline void secure_clean(void* p, size_t n){
    volatile uint8_t* vp = (volatile uint8_t*)p;
    while(n--) *vp++ = 0;
}

} // namespace hf
