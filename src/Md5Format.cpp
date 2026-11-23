#include "./headers/Md5Format.h"
#include <string>
#include <cstdint>
#include <vector>
#include <cmath>
#include <algorithm>
#include <cctype>

namespace {   // anonymous namespace

uint32_t F(uint32_t B, uint32_t C, uint32_t D, int i, int& g) {
    uint32_t f;
    if      (i < 16) { f = (B & C) | (~B & D); g = i; }
    else if (i < 32) { f = (B & D) | (C & ~D); g = (5*i + 1) % 16; }
    else if (i < 48) { f = B ^ C ^ D;          g = (3*i + 5) % 16; }
    else             { f = C ^ (B | ~D);       g = (7*i)     % 16; }
    return f;
}

uint32_t leftrotate(uint32_t x, int c) {
    return (x << c) | (x >> (32 - c));
}

std::string compute_md5(std::string in) {
    std::string out;
    size_t L = in.size();
    size_t count = ((56 - (L+ 1)) % 64 + 64) % 64;

    std::vector<uint8_t> buf (in.begin(), in.end());         
    buf.push_back(0x80);             
    buf.insert(buf.end(), count, 0x00);

    uint64_t bits = (uint64_t)L * 8;      

    for (int i = 0; i < 8; ++i) {
        buf.push_back( (bits >> (i * 8)) & 0xFF );
    }

    uint32_t a0 = 0x67452301;
    uint32_t b0 = 0xefcdab89;
    uint32_t c0 = 0x98badcfe;
    uint32_t d0 = 0x10325476;

    const int s[64] = {
        7,12,17,22, 7,12,17,22, 7,12,17,22, 7,12,17,22,   
        5, 9,14,20, 5, 9,14,20, 5, 9,14,20, 5, 9,14,20,   
        4,11,16,23, 4,11,16,23, 4,11,16,23, 4,11,16,23,   
        6,10,15,21, 6,10,15,21, 6,10,15,21, 6,10,15,21    
    };

    uint32_t K[64];
    for (int i = 0; i < 64; ++i)
        K[i] = (uint32_t)(std::floor(std::fabs(std::sin(i + 1)) * 4294967296.0));

    for (size_t block = 0; block < buf.size(); block += 64) {
        uint32_t M[16];
        for (int j = 0; j < 16; ++j) {
            M[j] =  (uint32_t)buf[block + j*4 + 0]
                  | ((uint32_t)buf[block + j*4 + 1] << 8)
                  | ((uint32_t)buf[block + j*4 + 2] << 16)
                  | ((uint32_t)buf[block + j*4 + 3] << 24);
        }

        uint32_t A = a0, B = b0, C = c0, D = d0;   

        for (int i = 0; i < 64; i++) {
            uint32_t f;
            int g;
            f = F(B, C, D, i, g);
            f = f + A + K[i] + M[g];
            A = D;
            D = C;
            C = B;
            B = B + leftrotate(f, s[i]);
        }

        a0 += A;   
        b0 += B;
        c0 += C;
        d0 += D;
    }

    uint32_t vals[4] = { a0, b0, c0, d0 };
    const char* hexdigits = "0123456789abcdef";
    for (int i = 0; i < 4; ++i) {
        for (int j = 0; j < 4; ++j) {                 
            uint8_t byte = (vals[i] >> (j * 8)) & 0xFF;
            out.push_back(hexdigits[byte >> 4]);
            out.push_back(hexdigits[byte & 0x0F]);
        }
    }

    return out;
}

} 

std::string Md5Format::hash(const std::string& candidate) const {
    return compute_md5(candidate);
}

std::string Md5Format::parse(const std::string& field) const {
    std::string s = field;
    while (!s.empty() && std::isspace((unsigned char)s.back())) s.pop_back();
    std::transform(s.begin(), s.end(), s.begin(),
                   [](unsigned char c){ return std::tolower(c); });
    return s;
}

std::size_t Md5Format::digest_size() const { return 32; }