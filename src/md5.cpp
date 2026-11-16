#include "./headers/md5.h"

#include <iostream>
#include <string>
#include <cstdint>
#include <vector>
#include <cmath>

uint32_t F(uint32_t B, uint32_t C, uint32_t D, int i, int& g){
    uint32_t F;
    if (i < 16) {
            F = (B & C) | (~B & D);         // round 1
            g = i;
    } else if (i < 32) {
            F = (B & D) | (C & ~D);         // round 2
            g = (5*i + 1) % 16;
    } else if (i < 48) {
            F = B ^ C ^ D;                  // round 3
            g = (3*i + 5) % 16;
    } else {
            F = C ^ (B | ~D);               // round 4
            g = (7*i) % 16;
        }
    return F;
}

uint32_t leftrotate(uint32_t x, int c) {
    return (x << c) | (x >> (32 - c));
}

std::string md5(std::string in){
    std::string out;
    size_t L = in.size();
    size_t count = ((56 - (L+ 1)) % 64 + 64) % 64;

    std::vector<uint8_t> buf (in.begin(), in.end());          // uint8_t = unsigned, always 0–255
    buf.push_back(0x80);               // no cast needed, no sign issues
    buf.insert(buf.end(), count, 0x00);

    uint64_t bits = (uint64_t)L * 8;      // bit-length, in a 64-bit type

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

        uint32_t A = a0, B = b0, C = c0, D = d0;   // init once per block

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

        a0 += A;   // add this block's result back into running state
        b0 += B;
        c0 += C;
        d0 += D;
    }

    uint32_t vals[4] = { a0, b0, c0, d0 };
    const char* hexdigits = "0123456789abcdef";
    for (int i = 0; i < 4; ++i) {
        for (int j = 0; j < 4; ++j) {                 // little-endian byte order
            uint8_t byte = (vals[i] >> (j * 8)) & 0xFF;
            out.push_back(hexdigits[byte >> 4]);
            out.push_back(hexdigits[byte & 0x0F]);
        }
    }

    return out;
}