#include "./headers/Sha256Format.h"
#include <iostream>
#include <string>
#include <cstdint>
#include <vector>
#include <cmath>
#include <algorithm>
#include <cctype>

namespace {   // anonymous namespace

uint32_t rightrotate(uint32_t x, int c) {
    return (x >> c) | (x << (32 - c));
}

uint32_t CH(uint32_t e, uint32_t f, uint32_t g)  { return (e & f) ^ (~e & g); }
uint32_t MAJ(uint32_t a, uint32_t b, uint32_t c) { return (a & b) ^ (a & c) ^ (b & c); }

uint32_t BSIG0(uint32_t x) { return rightrotate(x, 2) ^ rightrotate(x, 13) ^ rightrotate(x, 22); }
uint32_t BSIG1(uint32_t x) { return rightrotate(x, 6) ^ rightrotate(x, 11) ^ rightrotate(x, 25); }

std::string compute_sha256(std::string in) {
    std::string out;
    size_t L = in.size();
    size_t count = ((56 - (L+ 1)) % 64 + 64) % 64;

    std::vector<uint8_t> buf (in.begin(), in.end());         
    buf.push_back(0x80);             
    buf.insert(buf.end(), count, 0x00);

    //preprocessing
    uint64_t bits = (uint64_t)L * 8;      

    for (int i = 0; i < 8; ++i) {
        buf.push_back( (bits >> ((7 - i) * 8)) & 0xFF );   // high byte first = big-endian
    }

    //constants
    uint32_t K[64] = {
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
            0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
            0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
            0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
            0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
            0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
            0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2 }; 

    // initial hash values H0 -> h7
    uint32_t H[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19}; 

    
    // hashing
    for (size_t block = 0; block < (buf.size() / 64); block++)
    {

        //1. Prepare the message schedule W:
        uint32_t W[64];
        for (size_t t = 0; t < 16; t++){
            W[t] = ((uint32_t)buf[block*64 + t*4 + 0] << 24)
                | ((uint32_t)buf[block*64 + t*4 + 1] << 16)
                | ((uint32_t)buf[block*64 + t*4 + 2] << 8)
                |  (uint32_t)buf[block*64 + t*4 + 3];
        }
        for (int t = 16; t < 64; ++t) {
            uint32_t s0 = rightrotate(W[t-15], 7) ^ rightrotate(W[t-15], 18) ^ (W[t-15] >> 3);
            uint32_t s1 = rightrotate(W[t-2], 17) ^ rightrotate(W[t-2], 19) ^ (W[t-2] >> 10);
            W[t] = s1 + W[t-7] + s0 + W[t-16];
        }


        //2. Initialize the working variables:
        uint32_t a = H[0];
        uint32_t b = H[1];
        uint32_t c = H[2];
        uint32_t d = H[3];
        uint32_t e = H[4];
        uint32_t f = H[5];
        uint32_t g = H[6];
        uint32_t h = H[7];
        
        //3. Perform the main hash computation:
        for (int t = 0; t < 64; ++t) {
            uint32_t T1 = h + BSIG1(e) + CH(e,f,g) + K[t] + W[t];
            uint32_t T2 = BSIG0(a) + MAJ(a,b,c);
            h = g;
            g = f;
            f = e;
            e = d + T1;
            d = c;
            c = b;
            b = a;
            a = T1 + T2;
        }
        
        //4. Compute the intermediate hash value H(i)
        H[0] += a;
        H[1] += b;
        H[2] += c;
        H[3] += d;
        H[4] += e;
        H[5] += f;
        H[6] += g;
        H[7] += h;
    }
    
    const char* hexdigits = "0123456789abcdef";
    for (int i = 0; i < 8; ++i) {
        for (int j = 3; j >= 0; --j) {               // big-endian
            uint8_t byte = (H[i] >> (j * 8)) & 0xFF;
            out.push_back(hexdigits[byte >> 4]);
            out.push_back(hexdigits[byte & 0x0F]);
        }
    }

    return out;
}

} 

std::string Sha256Format::hash(const std::string& candidate) const {
    return compute_sha256(candidate);
}

std::string Sha256Format::parse(const std::string& field) const {
    std::string s = field;
    while (!s.empty() && std::isspace((unsigned char)s.back())) s.pop_back();
    std::transform(s.begin(), s.end(), s.begin(),
                   [](unsigned char c){ return std::tolower(c); });
    return s;
}

std::size_t Sha256Format::digest_size() const { return 64; }