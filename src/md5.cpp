#include "./headers/md5.h"

#include <iostream>
#include <string>
#include <cstdint>
#include <vector>


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
    
    return out;
}