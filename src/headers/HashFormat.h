#pragma once
#include <string>
#include <vector> 

class HashFormat {
public:
    virtual ~HashFormat() = default;
    virtual std::string hash(const std::string& candidate) const = 0;   // word -> digest
    virtual std::string parse(const std::string& field) const = 0;      // raw field -> canonical digest
    virtual size_t digest_size() const = 0;
};