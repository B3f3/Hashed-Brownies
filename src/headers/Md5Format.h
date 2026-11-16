#pragma once
#include <string>
#include <cstddef>
#include "HashFormat.h"

class Md5Format : public HashFormat {
public:
    std::string hash(const std::string& candidate) const override;
    std::string parse(const std::string& field)     const override;
    std::size_t digest_size() const override;
};