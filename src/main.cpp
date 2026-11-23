#include <iostream>
#include <fstream>
#include <unordered_set>
#include "./headers/Md5Format.h"
#include "./headers/Sha256Format.h"
#include <memory>
#include <vector>

std::unique_ptr<HashFormat> makeFormat(const std::string& name) {
    if (name == "md5")    return std::make_unique<Md5Format>();
    if (name == "sha256") return std::make_unique<Sha256Format>();
    return nullptr;   // unknown
}

std::unique_ptr<HashFormat> detectFormat(const std::string& hashLine) {
    // try each known format; pick the one whose digest length matches
    const char* names[] = { "md5", "sha256" };   // every format you support
    for (const char* name : names) {
        auto fmt = makeFormat(name);
        if (fmt && hashLine.size() == fmt->digest_size())
            return fmt;
    }
    return nullptr;   // unknown length
}

int main(int argc, char* argv[]) {

    std::string candidate;
    std::string hash;
    std::string wordlist;
    std::string hashes;
    std::string format;


    for (int i = 1; i < argc; ++i) {

            std::string arg = argv[i];
            if (arg.rfind("--wordlist=", 0) == 0) {        
                wordlist = arg.substr(arg.find("=") + 1);
            } else if (arg.rfind("--format=", 0) == 0) {
                format = arg.substr(arg.find("=") + 1);
            } else {
                hashes = arg;                              
            }
    }


    if (wordlist.empty() || hashes.empty()) { 
        std::cout <<
            "\n"
            "  +==========================================+\n"
            "  |          H A S H E D   B R O W N I E S    |\n"
            "  |            password hash cracker          |\n"
            "  +==========================================+\n"
            "\n"
            "  Usage:\n"
            "    " << argv[0] << " --wordlist=<PATH> <PATH_TO_HASHES>\n"
            "\n"
            "  Options:\n"
            "    --wordlist=<PATH>   Path to the wordlist file (required)\n"
            "\n"
            "  Arguments:\n"
            "    <PATH_TO_HASHES>    File containing the hashes to crack\n"
            "\n"
            "  Example:\n"
            "    " << argv[0] << " --wordlist=rockyou.txt hashes.txt\n"
            "\n";
        return 0;
    }

    
    std::ifstream WordlistFile(wordlist);
    std::ifstream HashFile(hashes);

    if (!WordlistFile) { std::cerr << "cannot open wordlist: " << wordlist << "\n"; return 1; }
    if (!HashFile)     { std::cerr << "cannot open hashes: "   << hashes   << "\n"; return 1; }

    std::unique_ptr<HashFormat> fmt;

    if (!format.empty()) {
        fmt = makeFormat(format);                 // user specified it explicitly
    } else {
        std::string firstHash;                    // auto-detect from the first target
        if (getline(HashFile, firstHash)) {
            // trim line-ending FIRST — see gotcha below
            while (!firstHash.empty() &&
                (firstHash.back() == '\r' || firstHash.back() == '\n'))
                firstHash.pop_back();
            fmt = detectFormat(firstHash);
        }
        HashFile.clear();                         // reset EOF flag
        HashFile.seekg(0);                        // rewind so the set-loading loop still sees ALL lines
    }
    if (!fmt) { std::cerr << "could not determine hash format\n"; return 1; }
    
    // Load every target hash into a set once (O(1) lookups later).
    std::unordered_set<std::string> targets;
    while (getline(HashFile, hash)) {
        std::string t = fmt->parse(hash);   // trim + lowercase to canonical form
        if (!t.empty()) targets.insert(t);
    }

    // Single pass over the wordlist: hash each candidate once, check against all targets.
    while (getline(WordlistFile, candidate)) {
        while (!candidate.empty() && (candidate.back() == '\r' || candidate.back() == '\n'))
            candidate.pop_back();          // strip line-ending (don't lowercase — passwords are case-sensitive)

        std::string digest = fmt->hash(candidate);
        if (targets.count(digest)) {
            std::cout << "hash: " << digest << " word: " << candidate << std::endl;
        }
    }

    return 0;
}