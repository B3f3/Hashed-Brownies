#include <iostream>
#include <fstream>
#include <unordered_set>
#include <unordered_map>
#include "./headers/Md5Format.h"
#include "./headers/Sha256Format.h"
#include <memory>
#include <vector>
#include <iomanip>
#include <chrono>
#include <utility>

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

// Split "username:hash" on the LAST ':' so colons in the username are safe.
// No ':' at all -> the whole line is the hash, identifier is "?".
std::pair<std::string, std::string> splitTarget(const std::string& line) {
    std::size_t pos = line.rfind(':');
    if (pos == std::string::npos) return { "?", line };
    return { line.substr(0, pos), line.substr(pos + 1) };
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
        std::string firstLine;                    // auto-detect from the first target
        if (getline(HashFile, firstLine)) {
            // trim line-ending FIRST — see gotcha below
            while (!firstLine.empty() &&
                (firstLine.back() == '\r' || firstLine.back() == '\n'))
                firstLine.pop_back();
            std::string firstHash = splitTarget(firstLine).second;   // detect on the HASH part only
            fmt = detectFormat(firstHash);
        }
        HashFile.clear();                         // reset EOF flag
        HashFile.seekg(0);                        // rewind so the set-loading loop still sees ALL lines
    }
    if (!fmt) { std::cerr << "could not determine hash format\n"; return 1; }
    
    // Load targets into a map: digest -> list of identifiers that share it.
    std::unordered_map<std::string, std::vector<std::string>> targets;
    while (getline(HashFile, hash)) {
        auto [id, rawHash] = splitTarget(hash);
        std::string digest = fmt->parse(rawHash);   // trim + lowercase to canonical form
        if (!digest.empty()) targets[digest].push_back(id);
    }

    // Load line (John-style) + start the clock.
    std::size_t total = targets.size();
    std::cout << "Loaded " << total << " password hash"
              << (total == 1 ? "" : "es")
              << " (" << (format.empty() ? "auto-detected" : format) << ")\n";

    auto start = std::chrono::steady_clock::now();
    std::size_t cracked = 0;

    // Single pass over the wordlist: hash each candidate once, check against all targets.
    while (getline(WordlistFile, candidate)) {
        while (!candidate.empty() && (candidate.back() == '\r' || candidate.back() == '\n'))
            candidate.pop_back();          // strip line-ending (don't lowercase — passwords are case-sensitive)

        std::string digest = fmt->hash(candidate);
        auto it = targets.find(digest);
        if (it != targets.end()) {
            for (const std::string& id : it->second)   // one line per identifier sharing this hash
                std::cout << std::left << std::setw(16) << candidate << "(" << id << ")\n";
            cracked++;                     // count the cracked hash
            targets.erase(it);             // avoid re-reporting; enables early stop
            if (targets.empty()) break;    // everything cracked, no need to keep scanning
        }
    }

    // Summary line (John-style).
    auto end = std::chrono::steady_clock::now();
    auto secs = std::chrono::duration_cast<std::chrono::seconds>(end - start).count();
    std::cout << cracked << "g " << secs << "s DONE ("
              << cracked << "/" << total << " cracked)\n";

    return 0;
}