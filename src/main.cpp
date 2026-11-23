#include "./headers/Md5Format.h"
#include "./headers/Sha256Format.h"
#include "./headers/bruteforce.h"

#include <iostream>
#include <fstream>
#include <unordered_map>
#include <memory>
#include <vector>
#include <iomanip>
#include <chrono>
#include <utility>
#include <string>

// digest -> list of identifiers (usernames) that share that digest
using TargetMap = std::unordered_map<std::string, std::vector<std::string>>;


// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

// Remove a trailing CR/LF left by getline on Windows-formatted files.
static void stripLineEnding(std::string& s) {
    while (!s.empty() && (s.back() == '\r' || s.back() == '\n'))
        s.pop_back();
}

// Split "username:hash" on the LAST ':' so colons in the username are safe.
// A line with no ':' is treated as all-hash, with identifier "?".
static std::pair<std::string, std::string> splitTarget(const std::string& line) {
    std::size_t pos = line.rfind(':');
    if (pos == std::string::npos) return { "?", line };
    return { line.substr(0, pos), line.substr(pos + 1) };
}


// ---------------------------------------------------------------------------
// Command-line options
// ---------------------------------------------------------------------------

struct Options {
    std::string wordlist;
    std::string hashes;
    std::string format;              // empty => auto-detect
    std::string mode = "wordlist";   // "wordlist" or "brute"
};

static Options parseArgs(int argc, char* argv[]) {
    Options opt;
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg.rfind("--wordlist=", 0) == 0)      opt.wordlist = arg.substr(arg.find('=') + 1);
        else if (arg.rfind("--format=", 0) == 0)   opt.format   = arg.substr(arg.find('=') + 1);
        else if (arg.rfind("--mode=", 0) == 0)     opt.mode     = arg.substr(arg.find('=') + 1);
        else                                       opt.hashes   = arg;   // the bare positional
    }
    return opt;
}

static void printUsage(const char* prog) {
    std::cout <<
        "\n"
        "  +==========================================+\n"
        "  |          H A S H E D   B R O W N I E S    |\n"
        "  |            password hash cracker          |\n"
        "  +==========================================+\n"
        "\n"
        "  Usage:\n"
        "    " << prog << " --wordlist=<PATH> <PATH_TO_HASHES> [--format=md5|sha256]\n"
        "\n"
        "  Options:\n"
        "    --wordlist=<PATH>   Path to the wordlist file (required)\n"
        "    --format=<name>     Hash type: md5 or sha256 (optional; auto-detected)\n"
        "\n"
        "  Arguments:\n"
        "    <PATH_TO_HASHES>    File of target hashes, one 'username:hash' per line\n"
        "\n"
        "  Example:\n"
        "    " << prog << " --wordlist=rockyou.txt hashes\n"
        "\n";
}


// ---------------------------------------------------------------------------
// Hash-format selection
// ---------------------------------------------------------------------------

static std::unique_ptr<HashFormat> makeFormat(const std::string& name) {
    if (name == "md5")    return std::make_unique<Md5Format>();
    if (name == "sha256") return std::make_unique<Sha256Format>();
    return nullptr;
}

// Pick a format by matching the hash length against each known format's digest size.
static std::unique_ptr<HashFormat> detectFormat(const std::string& hashLine) {
    for (const char* name : { "md5", "sha256" }) {
        auto fmt = makeFormat(name);
        if (fmt && hashLine.size() == fmt->digest_size())
            return fmt;
    }
    return nullptr;
}

// Use the explicit name if given; otherwise auto-detect from the first target hash.
// Leaves hashFile rewound to the start so the loader can read every line.
static std::unique_ptr<HashFormat> selectFormat(const std::string& name, std::ifstream& hashFile) {
    if (!name.empty())
        return makeFormat(name);

    std::unique_ptr<HashFormat> fmt;
    std::string firstLine;
    if (getline(hashFile, firstLine)) {
        stripLineEnding(firstLine);
        std::string firstHash = splitTarget(firstLine).second;   // detect on the hash part only
        fmt = detectFormat(firstHash);
    }
    hashFile.clear();     // reset EOF flag
    hashFile.seekg(0);    // rewind for the loader
    return fmt;
}


// ---------------------------------------------------------------------------
// Loading targets and running the attack
// ---------------------------------------------------------------------------

static TargetMap loadTargets(std::ifstream& hashFile, const HashFormat& fmt) {
    TargetMap targets;
    std::string line;
    while (getline(hashFile, line)) {
        auto [id, rawHash] = splitTarget(line);
        std::string digest = fmt.parse(rawHash);     // trim + lowercase to canonical form
        if (!digest.empty()) targets[digest].push_back(id);
    }
    return targets;
}

// Hash each wordlist candidate once and check it against all targets.
// Returns the number of hashes cracked; prints each crack John-style.
static std::size_t runWordlistAttack(std::ifstream& wordlistFile,
                                     const HashFormat& fmt,
                                     TargetMap& targets) {
    std::size_t cracked = 0;
    std::string candidate;
    while (getline(wordlistFile, candidate)) {
        stripLineEnding(candidate);                  // don't lowercase — passwords are case-sensitive

        auto it = targets.find(fmt.hash(candidate));
        if (it != targets.end()) {
            for (const std::string& id : it->second)
                std::cout << std::left << std::setw(16) << candidate << "(" << id << ")\n";
            cracked++;
            targets.erase(it);                       // avoid re-reporting; enables early stop
            if (targets.empty()) break;
        }
    }
    return cracked;
}


// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

int main(int argc, char* argv[]) {
    Options opt = parseArgs(argc, argv);

    if (opt.wordlist.empty() || opt.hashes.empty()) {
        printUsage(argv[0]);
        return 0;
    }

    std::ifstream wordlistFile(opt.wordlist);
    std::ifstream hashFile(opt.hashes);
    if (!wordlistFile) { std::cerr << "cannot open wordlist: " << opt.wordlist << "\n"; return 1; }
    if (!hashFile)     { std::cerr << "cannot open hashes: "   << opt.hashes   << "\n"; return 1; }

    std::unique_ptr<HashFormat> fmt = selectFormat(opt.format, hashFile);
    if (!fmt) { std::cerr << "could not determine hash format\n"; return 1; }

    TargetMap targets = loadTargets(hashFile, *fmt);
    std::size_t total = targets.size();

    std::cout << "Loaded " << total << " password hash" << (total == 1 ? "" : "es")
              << " (" << (opt.format.empty() ? "auto-detected" : opt.format) << ")\n";

    auto start = std::chrono::steady_clock::now();
    std::size_t cracked = 0;

    if (opt.mode == "brute") {
        bruteforce("a", 1, "a");     // TODO: brute-force mode (Milestone 3)
    } else {
        cracked = runWordlistAttack(wordlistFile, *fmt, targets);
    }

    auto secs = std::chrono::duration_cast<std::chrono::seconds>(
                    std::chrono::steady_clock::now() - start).count();
    std::cout << cracked << "g " << secs << "s DONE (" << cracked << "/" << total << " cracked)\n";

    return 0;
}
