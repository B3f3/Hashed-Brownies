#include <iostream>
#include <fstream>
#include "./headers/Md5Format.h"

int main(int argc, char* argv[]) {

    std::string candidate;
    std::string hash;
    std::string wordlist;
    std::string hashes;

    if (argc <= 2)
    {
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
        return 0;                       // nothing to crack — stop here
    } else {
        wordlist = argv[1];
        wordlist = wordlist.substr(wordlist.find("=") + 1);
        hashes = argv[2];
    }

    Md5Format fmt;                       // <-- the format object

    std::ifstream WordlistFile(wordlist);
    std::ifstream HashFile(hashes);

    if (!WordlistFile) { std::cerr << "cannot open wordlist: " << wordlist << "\n"; return 1; }
    if (!HashFile)     { std::cerr << "cannot open hashes: "   << hashes   << "\n"; return 1; }

    while (getline(HashFile, hash)) {
        std::string target = fmt.parse(hash);   // <-- normalize the target (trim/lowercase)
        WordlistFile.clear();
        WordlistFile.seekg(0);
        while (getline(WordlistFile, candidate)) {
            if (fmt.hash(candidate) == target) { // <-- fmt.hash() instead of md5()
                std::cout << "hash: " << target << " word: " << candidate << std::endl;
            }
        }
    }

    return 0;
}