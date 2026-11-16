#include <iostream>
#include <fstream> 
#include "./headers/md5.h"

int main(int argc, char* argv[]) {

    std::string word;
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
    } else {
        wordlist = argv[1];
        wordlist = wordlist.substr(wordlist.find("=") + 1);
        hashes = argv[2];
    }

    std::ifstream WordlistFile(wordlist);

    std::ifstream HashFile(hashes);

    while (getline(HashFile, hash)){
        WordlistFile.clear();        // clear the EOF flag
        WordlistFile.seekg(0);
        while (getline(WordlistFile, word))
        {
            if(md5(word) == hash){
                std::cout << "hash: " << hash << " word: " << word << std::endl; 
            }
        }
        
    }

    return 0;
}
