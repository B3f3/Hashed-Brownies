#include <iostream>

int main(int argc, char* argv[]) {

    std::string wordlist;
    std::string hashes;

    std::cout << "Got " << argc << " arguments\n";
    for (int i = 0; i < argc; ++i) {
        std::cout << "argv[" << i << "] = " << argv[i] << "\n";
    }

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
        hashes = argv[2];
    }
    

    return 0;
}
