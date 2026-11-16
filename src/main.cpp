#include <iostream>
#include <string>
#include "./headers/md5.h"

int main(int argc, char* argv[]) {
    // Known-answer tests (official RFC 1321 vectors).
    struct { std::string in; std::string expected; } tests[] = {
        { "",                                                                 "d41d8cd98f00b204e9800998ecf8427e" },
        { "a",                                                                "0cc175b9c0f1b6a831c399e269772661" },
        { "abc",                                                              "900150983cd24fb0d6963f7d28e17f72" },
        { "message digest",                                                   "f96b697d7cb7938d525a2f31aaf161d0" },
        { "abcdefghijklmnopqrstuvwxyz",                                       "c3fcd3d76192e4007dfb496cca67e13b" },
        { "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",  "d174ab98d277d9f5a5611c2c9f419d9f" },
    };

    std::cout << "=== MD5 self-test ===\n";
    int passed = 0, total = 0;
    for (auto& t : tests) {
        std::string got = md5(t.in);
        bool ok = (got == t.expected);
        passed += ok;
        ++total;
        std::cout << (ok ? "[PASS] " : "[FAIL] ")
                  << "md5(\"" << t.in << "\")\n"
                  << "    got      = " << got << "\n";
        if (!ok)
            std::cout << "    expected = " << t.expected << "\n";
    }
    std::cout << passed << "/" << total << " passed\n\n";

    // Hash any strings passed on the command line: ./md5 hello world
    if (argc > 1) {
        std::cout << "=== command-line input ===\n";
        for (int i = 1; i < argc; ++i) {
            std::cout << md5(argv[i]) << "  \"" << argv[i] << "\"\n";
        }
    }

    return (passed == total) ? 0 : 1;
}
