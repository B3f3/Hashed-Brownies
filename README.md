# Hashed Brownies

A learning-focused password hash cracker written in C++, in the spirit of
John the Ripper. It takes a list of target hashes and a wordlist, and reports
which words match which hashes.

This is an educational project. The hash algorithms (MD5, SHA-256) are
implemented from scratch rather than pulled from a library, so the goal is
understanding how they work, not production-grade performance or security.

## Features

- Dictionary attack: hash each word in a wordlist and compare against the targets.
- Hand-written MD5 and SHA-256, verified against published test vectors.
- Pluggable hash formats behind a small `HashFormat` interface, so adding a new
  algorithm is a single new class.
- Format auto-detection by digest length (32 hex chars = MD5, 64 = SHA-256),
  with an optional `--format` override.
- Single-pass cracking: targets are loaded into a hash set, so each candidate
  is hashed once and checked against all targets at once.

## Build

Requires a C++17 compiler (for example g++).

```
cd src
g++ -std=c++17 -Wall main.cpp Md5Format.cpp Sha256Format.cpp -o main
```

## Usage

```
./main --wordlist=<PATH> <PATH_TO_HASHES> [--format=<name>]
```

Arguments and flags can appear in any order:

- `--wordlist=<PATH>`  Path to the wordlist file (required).
- `<PATH_TO_HASHES>`   File containing the target hashes, one per line (required).
- `--format=<name>`    Hash type: `md5` or `sha256`. Optional; if omitted, the
                       format is detected from the hash length.

### Examples

Auto-detect the format:

```
./main --wordlist=rockyou.txt hashes
```

Specify the format explicitly:

```
./main --wordlist=rockyou.txt hashes --format=sha256
```

On a match, the matched hash and the plaintext word are printed.

## Supported formats

| Name     | Algorithm | Digest length |
|----------|-----------|---------------|
| `md5`    | MD5       | 32 hex chars  |
| `sha256` | SHA-256   | 64 hex chars  |

Note that detection by length is a best guess; different algorithms can share a
length. Use `--format` when you know the type.

## Project structure

```
src/
  main.cpp              CLI parsing, format selection, cracking loop
  Md5Format.cpp         MD5 implementation and Md5Format class
  Sha256Format.cpp      SHA-256 implementation and Sha256Format class
  headers/
    HashFormat.h        The format interface (hash, parse, digest_size)
    Md5Format.h
    Sha256Format.h
```

See `roadmap.md` for the planned milestones (brute force, mangling rules,
salted hashes, slow hashes, and more).

## Scope

This tool is for learning, CTFs, and auditing systems you own or are authorized
to test. Only run it against hashes you have permission to crack.
