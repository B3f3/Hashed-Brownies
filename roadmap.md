# Hash Cracker — Project Roadmap

A learning-focused password hash cracker in the spirit of John the Ripper.
Each milestone builds on the last: get it **correct**, then make it **fast**, then make it **flexible**.

> Guiding rule: never optimize a thing until a test proves it's correct. Keep a folder of
> known test vectors and run them after every change.

---

## Milestone 0 — Correct MD5

**Target:** Compute an MD5 digest and match it byte-for-byte against known values.

**How it should work**
- Input: an arbitrary byte string. Output: a 16-byte (128-bit) digest, usually shown as 32 hex characters.
- Start by wrapping a library implementation so you can build the rest of the pipeline, then (optionally) replace it with your own hand-written MD5 as a learning exercise and verify it still matches.
- Verify against canonical vectors before trusting anything downstream:
  - `md5("")` → `d41d8cd98f00b204e9800998ecf8427e`
  - `md5("abc")` → `900150983cd24fb0d6963f7d28e17f72`

**Why first:** MD5 is simple, fully specified, fast, and has endless public test vectors. It's broken for security, which is exactly why it's a realistic *learning* target.

**Sources**
- RFC 1321 — The MD5 Message-Digest Algorithm: https://www.rfc-editor.org/rfc/rfc1321
- Test vectors (RFC 1321, Appendix A.5) and NIST CAVP: https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program

---

## Milestone 1 — Dictionary Attack (the MVP)

**Target:** Given one target hash and a wordlist, find the word whose hash matches.

```
cracker --hash <md5> --wordlist words.txt
```

**How it should work**
1. Read the wordlist one line per candidate (stream it — don't load the whole file into memory).
2. Hash each candidate with your Milestone 0 function.
3. Compare to the target. On a match, print the plaintext and stop (or keep going if cracking many).
4. If the list is exhausted with no match, report "not found" and exit non-zero.

**Why:** This is how most real-world password auditing actually works — people reuse common passwords, so a good wordlist beats brute force almost every time. It's also the backbone every later mode plugs into.

**Sources**
- John the Ripper — wordlist mode docs: https://www.openwall.com/john/doc/MODES.shtml
- `rockyou.txt` (the classic public wordlist, from the 2009 breach; bundled with SecLists): https://github.com/danielmiessler/SecLists/tree/master/Passwords

---

## Milestone 2 — Hash Files & a Format Abstraction

**Target:** Crack many hashes at once from a file, and make "add a new hash type" a one-class change.

```
cracker --hashes targets.txt --wordlist words.txt
```
where `targets.txt` holds lines like `username:hash`.

**How it should work**
- Parse each line into (identifier, hash). Load all targets into a lookup structure (a hash set / map keyed by digest) so each candidate is checked against *all* targets in one pass.
- Define a small `HashFormat` interface: `hash()`, `parse()`, `digest_size()`. Register formats in a table keyed by name (`--format md5`). Every future algorithm becomes one new class — this is the extension point for all your "new format" updates.
- A candidate now hashes once and is compared against the whole target set; print each crack as it's found.

**Why:** Teaches you the architecture that makes the project maintainable. The map-based lookup is also your first real optimization: O(1) comparison against thousands of targets.

**Sources**
- hashcat example hashes (format reference for how different hash types are written): https://hashcat.net/wiki/doku.php?id=example_hashes
- John the Ripper `--format` concept: https://www.openwall.com/john/doc/

---

## Milestone 3 — Brute Force / Incremental Mode

**Target:** Generate and test every candidate over a charset up to length N.

```
cracker --hash <md5> --brute --charset abc...0-9 --max-len 6
```

**How it should work**
- Treat candidate generation as counting in base-`charset_size`: length 1, then length 2, and so on. An index-odometer approach (increment the rightmost position, carry over) generates all combinations without recursion blowing the stack.
- Make it **resumable**: the current counter state *is* your checkpoint — save it periodically so a long run can continue after a stop.
- Show progress: candidates/second and an estimate of the remaining keyspace.

**Why:** Teaches you the brutal math of search spaces — the keyspace grows as (charset^length), so each extra character multiplies the work. This is where you *feel* why dictionaries + rules beat raw brute force, and why fast hashes vs. slow hashes matters so much.

**Sources**
- John the Ripper incremental mode: https://www.openwall.com/john/doc/MODES.shtml
- Keyspace / mask-attack reasoning (hashcat): https://hashcat.net/wiki/doku.php?id=mask_attack

---

## Milestone 4 — Mangling Rules

**Target:** Transform dictionary words into realistic variants before hashing.

Example transforms: `password` → `Password`, `password1`, `p@ssw0rd`, `PASSWORD`.

**How it should work**
- Define a tiny rule language: capitalize, append digits, leetspeak substitutions, reverse, etc. Each rule is a function `string -> string` (or `string -> list<string>`).
- For each dictionary word, apply the active rules to produce extra candidates, then hash those too.
- This dramatically increases hit rate for a modest cost, because it models how people *actually* modify base passwords.

**Why:** This is the single highest-value feature after the basic dictionary attack, and it's the heart of what makes JtR effective.

**Sources**
- John the Ripper rules syntax: https://www.openwall.com/john/doc/RULES.shtml
- hashcat rule-based attack: https://hashcat.net/wiki/doku.php?id=rule_based_attack

---

## Milestone 5 — Salted Hashes

**Target:** Crack `md5($salt . $password)` style hashes where each target has its own salt.

**How it should work**
- Your `targets.txt` now carries a salt per line (`hash:salt`). Parsing extracts both.
- Because the salt differs per target, you can **no longer** precompute one digest per candidate and compare to all — each candidate must be re-hashed *with each target's salt*. This changes the loop structure (and performance profile) significantly.
- Handle both orderings (`salt+password` vs `password+salt`) as format variants.

**Why:** Salting is why real systems don't fall to a single precomputed table. Implementing it teaches you *why* salts exist and forces your format abstraction to carry per-target data.

**Sources**
- OWASP Password Storage Cheat Sheet (salting rationale): https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html

---

## Milestone 6 — Slow Hashes (bcrypt, PBKDF2)

**Target:** Crack a deliberately slow, work-factored hash.

**How it should work**
- These algorithms are *designed* to be expensive: bcrypt has a cost factor, PBKDF2 an iteration count. A single hash can take milliseconds instead of nanoseconds.
- Your cracker's throughput drops by orders of magnitude, which completely reshapes strategy: brute force becomes hopeless, and smart dictionaries + rules become essential.
- Use a vetted library for these — implementing bcrypt yourself is error-prone and not the point of this milestone.

**Why:** Teaches the defender's side of the arms race: *why* modern systems use slow hashes, and what "work factor" buys. A great conceptual capstone.

**Sources**
- bcrypt — Provos & Mazières, "A Future-Adaptable Password Scheme" (USENIX 1999): https://www.usenix.org/legacy/events/usenix99/provos.html
- PBKDF2 — RFC 8018 (PKCS #5 v2.1): https://www.rfc-editor.org/rfc/rfc8018
- OWASP Password Storage Cheat Sheet (recommended parameters): https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html

---

## Cross-Cutting Concerns (add as you go)

| Concern | What it is | When to add |
|---|---|---|
| **`.pot` file** | A record of already-cracked hashes so you never re-crack them | After Milestone 2 |
| **Multithreading** | Split the keyspace/wordlist across CPU cores | After Milestone 3 |
| **SIMD** | Hash several candidates at once in wide registers | Once single-thread MD5 is correct & benchmarked |
| **Benchmark mode** | `--benchmark` prints candidates/second | Early — you can't optimize what you don't measure |
| **CI + test vectors** | Automated correctness check on every commit | As soon as Milestone 0 passes |

**Reference implementations to study (not copy):**
- John the Ripper: https://github.com/openwall/john
- hashcat: https://github.com/hashcat/hashcat

---

## Ethics & Scope

This is a tool for **learning, CTFs, and auditing systems you own or are authorized to test**.
Only ever run it against hashes you have permission to crack. Keep that boundary clear in your
README from day one.
