
### hashcrack.py

```python
#!/usr/bin/env python3
"""
hashcrack - A lightweight hash cracking tool
Supports: MD5, SHA1, SHA224, SHA256, SHA384, SHA512
Attack modes: dictionary, brute force
Pure Python, zero dependencies.
"""

import hashlib
import argparse
import sys
import os
import time
import itertools
import string

SUPPORTED_ALGORITHMS = {
    'md5': hashlib.md5,
    'sha1': hashlib.sha1,
    'sha224': hashlib.sha224,
    'sha256': hashlib.sha256,
    'sha384': hashlib.sha384,
    'sha512': hashlib.sha512,
}

EXPECTED_LENGTHS = {
    'md5': 32,
    'sha1': 40,
    'sha224': 56,
    'sha256': 64,
    'sha384': 96,
    'sha512': 128,
}


def hash_string(text, algorithm):
    """Hash a string with the given algorithm."""
    hasher = SUPPORTED_ALGORITHMS[algorithm]()
    hasher.update(text.encode('utf-8'))
    return hasher.hexdigest()


def identify_hash(h):
    """Try to identify hash type by length."""
    h = h.strip().lower()
    for algo, length in EXPECTED_LENGTHS.items():
        if len(h) == length:
            return algo
    return None


def dictionary_attack(target_hash, algorithm, wordlist_path, verbose=False):
    """Try to crack hash using a dictionary file."""
    target_hash = target_hash.strip().lower()
    attempts = 0
    start = time.time()

    if not os.path.exists(wordlist_path):
        print(f"[-] Wordlist not found: {wordlist_path}")
        return None

    with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            word = line.rstrip('\n\r')
            if not word:
                continue
            attempts += 1
            h = hash_string(word, algorithm)
            if h == target_hash:
                elapsed = time.time() - start
                print(f"[+] CRACKED: {word}")
                print(f"    Hash: {h}")
                print(f"    Algorithm: {algorithm}")
                print(f"    Attempts: {attempts}")
                print(f"    Time: {elapsed:.2f}s")
                return word
            if verbose and attempts % 10000 == 0:
                elapsed = time.time() - start
                rate = attempts / elapsed if elapsed > 0 else 0
                print(f"[*] Tried {attempts} words ({rate:.0f}/s)")

    elapsed = time.time() - start
    print(f"[-] Not found. Tried {attempts} words in {elapsed:.2f}s")
    return None


def brute_force_attack(target_hash, algorithm, charset=None, min_len=1, max_len=8, verbose=False):
    """Try to crack hash using brute force."""
    target_hash = target_hash.strip().lower()

    if charset is None:
        charset = string.ascii_lowercase + string.digits

    attempts = 0
    start = time.time()

    for length in range(min_len, max_len + 1):
        print(f"[*] Trying length {length}...")
        for combo in itertools.product(charset, repeat=length):
            word = ''.join(combo)
            attempts += 1
            h = hash_string(word, algorithm)
            if h == target_hash:
                elapsed = time.time() - start
                print(f"[+] CRACKED: {word}")
                print(f"    Hash: {h}")
                print(f"    Algorithm: {algorithm}")
                print(f"    Attempts: {attempts}")
                print(f"    Time: {elapsed:.2f}s")
                return word
            if verbose and attempts % 100000 == 0:
                elapsed = time.time() - start
                rate = attempts / elapsed if elapsed > 0 else 0
                print(f"[*] Tried {attempts} combos ({rate:.0f}/s)")

    elapsed = time.time() - start
    print(f"[-] Not found. Tried {attempts} combos in {elapsed:.2f}s")
    return None


def generate_hash(text, algorithm):
    """Generate hash for given text."""
    return hash_string(text, algorithm)


def main():
    parser = argparse.ArgumentParser(
        description='hashcrack - A lightweight hash cracking tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python hashcrack.py -t d41d8cd98f00b204e9800998ecf8427e -a md5 -w wordlist.txt
  python hashcrack.py -t d41d8cd98f00b204e9800998ecf8427e -a md5 -b --max-len 6
  python hashcrack.py -t d41d8cd98f00b204e9800998ecf8427e --auto -w wordlist.txt
  python hashcrack.py -g hello -a sha256
        """
    )

    parser.add_argument('-t', '--target', help='Target hash to crack')
    parser.add_argument('-a', '--algorithm', choices=list(SUPPORTED_ALGORITHMS.keys()),
                        help='Hash algorithm')
    parser.add_argument('-w', '--wordlist', help='Path to wordlist file')
    parser.add_argument('-b', '--brute', action='store_true', help='Use brute force attack')
    parser.add_argument('--charset', help='Custom charset for brute force (default: a-z0-9)')
    parser.add_argument('--min-len', type=int, default=1, help='Min length for brute force (default: 1)')
    parser.add_argument('--max-len', type=int, default=8, help='Max length for brute force (default: 8)')
    parser.add_argument('--auto', action='store_true', help='Auto-detect hash algorithm by length')
    parser.add_argument('-g', '--generate', help='Generate hash for given text')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')

    args = parser.parse_args()

    # Generate mode
    if args.generate:
        if not args.algorithm:
            print("[-] Need -a/--algorithm to generate hash")
            sys.exit(1)
        h = generate_hash(args.generate, args.algorithm)
        print(f"{args.generate} -> {h}")
        return

    # Crack mode
    if not args.target:
        parser.print_help()
        sys.exit(1)

    target = args.target.strip().lower()

    # Auto-detect algorithm
    if args.auto:
        detected = identify_hash(target)
        if detected:
            algorithm = detected
            print(f"[*] Detected algorithm: {algorithm}")
        else:
            print(f"[-] Could not auto-detect hash type (length: {len(target)})")
            sys.exit(1)
    else:
        if not args.algorithm:
            print("[-] Need -a/--algorithm or --auto")
            sys.exit(1)
        algorithm = args.algorithm

    # Validate hash length matches algorithm
    if len(target) != EXPECTED_LENGTHS[algorithm]:
        print(f"[-] Hash length {len(target)} doesn't match {algorithm} (expected {EXPECTED_LENGTHS[algorithm]})")
        sys.exit(1)

    print(f"[*] Target: {target}")
    print(f"[*] Algorithm: {algorithm}")

    if args.brute:
        charset = args.charset if args.charset else string.ascii_lowercase + string.digits
        print(f"[*] Mode: Brute Force")
        print(f"[*] Charset: {charset}")
        print(f"[*] Length: {args.min_len}-{args.max_len}")
        print()
        brute_force_attack(target, algorithm, charset, args.min_len, args.max_len, args.verbose)
    elif args.wordlist:
        print(f"[*] Mode: Dictionary")
        print(f"[*] Wordlist: {args.wordlist}")
        print()
        dictionary_attack(target, algorithm, args.wordlist, args.verbose)
    else:
        print("[-] Need -w/--wordlist or -b/--brute")
        sys.exit(1)


if __name__ == '__main__':
    main()
