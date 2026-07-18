# hashcrack

A lightweight hash cracking tool written in pure Python. No dependencies.

## Features

- Supports MD5, SHA1, SHA224, SHA256, SHA384, SHA512
- Dictionary attack mode
- Brute force attack mode with custom charset
- Auto-detect hash algorithm by length
- Hash generation
- Progress reporting

## Usage

### Dictionary attack
```bash
python hashcrack.py -t d41d8cd98f00b204e9800998ecf8427e -a md5 -w wordlist.txt
