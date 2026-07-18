Brute force attack
python hashcrack.py -t d41d8cd98f00b204e9800998ecf8427e -a md5 -b --max-len 6
Auto-detect algorithm
python hashcrack.py -t d41d8cd98f00b204e9800998ecf8427e --auto -w wordlist.txt
Custom charset brute force
python hashcrack.py -t d41d8cd98f00b204e9800998ecf8427e -a md5 -b --charset "abc123" --max-len 4
python hashcrack.py -g hello -a sha256
Options
Flag	Description
-t	Target hash to crack
-a	Hash algorithm (md5, sha1, sha224, sha256, sha384, sha512)
-w	Path to wordlist file
-b	Use brute force attack
--charset	Custom charset for brute force (default: a-z0-9)
--min-len	Min length for brute force (default: 1)
--max-len	Max length for brute force (default: 8)
--auto	Auto-detect hash algorithm by length
-g	Generate hash for given text
-v	Verbose output
Requirements
Python 3.6+
