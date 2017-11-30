```
  /\  /\__ _ ___| |__         / __\ __ __ _  ___| | _____ _ __ 
 / /_/ / _` / __| '_ \ _____ / / | '__/ _` |/ __| |/ / _ \ '__|
/ __  / (_| \__ \ | | |_____/ /__| | | (_| | (__|   <  __/ |   
\/ /_/ \__,_|___/_| |_|     \____/_|  \__,_|\___|_|\_\___|_|   v1.0
                                                 @5h4d0wb0y

```

# Description

Hash-Cracker is a tool which try to crack different types of hashes using free online services.

Features:
- [x] Detects hash
- [x] MD5 Support
- [x] SHA1 Support
- [x] SHA256 Support
- [x] SHA384 Support
- [x] SHA512 Support
- [ ] RMD160 Support
- [x] LM Support
- [x] NTLM Support
- [x] MYSQL Support
- [ ] CISCO Support
- [ ] JUNIPER Support
- [ ] GOST Support
- [ ] WHIRLPOOL Support
- [ ] LDAP_MD5 Support
- [ ] LDAP_SHA1 Support
    
# Usage

```
usage: hash-cracker.py [-h] [-a <algorithm>] [--hash <hash>]

optional arguments:
  -h, --help            show this help message and exit
  -a <algorithm>, --algorithm <algorithm>
                        Choose hash' algorithm between ['md5', 'sha1',
                        'sha256', 'sha384', 'sha512', 'rmd160', 'lm', 'ntlm',
                        'mysql', 'cisco', 'juniper', 'gost', 'whirlpool',
                        'ldap_md5', 'ldap_sha1']
  --hash <hash>         Specify a hash to crack
```

# Installation

```
git clone https://github.com/5h4d0wb0y/hash-cracker.git
cd hash-cracker
pip install -r requirements.txt
```

# Examples

Try to crack md5 hash:

```
python hash-cracker.py --algorithm md5 --hash 098f6bcd4621d373cade4e832627b4f6
```

Try to crack sha1 hash:

```
python hash-cracker.py --algorithm sha1 --hash A94A8FE5CCB19BA61C4C0873D391E987982FBBD3
```

# Credits

Hash-Cracker is developed by [@5h4d0wb0y](https://twitter.com/5h4d0wb0y).
