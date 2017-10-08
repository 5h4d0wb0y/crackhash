#!/usr/bin/env python
# -*- coding: utf -*-

try:
    import argparse
    import sys
    from urllib import urlopen, urlencode
    from re import search
    from terminaltables import SingleTable #AsciiTable

except:
    print """
Execution error:
  You required some basic Python libraries. 
  Please, check if you have all of them installed in your system or type 'pip install -r requirements.txt'.
"""
    sys.exit(-1)


# Variables
MD5DECRYPT_EMAIL = 'deanna_abshire@proxymail.eu'
MD5DECRYPT_CODE = '1152464b80a61728'

# Constants
ALGORITHMS = [
    "md5",
    "sha1",
    "sha256",
    "sha384",
    "sha512",
    "rmd160",
    "lm",
    "ntlm",
    "mysql",
    "cisco",
    "juniper",
    "gost",
    "whirlpool",
    "ldap_md5",
    "ldap_sha1"
]

USER_AGENTS = [
    "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; Crazy Browser 1.0.5)",
    "curl/7.7.2 (powerpc-apple-darwin6.0) libcurl 7.7.2 (OpenSSL 0.9.6b)",
    "Mozilla/5.0 (X11; U; Linux amd64; en-US; rv:5.0) Gecko/20110619 Firefox/5.0",
    "Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:2.0b8pre) Gecko/20101213 Firefox/4.0b8pre",
    "Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1; Trident/6.0)",
    "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 7.1; Trident/5.0)",
    "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0) chromeframe/10.0.648.205",
    "Mozilla/5.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0; InfoPath.2; SLCC1; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729; .NET CLR 2.0.50727)",
    "Opera/9.80 (Windows NT 6.1; U; sv) Presto/2.7.62 Version/11.01",
    "Opera/9.80 (Windows NT 6.1; U; pl) Presto/2.7.62 Version/11.00",
    "Opera/9.80 (X11; Linux i686; U; pl) Presto/2.6.30 Version/10.61",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_7_0) AppleWebKit/535.2 (KHTML, like Gecko) Chrome/15.0.861.0 Safari/535.2",
    "Mozilla/5.0 (Windows NT 5.1) AppleWebKit/535.2 (KHTML, like Gecko) Chrome/15.0.872.0 Safari/535.2",
    "Mozilla/5.0 (Windows NT 6.1) AppleWebKit/535.1 (KHTML, like Gecko) Chrome/14.0.812.0 Safari/535.1",
    "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
]

class Colors:
    PURPLE = '\033[95m'
    CYAN = '\033[96m'
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BOLD = '\033[1m'
    ENDC = '\033[0m'

def print_status(message):
    print(("[") + (Colors.GREEN) + (Colors.BOLD) + ("✔") + (Colors.ENDC) + ("] ") + (str(message)))

def print_warning(message):
    print(("[") + (Colors.YELLOW) + (Colors.BOLD) + ("!") + (Colors.ENDC) + ("] ") + (str(message)))

def print_error(message):
    print(("[") + (Colors.RED) + (Colors.BOLD) + ("✖") + (Colors.ENDC) + ("] ") + (str(message)))

class Cracker:
    def md5(self):
        print_warning("Searching with md5decrypt.net ...")
        print_warning("Searching with https://hashkiller.co.uk/md5-decrypter.aspx ...")
        print_warning("Searching with md5hashing.net ...")
        ##############################################################
        print_warning("Hash function: " + (Colors.YELLOW) + (Colors.BOLD) + "MD5" + (Colors.ENDC))
        print_warning("Searching with md5decryption.com ...")
        data = urlencode({"hash": args.hash, "submit": "Decrypt It!"})
        html = urlopen("http://md5decryption.com", data)
        find = html.read()
        match = search(r"Decrypted Text: </b>[^<]*</font>", find)
        if match:
            print_status("Hash cracked: %s" % match.group().split('b>')[1][:-7])
            sys.exit()
        else:
            print_warning("Searching with md5.my-addr.com ...")
            data = urlencode({"md5": args.hash, "x": "21", "y": "8"})
            html = urlopen("http://md5.my-addr.com/md5_decrypt-md5_cracker_online/md5_decoder_tool.php", data)
            find = html.read()
            match = search(r"<span class='middle_title'>Hashed string</span>: [^<]*</div>", find)
            if match:
                print_status("Hash cracked: %s" % match.group().split('span')[2][3:-6])
                sys.exit()
            else:
                print_warning("Searching with nitrxgen.net ...")
                url = "http://www.nitrxgen.net/md5db/" + args.hash
                purl = urlopen(url).read()
                if len(purl) > 0:
                    print_status("Hash cracked: %s" % purl)
                    sys.exit()
                else:
                    print_warning("Searching with http://hashcrack.com/ ...")
                    data = urlencode({"auth": "8272hgt", "hash": args.hash, "string": "", "Submit": "Submit"})
                    html = urlopen("http://hashcrack.com/index.php", data)
                    find = html.read()
                    match = search(r'<span class=hervorheb2>[^<]*</span></div></TD>', find)
                    if match:
                        print_status("Hash cracked: %s" % match.group().split('hervorheb2>')[1][:-18])
                        sys.exit()
                    else:
                        print_error("Sorry this hash is not present in our database.")
                        sys.exit()

    def sha1(self):
        print_warning("Hash function: SHA1")
        print_warning("Searching with http://hashcrack.com/ ...")
        data = urlencode({"auth": "8272hgt", "hash": args.hash, "string": "", "Submit": "Submit"})
        html = urlopen("http://hashcrack.com/index.php", data)
        find = html.read()
        match = search(r'<span class=hervorheb2>[^<]*</span></div></TD>', find)
        if match:
            print_status("Hash cracked: %s" % match.group().split('hervorheb2>')[1][:-18])
            sys.exit()
        else:
            print_warning("Searching with md5decrypt.net ...")
            html = urlopen("http://md5decrypt.net/Api/api.php?hash=" + args.hash + "&hash_type=sha1&email=" + MD5DECRYPT_EMAIL + "&code=" + MD5DECRYPT_CODE)
            find = html.read()
            if len(find) > 0:
                print_status("Hash cracked: %s" % find)
                sys.exit()
            else:
                print_warning("Searching with https://hashkiller.co.uk/sha1-decrypter.aspx ...")
                print_warning("Searching with md5hashing.net ...")
                ##
                print_error("Sorry this hash is not present in our database.")
                sys.exit()

    def sha256(self):
        print_status("Hash function: SHA-256")
        print_warning("Searching with md5decrypt.net ...")
        html = urlopen("http://md5decrypt.net/Api/api.php?hash=" + args.hash + "&hash_type=sha256&email=" + MD5DECRYPT_EMAIL + "&code=" + MD5DECRYPT_CODE)
        find = html.read()
        if len(find) > 0:
            print_status("Hash cracked: %s" % find)
            sys.exit()
        else:
            print_warning("Searching with md5hashing.net ...")
            ##
            print_error("Sorry this hash is not present in our database.")
            sys.exit()

    def sha384(self):
        print_status("Hash function: SHA-384")
        print_warning("Searching with md5decrypt.net ...")
        print_warning("Searching with md5hashing.net ...")

    def sha512(self):
        print_status("Hash function: SHA-512")
        print_warning("Searching with md5decrypt.net ...")
        print_warning("Searching with md5hashing.net ...")

    def rmd160(self):
        print_status("Hash function: RIPEMD-160")
        print_warning("Searching with md5hashing.net ...")

    def lm(self):
        print_status("Hash function: LM")
        print_warning("Searching with http://hashcrack.com/ ...")
        data = urlencode({"auth": "8272hgt", "hash": args.hash, "string": "", "Submit": "Submit"})
        html = urlopen("http://hashcrack.com/index.php", data)
        find = html.read()
        match = search(r'<span class=hervorheb2>[^<]*</span></div></TD>', find)
        if match:
            print_status("Hash cracked: %s" % match.group().split('hervorheb2>')[1][:-18])
            sys.exit()
        else:
            print_error("Sorry this hash is not present in our database.")
            sys.exit()

    def ntlm(self):
        print_status("Hash function: NTLM")
        print_warning("Searching with md5decrypt.net ...")
        print_warning("Searching with https://hashkiller.co.uk/ntlm-decrypter.aspx ...")
        print_warning("Searching with http://hashcrack.com/ ...")
        data = urlencode({"auth": "8272hgt", "hash": args.hash, "string": "", "Submit": "Submit"})
        html = urlopen("http://hashcrack.com/index.php", data)
        find = html.read()
        match = search(r'<span class=hervorheb2>[^<]*</span></div></TD>', find)
        if match:
            print_status("Hash cracked: %s" % match.group().split('hervorheb2>')[1][:-18])
            sys.exit()
        else:
            print_error("Sorry this hash is not present in our database.")
            sys.exit()

    def mysql(self):
        print_status("Hash function: MYSQL")
        print_warning("Searching with http://hashcrack.com/ ...")
        data = urlencode({"auth": "8272hgt", "hash": args.hash, "string": "", "Submit": "Submit"})
        html = urlopen("http://hashcrack.com/index.php", data)
        find = html.read()
        match = search(r'<span class=hervorheb2>[^<]*</span></div></TD>', find)
        if match:
            print_status("Hash cracked: %s" % match.group().split('hervorheb2>')[1][:-18])
            sys.exit()
        else:
            print_error("Sorry this hash is not present in our database.")
            sys.exit()

    def cisco(self):
        print_status("Hash function: CISCO")
        print_warning("Searching with http://password-decrypt.com/ ...")
        print_warning("Searching with https://www.m00nie.com/type-7-password-tool/ ...")

    def juniper(self):
        print_status("Hash function: JUNIPER")
        print_warning("Searching with http://password-decrypt.com/ ...")
        print_warning("Searching with http://www.junostools.com/pdecrypt ...")
        print_warning("Searching with https://www.m00nie.com/juniper-type-9-password-tool/ ...")

    def gost(self):
        print_status("Hash function: GOST")
        print_warning("Searching with md5hashing.net ...")
        print_warning("Searching with codebeautify.org/encrypt-decrypt ...")
        print_warning("https://www.tools4noobs.com/online_tools/decrypt/ ...")

    def whirlpool(self):
        print_status("Hash function: WHIRLPOOL")
        print_warning("Searching with md5hashing.net ...")

    def ldap_md5(self):
        print_status("Hash function: LDAP-MD5")
        print_warning("Searching with md5hashing.net ...")

    def ldap_sha1(self):
        print_status("Hash function: LDAP-SHA1")
        print_warning("Searching with md5hashing.net ...")


class HashCracker:

    def __init__(self):
        pass

    def show_banner(self):
        print (Colors.PURPLE) + (Colors.BOLD) + ("                 _             ___               _             ")
        print "  /\  /\__ _ ___| |__         / __\ __ __ _  ___| | _____ _ __ "
        print " / /_/ / _` / __| '_ \ _____ / / | '__/ _` |/ __| |/ / _ \ '__|"
        print "/ __  / (_| \__ \ | | |_____/ /__| | | (_| | (__|   <  __/ |   "
        print "\/ /_/ \__,_|___/_| |_|     \____/_|  \__,_|\___|_|\_\___|_|   " + (Colors.ENDC) + (Colors.YELLOW) + (Colors.BOLD) + ("v1.0") + (Colors.ENDC)
        print "                                                 " + (Colors.CYAN) + (Colors.BOLD) + ("@5h4d0wb0y\n") + (Colors.ENDC)

    def validate_args(self):
        parser = argparse.ArgumentParser(description="")
        parser.add_argument("--algorithm", metavar="<algorithm>", dest="algorithm", default=None, help="")
        parser.add_argument("--hash", metavar="<hash>", dest="hash", default=None, help="")
        args = parser.parse_args()

        if not args.hash:
            print_error("Missing --hash argument")
            sys.exit(-1)
        if not args.algorithm:
            print_error("Missing --algorithm argument")
            sys.exit(-1)
        if args.algorithm not in ALGORITHMS:
            data = []
            for x in ALGORITHMS:
                data.append([x])
            t = SingleTable(data, 'Available Algorithms') #AsciiTable()
            t.inner_heading_row_border = False
            t.justify_columns[0] = 'center'
            print "Available Algorithms:"
            print t.table
            sys.exit(-1)
        return args

    def run(self, args):
        if len(args.hash) == 32 and args.algorithm == 'md5':
            Cracker.md5(args.hash)
        elif len(args.hash) == 40 and args.algorithm == 'sha1':
            Cracker.sha1(args.hash)
        elif len(args.hash) == 56 and args.algorithm == 'sha256':
            Cracker.sha256(args.hash)
        elif len(args.hash) == 64 and args.algorithm == 'sha384':
            Cracker.sha384(args.hash)
        elif len(args.hash) == 64 and args.algorithm == 'sha512':
            Cracker.sha512(args.hash)
        elif len(args.hash) == 32 and args.algorithm == 'rmd160':
            Cracker.rmd160(args.hash)
        elif len(args.hash) == 32 and args.algorithm == 'lm':
            Cracker.lm(args.hash)
        elif len(args.hash) == 32 and args.algorithm == 'ntlm':
            Cracker.ntlm(args.hash)
        elif len(args.hash) == 64 and args.algorithm == 'mysql':
            Cracker.mysql(args.hash)
        elif len(args.hash) == 64 and args.algorithm == 'juniper':
            Cracker.juniper(args.hash)
        elif len(args.hash) == 32 and args.algorithm == 'gost':
            Cracker.gost(args.hash)
        elif len(args.hash) == 64 and args.algorithm == 'whirlpool':
            Cracker.whirlpool(args.hash)
        elif len(args.hash) == 64 and args.algorithm == 'ldap_md5':
            Cracker.ldap_md5(args.hash)
        elif len(args.hash) == 64 and args.algorithm == 'ldap_sha1':
            Cracker.ldap_sha1(args.hash)
        else:
            print_error("This hash is not supported.")


# Main
if __name__ == "__main__":
    a = HashCracker()
    a.show_banner()
    args = a.validate_args()
    a.run(args)
