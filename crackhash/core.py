# -*- coding: utf-8 -*-

"""Main module."""

import base64
import random
from yaspin import yaspin
from .helpers import *
from .scraper import *
from .browser import *

USER_AGENTS = [
    "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; Crazy Browser 1.0.5)",
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
    "Mozilla/5.0 (Windows NT 6.1) AppleWebKit/535.1 (KHTML, like Gecko) Chrome/14.0.812.0 Safari/535.1"
]

md5 = [
    myaddr,
    nitrxgen,
    cmd5,
    hashcrack,
    md5decrypt,
    hashtoolkit,
    md5hashing,
    hashkiller]
sha1 = [md5decrypt, cmd5, md5hashing, hashkiller]
sha256 = [md5decrypt, cmd5, md5hashing]
sha384 = [md5decrypt, cmd5, md5hashing]
sha512 = [md5decrypt, cmd5, md5hashing]
rmd128 = [md5hashing]
rmd160 = [md5hashing]
rmd256 = [md5hashing]
rmd320 = [md5hashing]
lm = [it64]
ntlm = [md5decrypt, cmd5, hashkiller]
mysql = [cmd5, hashkiller]
cisco = [passworddecrypt, m00nie, firewallruletest, ifm, ibeast]
juniper = [passworddecrypt, m00nie]
gost = [md5hashing]
whirlpool = [md5hashing]
ldap_md5 = [
    myaddr,
    nitrxgen,
    hashcrack,
    md5decrypt,
    hashtoolkit,
    md5hashing,
    hashkiller]
ldap_sha1 = [md5decrypt, md5hashing, hashkiller]


class Crackhash():

    def __init__(self, proxy=None):
        self.browser = Browser()
        self.ua = random.choice(USER_AGENTS)
        self.result = {}

    def start(self, proxy=None):
        if proxy:
            self.browser.start(headless=True, proxy=proxy, user_agent=self.ua)
        else:
            self.browser.start(headless=True, user_agent=self.ua)

    def close(self):
        self.browser.stop()

    def validate_hash(self, hashvalue, algorithm):
        res = False
        if len(hashvalue) == 32 and algorithm == 'md5':
            res = True
        elif len(hashvalue) == 40 and algorithm == 'sha1':
            res = True
        elif len(hashvalue) == 60 and algorithm == 'sha256':
            res = True
        elif len(hashvalue) == 96 and algorithm == 'sha384':
            res = True
        elif len(hashvalue) == 128 and algorithm == 'sha512':
            res = True
        elif len(hashvalue) == 32 and algorithm == 'rmd128':
            res = True
        elif len(hashvalue) == 40 and algorithm == 'rmd160':
            res = True
        elif len(hashvalue) == 64 and algorithm == 'rmd256':
            res = True
        elif len(hashvalue) == 80 and algorithm == 'rmd320':
            res = True
        elif len(hashvalue) == 32 and algorithm == 'lm':
            res = True
        elif len(hashvalue) == 32 and algorithm == 'ntlm':
            res = True
        elif (len(hashvalue) == 16 or len(hashvalue) == 40) and algorithm == 'mysql':
            res = True
        elif hashvalue.startswith('$9$') and algorithm == 'juniper':
            res = True
        elif algorithm == 'cisco':
            res = True
        elif len(hashvalue) == 60 and algorithm == 'gost':
            res = True
        elif len(hashvalue) == 128 and algorithm == 'whirlpool':
            res = True
        elif hashvalue.startswith('{MD5}') and algorithm == 'ldap_md5':
            res = True
        elif hashvalue.startswith('{SHA}') and algorithm == 'ldap_sha1':
            res = True
        else:
            res = False

        return res

    def get_algo(self, hashvalue):
        algo = ''
        if len(hashvalue) == 32:
            algo = 'md5'
        elif len(hashvalue) == 40:
            algo = 'sha1'
        elif len(hashvalue) == 60:
            algo = 'sha256'
        elif len(hashvalue) == 96:
            algo = 'sha384'
        elif len(hashvalue) == 128:
            algo = 'sha512'
        elif len(hashvalue) == 32:
            algo = 'rmd128'
        elif len(hashvalue) == 40:
            algo = 'rmd160'
        elif len(hashvalue) == 64:
            algo = 'rmd256'
        elif len(hashvalue) == 80:
            algo = 'rmd320'
        elif len(hashvalue) == 32:
            algo = 'lm'
        elif len(hashvalue) == 32:
            algo = 'ntlm'
        elif (len(hashvalue) == 16 or len(hashvalue) == 40):
            algo = 'mysql'
        elif hashvalue.startswith('$9$'):
            algo = 'juniper'
        elif hashvalue == 'cisco':
            algo = 'cisco'
        elif len(hashvalue) == 60:
            algo = 'gost'
        elif len(hashvalue) == 128:
            algo = 'whirlpool'
        elif hashvalue.startswith('{MD5}'):
            algo = 'ldap_md5'
        elif hashvalue.startswith('{SHA}'):
            algo = 'ldap_sha1'
        else:
            algo = ''

        return algo

    def check(self, hashvalue, algorithm):
        if algorithm == 'md5':
            self.check_md5(hashvalue)
        elif algorithm == 'sha1':
            self.check_sha1(hashvalue)
        elif algorithm == 'sha256':
            self.check_sha256(hashvalue)
        elif algorithm == 'sha384':
            self.check_sha384(hashvalue)
        elif algorithm == 'sha512':
            self.check_sha512(hashvalue)
        elif algorithm == 'rmd128':
            self.check_rmd128(hashvalue)
        elif algorithm == 'rmd160':
            self.check_rmd160(hashvalue)
        elif algorithm == 'rmd256':
            self.check_rmd256(hashvalue)
        elif algorithm == 'rmd320':
            self.check_rmd320(hashvalue)
        elif algorithm == 'lm':
            self.check_lm(hashvalue)
        elif algorithm == 'ntlm':
            self.check_ntlm(hashvalue)
        elif algorithm == 'mysql':
            self.check_mysql(hashvalue)
        elif algorithm == 'juniper':
            self.check_juniper(hashvalue)
        elif algorithm == 'cisco':
            self.check_cisco(hashvalue)
        elif algorithm == 'gost':
            self.check_gost(hashvalue)
        elif algorithm == 'whirlpool':
            self.check_whirlpool(hashvalue)
        elif algorithm == 'ldap_md5':
            self.check_ldap_md5(hashvalue)
        elif algorithm == 'ldap_sha1':
            self.check_ldap_sha1(hashvalue)
        else:
            print_error('This hash is not supported.')

    def batch(self, file):
        lines = []
        with open(file, 'r') as f:
            for line in f:
                lines.append(line.strip('\n'))
        for line in lines:
            hashtype, hashvalue = line.split(':')
            if self.validate_hash(hashvalue, hashtype):
                self.check(hashvalue, hashtype)

    def check_md5(self, hash):
        for api in md5:
            with yaspin(text="Processing...", color="cyan") as sp:
                match = api(self.browser, hash, 'md5')
                if match:
                    sp.ok("✔")
                    print_success("Hash cracked: " +
                                  (Colors.YELLOW) +
                                  (Colors.BOLD) +
                                  "%s" %
                                  match +
                                  (Colors.ENDC))
                    break
                else:
                    if md5.index(api) == len(md5) - 1 and not match:
                        sp.fail("✗")
                        print_error(
                            "Hash not found! Try to crack it yourself.")

    def check_sha1(self, hash):
        for api in sha1:
            with yaspin(text="Processing...", color="cyan") as sp:
                match = api(self.browser, hash, 'sha1')
                if match:
                    sp.ok("✔")
                    print_success("Hash cracked: " +
                                  (Colors.YELLOW) +
                                  (Colors.BOLD) +
                                  "%s" %
                                  match +
                                  (Colors.ENDC))
                    break
                else:
                    if sha1.index(api) == len(sha1) - 1 and not match:
                        sp.fail("✗")
                        print_error(
                            "Hash not found! Try to crack it yourself.")

    def check_sha256(self, hash):
        for api in sha256:
            with yaspin(text="Processing...", color="cyan") as sp:
                match = api(self.browser, hash, 'sha256')
                if match:
                    sp.ok("✔")
                    print_success("Hash cracked: " +
                                  (Colors.YELLOW) +
                                  (Colors.BOLD) +
                                  "%s" %
                                  match +
                                  (Colors.ENDC))
                    break
                else:
                    if sha256.index(api) == len(sha256) - 1 and not match:
                        sp.fail("✗")
                        print_error(
                            "Hash not found! Try to crack it yourself.")

    def check_sha384(self, hash):
        for api in sha384:
            with yaspin(text="Processing...", color="cyan") as sp:
                match = api(self.browser, hash, 'sha384')
                if match:
                    sp.ok("✔")
                    print_success("Hash cracked: " +
                                  (Colors.YELLOW) +
                                  (Colors.BOLD) +
                                  "%s" %
                                  match +
                                  (Colors.ENDC))
                    break
                else:
                    if sha384.index(api) == len(sha384) - 1 and not match:
                        sp.fail("✗")
                        print_error(
                            "Hash not found! Try to crack it yourself.")

    def check_sha512(self, hash):
        for api in sha512:
            with yaspin(text="Processing...", color="cyan") as sp:
                match = api(self.browser, hash, 'sha512')
                if match:
                    sp.ok("✔")
                    print_success("Hash cracked: " +
                                  (Colors.YELLOW) +
                                  (Colors.BOLD) +
                                  "%s" %
                                  match +
                                  (Colors.ENDC))
                    break
                else:
                    if sha512.index(api) == len(sha512) - 1 and not match:
                        sp.fail("✗")
                        print_error(
                            "Hash not found! Try to crack it yourself.")

    def check_rmd128(self, hash):
        for api in rmd128:
            with yaspin(text="Processing...", color="cyan") as sp:
                match = api(self.browser, hash, 'rmd128')
                if match:
                    sp.ok("✔")
                    print_success("Hash cracked: " +
                                  (Colors.YELLOW) +
                                  (Colors.BOLD) +
                                  "%s" %
                                  match +
                                  (Colors.ENDC))
                    break
                else:
                    if rmd128.index(api) == len(rmd128) - 1 and not match:
                        sp.fail("✗")
                        print_error(
                            "Hash not found! Try to crack it yourself.")

    def check_rmd160(self, hash):
        for api in rmd160:
            with yaspin(text="Processing...", color="cyan") as sp:
                match = api(self.browser, hash, 'rmd160')
                if match:
                    sp.ok("✔")
                    print_success("Hash cracked: " +
                                  (Colors.YELLOW) +
                                  (Colors.BOLD) +
                                  "%s" %
                                  match +
                                  (Colors.ENDC))
                    break
                else:
                    if rmd160.index(api) == len(rmd160) - 1 and not match:
                        sp.fail("✗")
                        print_error(
                            "Hash not found! Try to crack it yourself.")

    def check_rmd256(self, hash):
        for api in rmd256:
            with yaspin(text="Processing...", color="cyan") as sp:
                match = api(self.browser, hash, 'rmd256')
                if match:
                    sp.ok("✔")
                    print_success("Hash cracked: " +
                                  (Colors.YELLOW) +
                                  (Colors.BOLD) +
                                  "%s" %
                                  match +
                                  (Colors.ENDC))
                    break
                else:
                    if rmd256.index(api) == len(rmd256) - 1 and not match:
                        sp.fail("✗")
                        print_error(
                            "Hash not found! Try to crack it yourself.")

    def check_rmd320(self, hash):
        for api in rmd320:
            with yaspin(text="Processing...", color="cyan") as sp:
                match = api(self.browser, hash, 'rmd320')
                if match:
                    sp.ok("✔")
                    print_success("Hash cracked: " +
                                  (Colors.YELLOW) +
                                  (Colors.BOLD) +
                                  "%s" %
                                  match +
                                  (Colors.ENDC))
                    break
                else:
                    if rmd320.index(api) == len(rmd320) - 1 and not match:
                        sp.fail("✗")
                        print_error(
                            "Hash not found! Try to crack it yourself.")

    def check_lm(self, hash):
        for api in lm:
            with yaspin(text="Processing...", color="cyan") as sp:
                match = api(self.browser, hash, 'lm')
                if match:
                    sp.ok("✔")
                    print_success("Hash cracked: " +
                                  (Colors.YELLOW) +
                                  (Colors.BOLD) +
                                  "%s" %
                                  match +
                                  (Colors.ENDC))
                    break
                else:
                    if lm.index(api) == len(lm) - 1 and not match:
                        sp.fail("✗")
                        print_error(
                            "Hash not found! Try to crack it yourself.")

    def check_ntlm(self, hash):
        for api in ntlm:
            with yaspin(text="Processing...", color="cyan") as sp:
                match = api(self.browser, hash, 'ntlm')
                if match:
                    sp.ok("✔")
                    print_success("Hash cracked: " +
                                  (Colors.YELLOW) +
                                  (Colors.BOLD) +
                                  "%s" %
                                  match +
                                  (Colors.ENDC))
                    break
                else:
                    if ntlm.index(api) == len(ntlm) - 1 and not match:
                        sp.fail("✗")
                        print_error(
                            "Hash not found! Try to crack it yourself.")

    def check_mysql(self, hash):
        for api in mysql:
            with yaspin(text="Processing...", color="cyan") as sp:
                match = api(self.browser, hash, 'mysql')
                if match:
                    sp.ok("✔")
                    print_success("Hash cracked: " +
                                  (Colors.YELLOW) +
                                  (Colors.BOLD) +
                                  "%s" %
                                  match +
                                  (Colors.ENDC))
                    break
                else:
                    if mysql.index(api) == len(mysql) - 1 and not match:
                        sp.fail("✗")
                        print_error(
                            "Hash not found! Try to crack it yourself.")

    def check_cisco(self, hash):
        for api in cisco:
            with yaspin(text="Processing...", color="cyan") as sp:
                match = api(self.browser, hash, 'cisco')
                if match:
                    sp.ok("✔")
                    print_success("Hash cracked: " +
                                  (Colors.YELLOW) +
                                  (Colors.BOLD) +
                                  "%s" %
                                  match +
                                  (Colors.ENDC))
                    break
                else:
                    if cisco.index(api) == len(cisco) - 1 and not match:
                        sp.fail("✗")
                        print_error(
                            "Hash not found! Try to crack it yourself.")

    def check_juniper(self, hash):
        for api in juniper:
            with yaspin(text="Processing...", color="cyan") as sp:
                match = api(self.browser, hash, 'juniper')
                if match:
                    sp.ok("✔")
                    print_success("Hash cracked: " +
                                  (Colors.YELLOW) +
                                  (Colors.BOLD) +
                                  "%s" %
                                  match +
                                  (Colors.ENDC))
                    break
                else:
                    if juniper.index(api) == len(juniper) - 1 and not match:
                        sp.fail("✗")
                        print_error(
                            "Hash not found! Try to crack it yourself.")

    def check_gost(self, hash):
        for api in gost:
            with yaspin(text="Processing...", color="cyan") as sp:
                match = api(self.browser, hash, 'gost')
                if match:
                    sp.ok("✔")
                    print_success("Hash cracked: " +
                                  (Colors.YELLOW) +
                                  (Colors.BOLD) +
                                  "%s" %
                                  match +
                                  (Colors.ENDC))
                    break
                else:
                    if gost.index(api) == len(gost) - 1 and not match:
                        sp.fail("✗")
                        print_error(
                            "Hash not found! Try to crack it yourself.")

    def check_whirlpool(self, hash):
        for api in whirlpool:
            with yaspin(text="Processing...", color="cyan") as sp:
                match = api(self.browser, hash, 'whirlpool')
                if match:
                    sp.ok("✔")
                    print_success("Hash cracked: " +
                                  (Colors.YELLOW) +
                                  (Colors.BOLD) +
                                  "%s" %
                                  match +
                                  (Colors.ENDC))
                    break
                else:
                    if whirlpool.index(api) == len(
                            whirlpool) - 1 and not match:
                        sp.fail("✗")
                        print_error(
                            "Hash not found! Try to crack it yourself.")

    def check_ldap_md5(self, hash):
        hash = str(base64.b64decode(hash[5:])).replace(
            "b'", "").replace("\\n'", "")
        for api in ldap_md5:
            with yaspin(text="Processing...", color="cyan") as sp:
                match = api(self.browser, hash, 'md5')
                if match:
                    sp.ok("✔")
                    print_success("Hash cracked: " +
                                  (Colors.YELLOW) +
                                  (Colors.BOLD) +
                                  "%s" %
                                  match +
                                  (Colors.ENDC))
                    break
                else:
                    if ldap_md5.index(api) == len(ldap_md5) - 1 and not match:
                        sp.fail("✗")
                        print_error(
                            "Hash not found! Try to crack it yourself.")

    def check_ldap_sha1(self, hash):
        hash = str(base64.b64decode(hash[5:])).replace(
            "b'", "").replace("\\n'", "")
        for api in ldap_sha1:
            with yaspin(text="Processing...", color="cyan") as sp:
                match = api(self.browser, hash, 'sha1')
                if match:
                    sp.ok("✔")
                    print_success("Hash cracked: " +
                                  (Colors.YELLOW) +
                                  (Colors.BOLD) +
                                  "%s" %
                                  match +
                                  (Colors.ENDC))
                    break
                else:
                    if ldap_sha1.index(api) == len(
                            ldap_sha1) - 1 and not match:
                        sp.fail("✗")
                        print_error(
                            "Hash not found! Try to crack it yourself.")
