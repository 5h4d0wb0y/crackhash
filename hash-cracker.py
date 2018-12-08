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
    def md5(self, hash):
        print_status("Hash function: " + (Colors.YELLOW) + (Colors.BOLD) + "MD5" + (Colors.ENDC))
        print_warning("Searching with md5decryption.com ...")
        data = urlencode({"hash": hash, "submit": "Decrypt It!"})
        html = urlopen("http://md5decryption.com", data)
        find = html.read()
        match = search(r"Decrypted Text: </b>[^<]*</font>", find)
        if match:
            print_status("Hash cracked: %s" % match.group().split('b>')[1][:-7])
            sys.exit()
        else:
            print_warning("Searching with md5.my-addr.com ...")
            data = urlencode({"md5": hash, "x": "21", "y": "8"})
            html = urlopen("http://md5.my-addr.com/md5_decrypt-md5_cracker_online/md5_decoder_tool.php", data)
            find = html.read()
            match = search(r"<span class='middle_title'>Hashed string</span>: [^<]*</div>", find)
            if match:
                print_status("Hash cracked: %s" % match.group().split('span')[2][3:-6])
                sys.exit()
            else:
                print_warning("Searching with nitrxgen.net ...")
                url = "http://www.nitrxgen.net/md5db/" + hash
                purl = urlopen(url).read()
                if len(purl) > 0:
                    print_status("Hash cracked: %s" % purl)
                    sys.exit()
                else:
                    print_warning("Searching with http://hashcrack.com/ ...")
                    data = urlencode({"auth": "8272hgt", "hash": hash, "string": "", "Submit": "Submit"})
                    html = urlopen("http://hashcrack.com/index.php", data)
                    find = html.read()
                    match = search(r'<span class=hervorheb2>[^<]*</span></div></TD>', find)
                    if match:
                        print_status("Hash cracked: %s" % match.group().split('hervorheb2>')[1][:-18])
                        sys.exit()
                    else:
                        print_warning("Searching with md5decrypt.net ...")
                        html = urlopen(
                            "http://md5decrypt.net/Api/api.php?hash=" + hash + "&hash_type=md5&email=" +
                            MD5DECRYPT_EMAIL + "&code=" + MD5DECRYPT_CODE)
                        find = html.read()
                        if len(find) > 0:
                            print_status("Hash cracked: %s" % find)
                            sys.exit()
                        else:
                            import cfscrape
                            import requests
                            import StringIO
                            from PIL import Image
                            from pyquery import PyQuery
                            print_warning("Searching with https://hashkiller.co.uk/md5-decrypter.aspx ...")
                            scraper = cfscrape.create_scraper()
                            response = scraper.get('https://www.hashkiller.co.uk/md5-decrypter.aspx')
                            # Save headers and cookies, to be used in next request
                            session = requests.session()
                            session.headers = response.headers
                            session.cookies = response.cookies
                            query = PyQuery(response.content)
                            image_path = query("#content1_imgCaptcha").attr("src")
                            image_content = scraper.get('https://www.hashkiller.co.uk' + image_path).content
                            # Trying to decaptcha image
                            captcha_image = Image.open(StringIO.StringIO(image_content))
                            captcha_image.show()
                            while True:
                                captcha = raw_input(("[") + (Colors.YELLOW) + (Colors.BOLD) + ("!") + (Colors.ENDC) + (
                                    "] ") + "Input captcha: ")
                                if len(captcha) != 6:
                                    print_error("You must input the correct captcha!")
                                    continue
                                else:
                                    break
                            scraper = cfscrape.create_scraper(sess=scraper)
                            response = scraper.post('https://www.hashkiller.co.uk/md5-decrypter.aspx', data={
                                'ctl00$ScriptMan1': 'ctl00$content1$updDecrypt|ctl00$content1$btnSubmit',
                                'ctl00$content1$txtInput': hash,
                                'ctl00$content1$txtCaptcha': captcha,
                                '__EVENTTARGET': '',
                                '__EVENTARGUMENT': '',
                                '__VIEWSTATE': query("#__VIEWSTATE").attr("value"),
                                '__EVENTVALIDATION': query("#__EVENTVALIDATION").attr("value"),
                                '__ASYNCPOST': 'true',
                                'ctl00$content1$btnSubmit': 'Submit',
                                query('#content1_pnlStatus input').attr('name'): query(
                                    '#content1_pnlStatus input').attr(
                                    'value')
                            })
                            response = PyQuery(response.content)
                            status = response('#content1_lblStatus').text()
                            result = response('#content1_lblResults .text-green').text()
                            if 'Failed' in status:
                                print_error("Sorry this hash is not present in our database.")
                                sys.exit()
                            elif 'CAPTCHA' in status:
                                print_error("The CAPTCHA code you specified is wrong!")
                            else:
                                print_status("Hash cracked: %s" % result)
                                sys.exit()

    def sha1(self, hash):
        print_status("Hash function: " + (Colors.YELLOW) + (Colors.BOLD) + "SHA1" + (Colors.ENDC))
        print_warning("Searching with http://hashcrack.com/ ...")
        data = urlencode({"auth": "8272hgt", "hash": hash, "string": "", "Submit": "Submit"})
        html = urlopen("http://hashcrack.com/index.php", data)
        find = html.read()
        match = search(r'<span class=hervorheb2>[^<]*</span></div></TD>', find)
        if match:
            print_status("Hash cracked: %s" % match.group().split('hervorheb2>')[1][:-18])
            sys.exit()
        else:
            print_warning("Searching with md5decrypt.net ...")
            html = urlopen("http://md5decrypt.net/Api/api.php?hash=" + hash + "&hash_type=sha1&email=" + MD5DECRYPT_EMAIL + "&code=" + MD5DECRYPT_CODE)
            find = html.read()
            if len(find) > 0:
                print_status("Hash cracked: %s" % find)
                sys.exit()
            else:
                print_warning("Searching with md5hashing.net ...")
                html = urlopen("https://md5hashing.net/hash/sha1/" + hash)
                find = html.read()
                match = search(r'<span id="decodedValue">[^<]*</span>', find)
                if match:
                    print("Hash cracked: %s" % match)  # % match.group().split('hervorheb2>')[1][:-18])
                    sys.exit()
                else:
                    import cfscrape
                    import requests
                    import StringIO
                    from PIL import Image
                    from pyquery import PyQuery
                    print_warning("Searching with https://hashkiller.co.uk/sha1-decrypter.aspx ...")
                    scraper = cfscrape.create_scraper()
                    response = scraper.get('https://www.hashkiller.co.uk/sha1-decrypter.aspx')
                    # Save headers and cookies, to be used in next request
                    session = requests.session()
                    session.headers = response.headers
                    session.cookies = response.cookies
                    query = PyQuery(response.content)
                    image_path = query("#content1_imgCaptcha").attr("src")
                    image_content = scraper.get('https://www.hashkiller.co.uk' + image_path).content
                    # Trying to decaptcha image
                    captcha_image = Image.open(StringIO.StringIO(image_content))
                    captcha_image.show()
                    while True:
                        captcha = raw_input(("[") + (Colors.YELLOW) + (Colors.BOLD) + ("!") + (Colors.ENDC) + (
                        "] ") + "Input captcha: ")
                        if len(captcha) != 6:
                            print_error("You must input the correct captcha!")
                            continue
                        else:
                            break
                    scraper = cfscrape.create_scraper(sess=scraper)
                    response = scraper.post('https://www.hashkiller.co.uk/sha1-decrypter.aspx', data={
                        'ctl00$ScriptMan1': 'ctl00$content1$updDecrypt|ctl00$content1$btnSubmit',
                        'ctl00$content1$txtInput': hash,
                        'ctl00$content1$txtCaptcha': captcha,
                        '__EVENTTARGET': '',
                        '__EVENTARGUMENT': '',
                        '__VIEWSTATE': query("#__VIEWSTATE").attr("value"),
                        '__EVENTVALIDATION': query("#__EVENTVALIDATION").attr("value"),
                        '__ASYNCPOST': 'true',
                        'ctl00$content1$btnSubmit': 'Submit',
                        query('#content1_pnlStatus input').attr('name'): query('#content1_pnlStatus input').attr(
                            'value')
                    })
                    response = PyQuery(response.content)
                    status = response('#content1_lblStatus').text()
                    result = response('#content1_lblResults .text-green').text()
                    if 'Failed' in status:
                        print_error("Sorry this hash is not present in our database.")
                        sys.exit()
                    elif 'CAPTCHA' in status:
                        print_error("The CAPTCHA code you specified is wrong!")
                    else:
                        print_status("Hash cracked: %s" % result)
                        sys.exit()

    def sha256(self, hash):
        print_status("Hash function: " + (Colors.YELLOW) + (Colors.BOLD) + "SHA-256" + (Colors.ENDC))
        print_warning("Searching with md5decrypt.net ...")
        html = urlopen("http://md5decrypt.net/Api/api.php?hash=" + hash + "&hash_type=sha256&email=" + MD5DECRYPT_EMAIL + "&code=" + MD5DECRYPT_CODE)
        find = html.read()
        if len(find) > 0:
            print_status("Hash cracked: %s" % find)
            sys.exit()
        else:
            print_warning("Searching with md5hashing.net ...")
            html = urlopen("https://md5hashing.net/hash/sha256/" + hash)
            find = html.read()
            match = search(r'<span id="decodedValue">[^<]*</span>', find)
            if match:
                print("Hash cracked: %s" % match)  # % match.group().split('hervorheb2>')[1][:-18])
                sys.exit()
            else:
                print_error("Sorry this hash is not present in our database.")
                sys.exit()

    def sha384(self, hash):
        print_status("Hash function: " + (Colors.YELLOW) + (Colors.BOLD) + "SHA-384" + (Colors.ENDC))
        print_warning("Searching with md5decrypt.net ...")
        html = urlopen(
            "http://md5decrypt.net/Api/api.php?hash=" + hash + "&hash_type=sha384&email=" + MD5DECRYPT_EMAIL + "&code=" + MD5DECRYPT_CODE)
        find = html.read()
        if len(find) > 0:
            print_status("Hash cracked: %s" % find)
            sys.exit()
        else:
            print_warning("Searching with md5hashing.net ...")

    def sha512(self, hash):
        print_status("Hash function: " + (Colors.YELLOW) + (Colors.BOLD) + "SHA-512" + (Colors.ENDC))
        print_warning("Searching with md5decrypt.net ...")
        html = urlopen(
            "http://md5decrypt.net/Api/api.php?hash=" + hash + "&hash_type=sha512&email=" + MD5DECRYPT_EMAIL + "&code=" + MD5DECRYPT_CODE)
        find = html.read()
        if len(find) > 0:
            print_status("Hash cracked: %s" % find)
            sys.exit()
        else:
            print_warning("Searching with md5hashing.net ...")

    def rmd160(self, hash):
        print_status("Hash function: " + (Colors.YELLOW) + (Colors.BOLD) + "RIPEMD-160" + (Colors.ENDC))
        print_warning("Searching with md5hashing.net ...")

    def lm(self, hash):
        print_status("Hash function: " + (Colors.YELLOW) + (Colors.BOLD) + "LM" + (Colors.ENDC))
        print_warning("Searching with http://hashcrack.com/ ...")
        data = urlencode({"auth": "8272hgt", "hash": hash, "string": "", "Submit": "Submit"})
        html = urlopen("http://hashcrack.com/index.php", data)
        find = html.read()
        match = search(r'<span class=hervorheb2>[^<]*</span></div></TD>', find)
        if match:
            print_status("Hash cracked: %s" % match.group().split('hervorheb2>')[1][:-18])
            sys.exit()
        else:
            print_error("Sorry this hash is not present in our database.")
            sys.exit()

    def ntlm(self, hash):
        print_status("Hash function: " + (Colors.YELLOW) + (Colors.BOLD) + "NTLM" + (Colors.ENDC))
        print_warning("Searching with md5decrypt.net ...")
        html = urlopen(
            "http://md5decrypt.net/Api/api.php?hash=" + hash + "&hash_type=ntlm&email=" + MD5DECRYPT_EMAIL + "&code=" + MD5DECRYPT_CODE)
        find = html.read()
        if len(find) > 0:
            print_status("Hash cracked: %s" % find)
            sys.exit()
        else:
            print_warning("Searching with http://hashcrack.com/ ...")
            data = urlencode({"auth": "8272hgt", "hash": hash, "string": "", "Submit": "Submit"})
            html = urlopen("http://hashcrack.com/index.php", data)
            find = html.read()
            match = search(r'<span class=hervorheb2>[^<]*</span></div></TD>', find)
            if match:
                print_status("Hash cracked: %s" % match.group().split('hervorheb2>')[1][:-18])
                sys.exit()
            else:
                import cfscrape
                import requests
                import StringIO
                from PIL import Image
                from pyquery import PyQuery
                print_warning("Searching with https://hashkiller.co.uk/ntlm-decrypter.aspx ...")
                scraper = cfscrape.create_scraper()
                response = scraper.get('https://www.hashkiller.co.uk/ntlm-decrypter.aspx')
                # Save headers and cookies, to be used in next request
                session = requests.session()
                session.headers = response.headers
                session.cookies = response.cookies
                query = PyQuery(response.content)
                image_path = query("#content1_imgCaptcha").attr("src")
                image_content = scraper.get('https://www.hashkiller.co.uk' + image_path).content
                # Trying to decaptcha image
                captcha_image = Image.open(StringIO.StringIO(image_content))
                captcha_image.show()
                while True:
                    captcha = raw_input(("[") + (Colors.YELLOW) + (Colors.BOLD) + ("!") + (Colors.ENDC) + ("] ") +"Input captcha: ")
                    if len(captcha) != 6:
                        print_error("You must input the correct captcha!")
                        continue
                    else:
                        break
                scraper = cfscrape.create_scraper(sess=scraper)
                response = scraper.post('https://www.hashkiller.co.uk/ntlm-decrypter.aspx', data={
                    'ctl00$ScriptMan1': 'ctl00$content1$updDecrypt|ctl00$content1$btnSubmit',
                    'ctl00$content1$txtInput': hash,
                    'ctl00$content1$txtCaptcha': captcha,
                    '__EVENTTARGET': '',
                    '__EVENTARGUMENT': '',
                    '__VIEWSTATE': query("#__VIEWSTATE").attr("value"),
                    '__EVENTVALIDATION': query("#__EVENTVALIDATION").attr("value"),
                    '__ASYNCPOST': 'true',
                    'ctl00$content1$btnSubmit': 'Submit',
                    query('#content1_pnlStatus input').attr('name'): query('#content1_pnlStatus input').attr('value')
                })
                response = PyQuery(response.content)
                status = response('#content1_lblStatus').text()
                result = response('#content1_lblResults .text-green').text()
                if 'Failed' in status:
                    print_error("Sorry this hash is not present in our database.")
                    sys.exit()
                elif 'CAPTCHA' in status:
                    print_error("The CAPTCHA code you specified is wrong!")
                else:
                    print_status("Hash cracked: %s" % result)
                    sys.exit()

    def mysql(self, hash):
        print_status("Hash function: " + (Colors.YELLOW) + (Colors.BOLD) + "MYSQL" + (Colors.ENDC))
        print_warning("Searching with http://hashcrack.com/ ...")
        data = urlencode({"auth": "8272hgt", "hash": hash, "string": "", "Submit": "Submit"})
        html = urlopen("http://hashcrack.com/index.php", data)
        find = html.read()
        match = search(r'<span class=hervorheb2>[^<]*</span></div></TD>', find)
        if match:
            print_status("Hash cracked: %s" % match.group().split('hervorheb2>')[1][:-18])
            sys.exit()
        else:
            print_error("Sorry this hash is not present in our database.")
            sys.exit()

    def cisco(self, hash):
        print_status("Hash function: " + (Colors.YELLOW) + (Colors.BOLD) + "CISCO" + (Colors.ENDC))
        print_warning("Searching with http://password-decrypt.com/ ...")
        data = urlencode({"submit": "Submit", "cisco_password": hash, "submit": "Submit"})
        html = urlopen("http://password-decrypt.com/cisco.cgi", data)
        find = html.read()
        match = search(r'Decrypted Password:&nbsp;<B>[^<]*</B> </p>', find)
        if match:
            print_status("Hash cracked: %s" % match.group().split('B>')[1][:-2])
            sys.exit()
        else:
            print_warning("Searching with https://www.m00nie.com/type-7-password-tool/ ...")
            data = urlencode({"w": hash, "x": "decrypt"})
            html = urlopen("https://m00nie.com/shares/type7.pl", data)
            find = html.read()
            match = search('<br>Output text is (.*)<br>', find)
            if match:
                print_status("Hash cracked: %s" % match.group(1))
                sys.exit()
            else:
                print_error("Sorry this hash is not present in our database.")
                sys.exit()

    def juniper(self, hash):
        print_status("Hash function: " + (Colors.YELLOW) + (Colors.BOLD) + "JUNIPER" + (Colors.ENDC))
        print_warning("Searching with http://password-decrypt.com/ ...")
        data = urlencode({"submit": "Submit", "juniper_password": hash, "submit": "Submit"})
        html = urlopen("http://password-decrypt.com/juniper.cgi", data)
        find = html.read()
        match = search(r'Decrypted Password:&nbsp;<B>[^<]*</B> </p>', find)
        if match:
            print_status("Hash cracked: %s" % match.group().split('B>')[1][:-2])
            sys.exit()
        else:
            print_warning("Searching with https://www.m00nie.com/juniper-type-9-password-tool/ ...")
            data = urlencode({"w": hash, "x": "decrypt"})
            html = urlopen("https://m00nie.com/shares/type9.pl", data)
            find = html.read()
            match = search('<br>Output text is (.*)<br>', find)
            if match:
                print_status("Hash cracked: %s" % match.group(1))
                sys.exit()
            else:
                print_error("Sorry this hash is not present in our database.")
                sys.exit()

    def gost(self, hash):
        print_status("Hash function: " + (Colors.YELLOW) + (Colors.BOLD) + "GOST" + (Colors.ENDC))
        print_warning("Searching with md5hashing.net ...")

    def whirlpool(self, hash):
        print_status("Hash function: " + (Colors.YELLOW) + (Colors.BOLD) + "WHIRLPOOL" + (Colors.ENDC))
        print_warning("Searching with md5hashing.net ...")

    def ldap_md5(self, hash):
        print_status("Hash function: " + (Colors.YELLOW) + (Colors.BOLD) + "LDAP-MD5" + (Colors.ENDC))
        print_warning("Searching with md5hashing.net ...")

    def ldap_sha1(self, hash):
        print_status("Hash function: " + (Colors.YELLOW) + (Colors.BOLD) + "LDAP-SHA1" + (Colors.ENDC))
        print_warning("Searching with md5hashing.net ...")


class HashCracker:

    def __init__(self):
        pass

    def show_banner(self):
        print (Colors.PURPLE) + (Colors.BOLD) + ("                 _             ___               _             ")
        print "  /\  /\__ _ ___| |__         / __\ __ __ _  ___| | _____ _ __ "
        print " / /_/ / _` / __| '_ \ _____ / / | '__/ _` |/ __| |/ / _ \ '__|"
        print "/ __  / (_| \__ \ | | |_____/ /__| | | (_| | (__|   <  __/ |   "
        print "\/ /_/ \__,_|___/_| |_|     \____/_|  \__,_|\___|_|\_\___|_|   " + (Colors.ENDC) + (Colors.YELLOW) + (Colors.BOLD) + ("v1.2") + (Colors.ENDC)
        print "                                                 " + (Colors.CYAN) + (Colors.BOLD) + ("@5h4d0wb0y\n") + (Colors.ENDC)

    def validate_args(self):
        parser = argparse.ArgumentParser(description="")
        parser.add_argument("-A","--algorithm", metavar="<algorithm>", dest="algorithm", default=None, help="Choose hash' algorithm between %s" % ALGORITHMS)
        parser.add_argument("-H", "--hash", metavar="<hash>", dest="hash", default=None, help="Specify a hash to crack")
        args = parser.parse_args()

        if not args.hash:
            print_error("Missing --hash argument!")
            sys.exit(-1)
        if not args.algorithm:
            print_error("Missing --algorithm argument!")
            sys.exit(-1)
        if args.algorithm not in ALGORITHMS:
            print_error("Wrong --algorithm argument!")
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
        crack = Cracker()
        if len(args.hash) == 32 and args.algorithm == 'md5':
            crack.md5(args.hash)
        elif len(args.hash) == 40 and args.algorithm == 'sha1':
            crack.sha1(args.hash)
        elif len(args.hash) == 64 and args.algorithm == 'sha256':
            crack.sha256(args.hash)
        elif len(args.hash) == 96 and args.algorithm == 'sha384':
            crack.sha384(args.hash)
        elif len(args.hash) == 128 and args.algorithm == 'sha512':
            crack.sha512(args.hash)
        elif len(args.hash) == 40 and args.algorithm == 'rmd160':
            crack.rmd160(args.hash)
        elif len(args.hash) == 32 and args.algorithm == 'lm':
            crack.lm(args.hash)
        elif len(args.hash) == 32 and args.algorithm == 'ntlm':
            crack.ntlm(args.hash)
        elif (len(args.hash) == 16 or len(args.hash) == 40) and args.algorithm == 'mysql':
            crack.mysql(args.hash)
        elif args.hash.startswith('\$9\$') and args.algorithm == 'juniper':
            crack.juniper(args.hash)
        elif args.algorithm == 'cisco':
            crack.cisco(args.hash)
        elif len(args.hash) == 60 and args.algorithm == 'gost':
            crack.gost(args.hash)
        elif len(args.hash) == 128 and args.algorithm == 'whirlpool':
            crack.whirlpool(args.hash)
        elif args.hash.startswith('{MD5}') and args.algorithm == 'ldap_md5':
            crack.ldap_md5(args.hash)
        elif args.hash.startswith('{SHA}') and args.algorithm == 'ldap_sha1':
            crack.ldap_sha1(args.hash)
        else:
            print_error("This hash is not supported.")


# Main
if __name__ == "__main__":
    a = HashCracker()
    a.show_banner()
    args = a.validate_args()
    a.run(args)
