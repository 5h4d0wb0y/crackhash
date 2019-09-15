#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Tests for `crackhash` package."""

import base64
import unittest
from click.testing import CliRunner

from crackhash import scraper
from crackhash import browser
from crackhash import cli

# Hashes of common word 'password'
md5 = "5f4dcc3b5aa765d61d8327deb882cf99"
sha1 = "5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8"
sha256 = "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8"
sha384 = "a8b64babd0aca91a59bdbb7761b421d4f2bb38280d3a75ba0f21f2bebc45583d446c598660c94ce680c47d19c30783a7"
sha512 = "b109f3bbbc244eb82441917ed06d618b9008dd09b3befd1b5e07394c706a8bb980b1d7785e5976ec049b46df5f1326af5a2ea6d103fd07c95385ffab0cacbc86"
ripemd128 = "c9c6d316d6dc4d952a789fd4b8858ed7"
ripemd160 = "2c08e8f5884750a7b99f6f2f342fc638db25ff31"
ripemd256 = "f94cf96c79103c3ccad10d308c02a1db73b986e2c48962e96ecd305e0b80ef1b"
ripemd320 = "c571d82e535de67ff5f87e417b3d53125f2d83ed7598b89d74483e6c0dfe8d86e88b380249fc8fb4"
mysql = "*2470C0C06DEE42FD1618BB99005ADCA2EC9D1E19"
lm = "E52CAC67419A9A224A3B108F3FA6CB6D"
ntlm = "8846F7EAEE8FB117AD06BDD830B7586C"
whirlpool = "74dfc2b27acfa364da55f93a5caee29ccad3557247eda238831b3e9bd931b01d77fe994e4f12b9d4cfa92a124461d2065197d8cf7f33fc88566da2db2a4d6eae"
gost = "db4d9992897eda89b50f1d3208db607902da7e79c6f3bc6e6933cc5919068564"
cisco = "021605481811003348"
juniper = "$9$QHbgz/tu0IcrvBIwgJDmPBIEhSe"
ldap_md5 = "{MD5}NWY0ZGNjM2I1YWE3NjVkNjFkODMyN2RlYjg4MmNmOTkK"
ldap_sha1 = "{SHA}NWJhYTYxZTRjOWI5M2YzZjA2ODIyNTBiNmNmODMzMWI3ZWU2OGZkOAo="


class TestCrackhash(unittest.TestCase):
    """Tests for `crackhash` package."""

    def setUp(self):
        """Start browser."""
        self.browser = browser.Browser()
        self.browser.start(headless=False)

    def test_command_line_interface(self):
        """Test the CLI."""
        runner = CliRunner()
        help_result = runner.invoke(cli.main, ['--help'])
        assert help_result.exit_code == 0
        assert '--help                          Show this message and exit.' in help_result.output

    #
    # MD5 tests
    #
    def test_md5_myaddr(self):
        """Test MDA5 hash with myaddr."""
        res = scraper.myaddr(self.browser, md5, 'md5')
        assert res

    def test_md5_nitrxgen(self):
        """Test MDA5 hash with nitrxgen."""
        res = scraper.nitrxgen(self.browser, md5, 'md5')
        assert res

    def test_md5_cmd5(self):
        """Test MDA5 hash with cmd5."""
        res = scraper.cmd5(self.browser, md5, 'md5')
        assert res

    def test_md5_hashcrack(self):
        """Test MDA5 hash with hashcrack."""
        res = scraper.hashcrack(self.browser, md5, 'md5')
        assert res

    def test_md5_md5decrypt(self):
        """Test MDA5 hash with md5decrypt."""
        res = scraper.md5decrypt(self.browser, md5, 'md5')
        assert res

    def test_md5_hashtoolkit(self):
        """Test MDA5 hash with hashtoolkit."""
        res = scraper.hashtoolkit(self.browser, md5, 'md5')
        assert res

    def test_md5_md5hashing(self):
        """Test MDA5 hash with md5hashing."""
        res = scraper.md5hashing(self.browser, md5, 'md5')
        assert res

    def test_md5_hashkiller(self):
        """Test MDA5 hash with hashkiller."""
        res = scraper.hashkiller(self.browser, md5, 'md5')
        assert res

    #
    # SHA1 Tests
    #
    def test_sha1_md5decrypt(self):
        """Test SHA1 hash with md5decrypt."""
        res = scraper.md5decrypt(self.browser, sha1, 'sha1')
        assert res

    def test_sha1_cmd5(self):
        """Test SHA1 hash with cmd5."""
        res = scraper.cmd5(self.browser, sha1, 'sha1')
        assert res

    #def test_sha1_hashcrack(self):
    #    """Test SHA1 hash with hashcrack."""
    #    res = scraper.hashcrack(self.browser, sha1, 'sha1')
    #    assert res

    def test_sha1_md5hashing(self):
        """Test SHA1 hash with md5hashing."""
        res = scraper.md5hashing(self.browser, sha1, 'sha1')
        assert res

    def test_sha1_hashkiller(self):
        """Test SHA1 hash with hashkiller."""
        res = scraper.hashkiller(self.browser, sha1, 'sha1')
        assert res

    #
    # SHA256 Tests
    #
    def test_sha256_md5decrypt(self):
        """Test SHA256 hash with md5decrypt."""
        res = scraper.md5decrypt(self.browser, sha256, 'sha256')
        assert res

    def test_sha256_cmd5(self):
        """Test SHA256 hash with cmd5."""
        res = scraper.cmd5(self.browser, sha256, 'sha256')
        assert res

    def test_sha256_md5hashing(self):
        """Test SHA256 hash with md5hashing."""
        res = scraper.md5hashing(self.browser, sha256, 'sha256')
        assert res

    #
    # SHA384 Tests
    #
    def test_sha384_md5decrypt(self):
        """Test SHA384 hash with md5decrypt."""
        res = scraper.md5decrypt(self.browser, sha384, 'sha384')
        assert res

    def test_sha384_cmd5(self):
        """Test SHA384 hash with cmd5."""
        res = scraper.cmd5(self.browser, sha384, 'sha384')
        assert res

    def test_sha384_md5hashing(self):
        """Test SHA384 hash with md5hashing."""
        res = scraper.md5hashing(self.browser, sha384, 'sha384')
        assert res

    #
    # SHA512 Tests
    #
    def test_sha512_md5decrypt(self):
        """Test SHA512 hash with md5decrypt."""
        res = scraper.md5decrypt(self.browser, sha512, 'sha512')
        assert res

    def test_sha512_md5hashing(self):
        """Test SHA512 hash with md5hashing."""
        res = scraper.md5hashing(self.browser, sha512, 'sha512')
        assert res

    #
    # RIPEMD128 Tests
    #
    def test_ripemd128_md5hashing(self):
        """Test RIPEMD128 hash with md5hashing."""
        res = scraper.md5hashing(self.browser, ripemd128, 'rmd128')
        assert res

    #
    # RIPEMD160 Tests
    #
    def test_ripemd160_md5hashing(self):
        """Test RIPEMD160 hash with md5hashing."""
        res = scraper.md5hashing(self.browser, ripemd160, 'rmd160')
        assert res

    #
    # RIPEMD256 Tests
    #
    def test_ripemd256_md5hashing(self):
        """Test RIPEMD256 hash with md5hashing."""
        res = scraper.md5hashing(self.browser, ripemd256, 'rmd256')
        assert res

    #
    # RIPEMD320 Tests
    #
    def test_ripemd320_md5hashing(self):
        """Test RIPEMD320 hash with md5hashing."""
        res = scraper.md5hashing(self.browser, ripemd320, 'rmd320')
        assert res

    #
    # LM Tests
    #
    def test_lm_it64(self):
        """Test LM hash with it64."""
        res = scraper.it64(self.browser, lm, 'lm')
        assert res
    #def test_lm_hashcrack(self):
    #    """Test LM hash with hashcrack."""
    #    res = scraper.hashcrack(self.browser, lm, 'lm')
    #    assert res

    #
    # NTLM Tests
    #
    def test_ntlm_md5decrypt(self):
        """Test NTLM hash with md5decrypt."""
        res = scraper.md5decrypt(self.browser, ntlm, 'ntlm')
        assert res

    def test_ntlm_cmd5(self):
        """Test NTLM hash with cmd5."""
        res = scraper.cmd5(self.browser, ntlm, 'ntlm')
        assert res

    #def test_ntlm_hashcrack(self):
    #    """Test NTLM hash with hashcrack."""
    #    res = scraper.hashcrack(self.browser, ntlm, 'ntlm')
    #    assert res

    def test_ntlm_hashkiller(self):
        """Test NTLM hash with hashkiller."""
        res = scraper.hashkiller(self.browser, ntlm, 'ntlm')
        assert res

    #
    # MYSQL Tests
    #
    def test_mysql_cmd5(self):
        """Test MYSQL hash with cmd5."""
        res = scraper.cmd5(self.browser, mysql, 'mysql')
        assert res

    def test_mysql_hashkiller(self):
        """Test MYSQL hash with hashkiller."""
        res = scraper.hashkiller(self.browser, mysql, 'mysql')
        assert res

    #def test_mysql_hashcrack(self):
    #    """Test MYSQL hash with hashcrack."""
    #    res = scraper.hashcrack(self.browser, mysql, 'mysql')
    #    assert res

    #
    # CISCO Tests
    #
    def test_cisco_passworddecrypt(self):
        """Test CISCO hash with passworddecrypt."""
        res = scraper.passworddecrypt(self.browser, cisco, 'cisco')
        assert res

    def test_cisco_m00nie(self):
        """Test CISCO hash with m00nie."""
        res = scraper.m00nie(self.browser, cisco, 'cisco')
        assert res

    def test_cisco_firewallruletest(self):
        """Test CISCO hash with firewallruletest."""
        res = scraper.firewallruletest(self.browser, cisco, 'cisco')
        assert res

    def test_cisco_ifm(self):
        """Test CISCO hash with ifm."""
        res = scraper.ifm(self.browser, cisco, 'cisco')
        assert res

    def test_cisco_ibeast(self):
        """Test CISCO hash with ibeast."""
        res = scraper.ibeast(self.browser, cisco, 'cisco')
        assert res

    #
    # JUNIPER Tests
    #
    def test_juniper_passworddecrypt(self):
        """Test JUNIPER hash with passworddecrypt."""
        res = scraper.passworddecrypt(self.browser, juniper, 'juniper')
        assert res

    def test_juniper_m00nie(self):
        """Test JUNIPER hash with m00nie."""
        res = scraper.m00nie(self.browser, juniper, 'juniper')
        assert res

    #
    # GOST Tests
    #
    def test_gost_md5hashing(self):
        """Test GOST hash with md5hashing."""
        res = scraper.md5hashing(self.browser, gost, 'gost')
        assert res

    #
    # WHIRLPOOL Tests
    #
    def test_whirlpool_md5hashing(self):
        """Test WHIRLPOOL hash with md5hashing."""
        res = scraper.md5hashing(self.browser, whirlpool, 'whirlpool')
        assert res

    #
    # LDAP_MD5 Tests
    #

    def test_ldap_md5_myaddr(self):
        """Test LDAP MD5 hash with myaddr."""
        hash = str(base64.b64decode(ldap_md5[5:])).replace("b'", "").replace("\\n'", "")
        res = scraper.myaddr(self.browser, hash, 'md5')
        assert res

    def test_ldap_md5_nitrxgen(self):
        """Test LDAP MD5 hash with nitrxgen."""
        hash = str(base64.b64decode(ldap_md5[5:])).replace("b'", "").replace("\\n'", "")
        res = scraper.nitrxgen(self.browser, hash, 'md5')
        assert res

    def test_ldap_md5_hashcrack(self):
        """Test LDAP MD5 hash with hashcrack."""
        hash = str(base64.b64decode(ldap_md5[5:])).replace("b'", "").replace("\\n'", "")
        res = scraper.hashcrack(self.browser, hash, 'md5')
        assert res

    def test_ldap_md5_md5decrypt(self):
        """Test LDAP MD5 hash with md5decrypt."""
        hash = str(base64.b64decode(ldap_md5[5:])).replace("b'", "").replace("\\n'", "")
        res = scraper.md5decrypt(self.browser, hash, 'md5')
        assert res

    def test_ldap_md5_hashtoolkit(self):
        """Test LDAP MD5 hash with hashtoolkit."""
        hash = str(base64.b64decode(ldap_md5[5:])).replace("b'", "").replace("\\n'", "")
        res = scraper.hashtoolkit(self.browser, hash, 'md5')
        assert res

    def test_ldap_md5_md5hashing(self):
        """Test LDAP MD5 hash with md5hashing."""
        hash = str(base64.b64decode(ldap_md5[5:])).replace("b'", "").replace("\\n'", "")
        res = scraper.md5hashing(self.browser, hash, 'md5')
        assert res

    def test_ldap_md5_hashkiller(self):
        """Test LDAP MD5 hash with hashkiller."""
        hash = str(base64.b64decode(ldap_md5[5:])).replace("b'", "").replace("\\n'", "")
        res = scraper.hashkiller(self.browser, hash, 'md5')
        assert res

    #
    # LDAP_SHA1 Tests
    #
    def test_ldap_sha1_md5decrypt(self):
        """Test LDAP SHA1 hash with md5decrypt."""
        hash = str(base64.b64decode(ldap_sha1[5:])).replace("b'", "").replace("\\n'", "")
        res = scraper.md5decrypt(self.browser, hash, 'sha1')
        assert res

    #def test_ldap_sha1_hashcrack(self):
    #    """Test LDAP SHA1 hash with hashcrack."""
    #    hash = str(base64.b64decode(ldap_sha1[5:])).replace("b'", "").replace("\\n'", "")
    #    res = scraper.hashcrack(self.browser, hash, 'sha1')
    #    assert res

    def test_ldap_sha1_md5hashing(self):
        """Test LDAP SHA1 hash with md5hashing."""
        hash = str(base64.b64decode(ldap_sha1[5:])).replace("b'", "").replace("\\n'", "")
        res = scraper.md5hashing(self.browser, hash, 'sha1')
        assert res

    def test_ldap_sha1_hashkiller(self):
        """Test LDAP SHA1 hash with hashkiller."""
        hash = str(base64.b64decode(ldap_sha1[5:])).replace("b'", "").replace("\\n'", "")
        res = scraper.hashkiller(self.browser, hash, 'sha1')
        assert res

    def tearDown(self):
        """Stop browser."""
        self.browser.stop()