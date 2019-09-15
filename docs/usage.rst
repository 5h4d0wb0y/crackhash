=====
Usage
=====

.. code-block:: console

  usage: crackhash [OPTIONS]

    Crackhash is a tool that try to crack different types of hashes using free
    online services.

  Options:
    --use-proxy / --no-proxy        Set a proxy to use
    --proxy-host TEXT               Specify the proxy host
    --proxy-port INTEGER            Specify the proxy port
    --proxy-user TEXT               Specify a proxy user
    --proxy-pass TEXT               Specify a proxy user's password
    -a, --algo [md5|sha1|sha256|sha384|sha512|rmd128|rmd160|rmd256|rmd320|lm|ntlm|mysql|cisco|juniper|gost|whirlpool|ldap_md5|ldap_sha1]
                                    Specify hash' algorithm
    -h, --hash TEXT                 Specify a hash to crack
    -f, --file FILENAME             Specify file containing hashes, formatted
                                    this way: hashtype:hashvalue
    --help                          Show this message and exit.


If the `algo` parameter is not specified, crackhash is able to detect the hash and try to crack it:

.. code-block:: console

  $ crackhash -h 098f6bcd4621d373cade4e832627b4f6


Otherwise try to crack it by specifying the `algo` parameter:

.. code-block:: console

  $ crackhash -a md5 -h 098f6bcd4621d373cade4e832627b4f6


Try to crack it using a proxy:

.. code-block:: console

  $ crackhash --use-proxy --proxy-host 127.0.0.1 --proxy-port 9050 -h 098f6bcd4621d373cade4e832627b4f6


Crackhash is able to parse a file containing hashes and try to crack them as fast as possible:

.. code-block:: console

  $ cat ~/crackhash-hashes.txt
  md5:5f4dcc3b5aa765d61d8327deb882cf99
  sha1:5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8
  sha256:5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8
  sha384:a8b64babd0aca91a59bdbb7761b421d4f2bb38280d3a75ba0f21f2bebc45583d446c598660c94ce680c47d19c30783a7
  sha512:b109f3bbbc244eb82441917ed06d618b9008dd09b3befd1b5e07394c706a8bb980b1d7785e5976ec049b46df5f1326af5a2ea6d103fd07c95385ffab0cacbc86
  ripemd128:c9c6d316d6dc4d952a789fd4b8858ed7
  ripemd160:2c08e8f5884750a7b99f6f2f342fc638db25ff31
  ripemd256:f94cf96c79103c3ccad10d308c02a1db73b986e2c48962e96ecd305e0b80ef1b
  ripemd320:c571d82e535de67ff5f87e417b3d53125f2d83ed7598b89d74483e6c0dfe8d86e88b380249fc8fb4
  mysql:*2470C0C06DEE42FD1618BB99005ADCA2EC9D1E19
  lm:E52CAC67419A9A224A3B108F3FA6CB6D
  ntlm:8846F7EAEE8FB117AD06BDD830B7586C
  whirlpool:74dfc2b27acfa364da55f93a5caee29ccad3557247eda238831b3e9bd931b01d77fe994e4f12b9d4cfa92a124461d2065197d8cf7f33fc88566da2db2a4d6eae
  gost:db4d9992897eda89b50f1d3208db607902da7e79c6f3bc6e6933cc5919068564
  cisco:021605481811003348
  juniper:$9$QHbgz/tu0IcrvBIwgJDmPBIEhSe
  ldap_md5:{MD5}NWY0ZGNjM2I1YWE3NjVkNjFkODMyN2RlYjg4MmNmOTkK
  ldap_sha1:{SHA}NWJhYTYxZTRjOWI5M2YzZjA2ODIyNTBiNmNmODMzMWI3ZWU2OGZkOAo=
  $ crackhash -f ~/crackhash-hashes.txt
