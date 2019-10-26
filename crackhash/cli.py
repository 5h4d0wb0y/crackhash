# -*- coding: utf-8 -*-

"""Console script for crackhash."""
import sys
import click

from crackhash import __author__, __version__
from crackhash.core import *

ALGORITHMS = [
    "md5",
    "sha1",
    "sha256",
    "sha384",
    "sha512",
    "rmd128",
    "rmd160",
    "rmd256",
    "rmd320",
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


def show_banner():
    print((Colors.PURPLE) + (Colors.BOLD) +
          "   ___               _    _               _      ")
    print(r"  / __\ __ __ _  ___| | _| |__   __ _ ___| |__   ")
    print(r" / / | '__/ _` |/ __| |/ / '_ \ / _` / __| '_ \  ")
    print(r"/ /__| | | (_| | (__|   <| | | | (_| \__ \ | | | ")
    print(r"\____/_|  \__,_|\___|_|\_\_| |_|\__,_|___/_| |_| \n" + (Colors.ENDC))
    print("        --[    Version: " +
          (Colors.YELLOW) +
          (Colors.BOLD) +
          (__version__) +
          (Colors.ENDC) +
          "      ]--")
    print("        --[     Author: " +
          (Colors.CYAN) +
          (Colors.BOLD) +
          (__author__) +
          (Colors.ENDC) +
          "  ]--\n\n")


def prompt_proxy(ctx, param, use_proxy):
    if use_proxy:
        host = ctx.params.get('proxy_host')
        if not host:
            host = click.prompt('Proxy host', default='localhost')

        port = ctx.params.get('proxy_port')
        if not port:
            port = click.prompt('Proxy port', default=9050)

        user = ctx.params.get('proxy_user')
        if not user:
            user = click.prompt('Proxy user', default=None)

        pwd = ctx.params.get('proxy_pass')
        if not pwd:
            pwd = click.prompt('Proxy user\'s password', default=None)
        return (host, port, user, pwd)


@click.command()
@click.option('--use-proxy/--no-proxy', is_flag=True, default=False,
              help='Set a proxy to use', callback=prompt_proxy)
@click.option('--proxy-host', is_eager=True, help='Specify the proxy host')
@click.option('--proxy-port', is_eager=True,
              type=int, help='Specify the proxy port')
@click.option('--proxy-user', is_eager=True, help='Specify a proxy user')
@click.option('--proxy-pass', is_eager=True,
              help='Specify a proxy user\'s password')
@click.option('-a', '--algo', type=click.Choice(ALGORITHMS),
              help='Specify hash\' algorithm')
@click.option('-h', '--hash', help='Specify a hash to crack')
@click.option('-f', '--file', type=click.Path(exists=True),
              help='Specify file containing hashes, formatted this way: hashtype:hashvalue')
def main(use_proxy, proxy_host, proxy_port,
         proxy_user, proxy_pass, algo, hash, file):
    """Crackhash is a tool that try to crack different types of hashes using free online services."""
    if (hash == False) and (file == False):
        print_error("Have to set a 'hash' or 'file' argument!")
        return 0
    if hash and file:
        print_error(
            "Can't set both options at once. Choose between 'hash' or 'file' argument!")
        return 0

    sc = Crackhash()

    if hash and (algo is None):
        algo = sc.get_algo(hash)
        print_info(
            'The hash you are looking for probably is %s%s%s' %
            (Colors.BOLD, algo.upper(), Colors.ENDC))
        if not sc.validate_hash(hash, algo):
            print_error('The hash is not supported')
            return 0

    if use_proxy:
        proxy = {
            'host': proxy_host,
            'port': proxy_port,
            'user': proxy_user,
            'pass': proxy_pass,
        }
        sc.start(proxy=proxy)
    else:
        sc.start()

    if file:
        sc.batch(file)
    else:
        sc.check(hash, algo)

    sc.close()
    return 0


if __name__ == "__main__":
    show_banner()
    sys.exit(main())  # pragma: no cover
