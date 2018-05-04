#!/usr/bin/python3 -u
# -* encoding: utf-8 *-
import contextlib
import os
import sys
import argparse
import subprocess
from io import TextIOWrapper

from typing import Tuple, Union, Set, List, TextIO, Generator, cast, IO, Optional
from urllib.parse import urlencode

import jwt
import requests
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKeyWithSerialization
from cryptography.x509 import Certificate


@contextlib.contextmanager
def stdout_or_file(path: Optional[str]) -> Generator[Union[TextIOWrapper, TextIO], None, None]:
    if path is None or path == "" or path == "-":
        yield sys.stdout
    else:
        fd = open(path, mode="w")
        yield fd
        fd.close()


def readinput_checkpassword() -> Tuple[str, str]:
    try:
        fd = os.fdopen(3, 'r')
    except OSError as e:
        print("ERROR while opening descriptor 3 (%s)" % str(e))
        sys.exit(2)

    inp = fd.read(512)
    # parse input
    try:
        username, password, _ = inp.split("\x00", 2)
    except ValueError as e:
        print("ERROR Not enough null-terminated inputs")
        sys.exit(2)

    return username, password


def readinput_authext() -> Tuple[str, str]:
    username = sys.stdin.readline().strip()
    password = sys.stdin.readline().strip()
    return username, password


def readinput_groups() -> Tuple[str, List[str]]:
    username = sys.stdin.readline().strip()
    groups = sys.stdin.readline().strip().split(' ')
    return username, groups


def validate(url: str, username: str, password: Optional[str], jwtkeyfile: str, scopes: Set[str],
             validate_ssl: Union[bool, str]=True, require_authnz: bool=True) -> bool:
    if os.path.exists(jwtkeyfile) and os.access(jwtkeyfile, os.R_OK):
        try:
            with open(jwtkeyfile, "rt") as keyfile:
                jwtkey = "".join(keyfile.readlines())
        except IOError as e:
            sys.stderr.write("ERROR Can't read JWT file %s: %s" % (jwtkeyfile, str(e)))
            sys.exit(2)
    else:
        sys.stderr.write("ERROR JWT key file %s does not exist.\n" % jwtkeyfile)
        sys.exit(2)

    # if we get a X509 certificate, convert it to a public key that can then be deserialized by pyjwt
    if jwtkey.startswith("-----BEGIN CERTIFICATE"):
        cert = x509.load_pem_x509_certificate(jwtkey, backend=default_backend())  # type: Certificate
        pk = cert.public_key()  # type: RSAPublicKeyWithSerialization
        jwtkey = pk.public_bytes(encoding=serialization.Encoding.PEM,
                                 format=serialization.PublicFormat.SubjectPublicKeyInfo)

    try:
        resp = requests.post(url, json={"username": username, "password": password}, verify=validate_ssl)
    except requests.exceptions.SSLError as sslerr:
        sys.stderr.write("Unverifiable server certificate or SSL error while connecting to %s: %s\n" %
                         (url, str(sslerr)))
        sys.exit(2)
    except requests.exceptions.ConnectionError as sslerr:
        sys.stderr.write("Connection error while connecting to %s: %s\n" % (url, sslerr))
        sys.exit(2)

    if resp.status_code == 200 and resp.headers["content-type"] == "application/jwt":
        try:
            token = jwt.decode(resp.text, jwtkey, algorithms=["RS256"], leeway=10, audience="net.maurus.authclient")
        except (jwt.ExpiredSignatureError, jwt.InvalidAlgorithmError,
                jwt.InvalidIssuerError, jwt.InvalidTokenError) as e:
            return False

        if ("authenticated" in token and token["authenticated"] or not require_authnz) and \
           ("authorized" in token and token["authorized"] or not require_authnz) and \
           "scopes" in token and isinstance(token["scopes"], list) and scopes.issubset(set(token["scopes"])):
            return True
        else:
            return False
    elif resp.status_code != 200 and resp.headers["content-type"] == "application/json":
        js = resp.json()
        if "error" in js:
            sys.stderr.write("ERROR Server returned: %s %s\n" % (resp.status_code, js["error"]))
            return False
    else:
        sys.stderr.write("ERROR Server returned code %s\n" % resp.status_code)
        return False

    return False


def loadkey(url: str, domain: str=None, jwtkeyfile: str=None, response_format: str="pubkey", check: bool=False,
            validate_ssl: Union[bool, str]=True) -> None:
    if jwtkeyfile and jwtkeyfile != "-":
        if os.path.exists(jwtkeyfile):
            sys.stderr.write("Path %s already exists. Doing nothing.\n" % jwtkeyfile)
            sys.exit(0)

    if domain:
        par = urlencode({"domain": domain})
        if "?" in url:
            url = "%s&%s" % (url, par)
        else:
            url = "%s?%s" % (url, par)

    if "?" in url:
        url = "%s&%s" % (url, "format=%s" % response_format,)
    else:
        url = "%s?%s" % (url, "format=%s" % response_format,)

    try:
        resp = requests.get(url, verify=validate_ssl)
    except requests.exceptions.SSLError as sslerr:
        sys.stderr.write("Unverifiable server certificate or SSL error while connecting to %s: %s\n" %
                         (url, str(sslerr)))
        sys.exit(2)
    except requests.exceptions.ConnectionError as sslerr:
        sys.stderr.write("Connection error while connecting to %s: %s\n" % (url, sslerr))
        sys.exit(2)

    if resp.status_code == 404:
        sys.stderr.write("Server returned 404. Domain probably not initialized for JWT.\n")
        if resp.headers["content-type"] == "application/json":
            if "error" is resp.json():
                sys.stderr.write("With error: %s\n" % resp.json()["error"])
        sys.exit(1)

    if resp.status_code == 200:
        if check:
            sys.stderr.write("Check successful.\n")
        else:
            with stdout_or_file(jwtkeyfile) as out:
                print("\n".join(resp.json()[
                                    "cert" if response_format == "cert" else "public_key_pem"
                                ]), file=cast(IO[str], out))

            if jwtkeyfile != "-":
                sys.stderr.write("Key written to %s\n" % jwtkeyfile)
        sys.exit(0)
    else:
        sys.stderr.write("Server returned status code %s\n" % resp.status_code)

        if resp.headers["content-type"] == "application/json":
            if "error" is resp.json():
                sys.stderr.write("With error: %s\n" % resp.json()["error"])
                sys.exit(3)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="This tool talks to a proprietary API on authserver to check a username "
                    "and password. It can operate in two modes: one is djb checkpassword "
                    "compatible, the other is Apache2 mod_auth_ext compatible. The tool will "
                    "return exitcode 0 if the username and password are correct."
    )

    parser.add_argument("-m", "--mode", dest="mode", default="checkpassword",
                        choices=["checkpassword", "authext", "authextgroup", "init", "check"],
                        help="Tells the program what mode to operate in. 'authext' is compatible with Apache2 "
                             "mod_authnz_ext and 'checkpassword' is compatible with the qmail checkpassword "
                             "interface. 'authextgroup' supports checking groups against scopes as supported by "
                             "mod_authnz_ext. 'init' is used to download the public key from the authentication server "
                             "and write it to stdout (URL must then be the server's getkey endpoint). 'check' behaves "
                             "like 'init' but makes no changes. 'check' and 'init' return error code 0 for success, "
                             "error code 1 if the domain has no key, error code 2 for connection problems and error "
                             "code 3 for everything else.")
    parser.add_argument("-u", "--url", dest="url", required=True,
                        help="The URL of the authserver endpoint to use to check the password. Usually this should "
                             "point to the server's 'checkpassword' REST API, unless mode is 'init' in which case "
                             "it should point to the servers 'getkey' REST API endpoint")
    parser.add_argument("-f", "--format", dest="format", choices=["pubkey", "cert"], default="pubkey",
                        help="Choose the format for the JWT public key, which can be requested as a RSA public key "
                             "('pubkey') or a self-signed X509 certiifcate ('cert')")
    parser.add_argument("--no-ssl-validate", dest="validate_ssl", action="store_false", default=True,
                        help="Skip validation of the server's SSL certificate.")
    parser.add_argument("--ca-file", dest="ca_file", default=None,
                        help="Set a CA bundle to validate the server's SSL certificate against")
    parser.add_argument("-s", "--scope", dest="scopes", action="append", default=[],
                        help="One or more required scopes assigned to the user beyond being authenticated correctly.")
    parser.add_argument("--jwtkey", dest="jwtkey", required=True,
                        help="Path to a PEM encoded public key to verify the JWT claims and scopes returned by the "
                             "server (i.e. the server's public key). Mode 'init' writes the key to this file. Use '-' "
                             "to write the key to stdout in 'init' mode.")
    parser.add_argument("--domain", dest="domain", default=None,
                        help="Specify an alternate domain to check for an existing JWT signing public key, otherwise "
                             "the server will use the domain from '--url'.")
    parser.add_argument("prog", nargs="*", help="The program to run as defined by the checkpassword interface "
                                                "(optional).")

    _args = parser.parse_args()

    if _args.mode in ["init", "check"]:
        loadkey(_args.url, domain=_args.domain, check=(_args.mode == "check"), response_format=_args.format,
                jwtkeyfile=_args.jwtkey, validate_ssl=_args.ca_file if _args.ca_file else _args.validate_ssl)
        return
    elif _args.mode == "checkpassword":
        username, password = readinput_checkpassword()  # type: str, Optional[str]
    elif _args.mode == "authext":
        username, password = readinput_authext()
    elif _args.mode == "authextgroup":
        username, groups = readinput_groups()
        password = None
    else:
        print("Unknown mode")
        sys.exit(1)

    if validate(_args.url, username, password, jwtkeyfile=_args.jwtkey, scopes=set(_args.scopes),
                validate_ssl=_args.ca_file if _args.ca_file else _args.validate_ssl,
                require_authnz=not _args.mode == "authextgroup"):
        if _args.mode == "checkpassword":
            # execute prog
            subprocess.call(_args.prog)
        sys.exit(0)
    else:
        sys.exit(1)


if __name__ == "__main__":
    main()
