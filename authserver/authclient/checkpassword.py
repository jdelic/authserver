#!/usr/bin/python3 -u
# -* encoding: utf-8 *-
import os
import sys
import argparse
import subprocess

from typing import Tuple, Union, Set

import jwt
import requests


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


def validate(url: str, username: str, password: str, jwtkey: str, scopes: Set[str],
             validate_ssl: Union[bool, str]=True) -> bool:
    resp = requests.post(url, json={"username": username, "password": password}, verify=validate_ssl)

    if resp.status_code == 200 and resp.headers["content-type"] == "application/jwt":
        try:
            token = jwt.decode(resp.text, jwtkey, algorithms=["RS256"], leeway=10, audience="net.maurus.authclient")
        except (jwt.ExpiredSignatureError, jwt.InvalidAlgorithmError,
                jwt.InvalidIssuerError, jwt.InvalidTokenError) as e:
            return False

        if "authenticated" in token and token["authenticated"] and \
           "authorized" in token and token["authorized"] and \
           "scopes" in token and isinstance(token["scopes"], list) and scopes.issubset(set(token["scopes"])):
            return True
        else:
            return False
    elif resp.status_code != 200 and resp.headers["content-type"] == "application/json":
        js = resp.json()
        if "error" in js:
            print("ERROR Server returned: %s %s" % (resp.status_code, js["error"]))
    else:
        print("ERROR Server returned code %s" % resp.status_code)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="This tool talks to a proprietary API on authserver to check a username "
                    "and password. It can operate in two modes: one is djb checkpassword "
                    "compatible, the other is Apache2 mod_auth_ext compatible. The tool will "
                    "return exitcode 0 if the username and password are correct."
    )

    parser.add_argument("-m", "--mode", dest="mode", choices=["checkpassword", "authext"], default="checkpassword",
                        help="Tells the program what mode to operate in. 'authext' is compatible with Apache2 "
                             "mod_auth_ext and 'checkpassword' is compatible with the qmail checkpassword "
                             "interface.")
    parser.add_argument("-u", "--url", dest="url", required=True,
                        help="The URL of the authserver endpoint to use to check the password.")
    parser.add_argument("--no-ssl-validate", dest="validate_ssl", action="store_false", default=True,
                        help="Skip validation of the server's SSL certificate.")
    parser.add_argument("--ca-file", dest="ca_file", default=None,
                        help="Set a CA bundle to validate the server's SSL certificate against")
    parser.add_argument("-s", "--scope", dest="scopes", action="append", default=[],
                        help="One or more required scopes assigned to the user beyond being authenticated correctly.")
    parser.add_argument("--jwtkey", dest="jwtkey", required=True,
                        help="Path to a PEM encoded public key to verify the JWT claims and scopes returned by the "
                             "server (i.e. the server's public key).")
    parser.add_argument("prog", nargs="*", help="The program to run as defined by the checkpassword interface "
                                                "(optional).")

    _args = parser.parse_args()

    if _args.mode == "checkpassword":
        username, password = readinput_checkpassword()
    else:
        username, password = readinput_authext()

    if validate(_args.url, username, password, validate_ssl=_args.ca_file if _args.ca_file else _args.validate_ssl):
        if _args.mode == "checkpassword":
            # execute prog
            subprocess.call(_args.prog)
        sys.exit(0)
    else:
        sys.exit(1)


if __name__ == "__main__":
    main()
