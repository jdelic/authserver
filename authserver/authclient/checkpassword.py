#!/usr/bin/python -u
# -* encoding: utf-8 *-
import os
import subprocess
import sys
import argparse

from typing import Tuple


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


def validate(url: str, username: str, password: str) -> bool:
    pass


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
    parser.add_argument("prog", nargs="*", help="The program to run as defined by the checkpassword interface "
                                                "(optional).")

    _args = parser.parse_args()

    if _args.mode == "checkpassword":
        username, password = readinput_checkpassword()
    else:
        username, password = readinput_authext()

    if validate(_args.url, username, password):
        if _args.mode == "checkpassword":
            # execute prog
            subprocess.call(_args.prog)
        sys.exit(0)
    else:
        sys.exit(1)


if __name__ == "__main__":
    main()
