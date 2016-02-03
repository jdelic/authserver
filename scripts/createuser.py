#!/usr/bin/env python -u
#

import os
import sys
import getpass

from argparse import ArgumentParser
from django.contrib.auth.hashers import make_password
from django.contrib.auth.models import User
from django.core.exceptions import ValidationError


def read_password(filename):
    if not os.path.exists(filename):
        print("%s does not exist" % filename)

    if not os.getuid() == os.stat(filename).st_uid:
        print("File %s must be owned by user executing createuser.py (%s != %s)" % (filename, os.getuid(),
                                                                                    os.stat(filename).st_uid))

    if not


def main():
    parser = ArgumentParser(description="Create a user in the CAS server database. The user will be able to "
                                        "log into all servers which authenticate against this CAS server. "
                                        "Users are authenticated through their usernames or email addresses and "
                                        "their passwords. Passwords will be hashed and randomly salted in accordance "
                                        "with the settings in casserver.settings.")

    pos_args = parser.add_argument_group("Positional arguments")
    pos_args.add_argument("username", dest="username",
                          help="The user's alias to create.", required=True)
    pos_args.add_argument("email address", dest="email",
                          help="The user's emaila address.", required=True)

    pw_args = parser.add_mutually_exclusive_group()
    pw_args.add_argument("-f", "--read-from", dest="readfrom", default=None,
                         help="Read the plaintext password from a file. The file MUST belong to the user executing "
                              "createuser and it MUST have permissions of 600 or 400.")
    pw_args.add_argument("-p", "--prompt", dest="prompt", action="store_true", default=False,
                         help="Prompt for the cleartext password and read it from STDIN.")
    pw_args.add_argument("-s", "--set", dest="set_password", default=None,
                         help="Set the password to the value provided as a command-line parameter. The password MUST "
                              "already be hashed with a valid algorithm. Does NOT support plaintext passwords. You can "
                              "use 'mkpasswd' to hash passwords. However, passwords will be converted to the hashing "
                              "algorithm selected in casserver.settings the next time the user logs in, if you use "
                              "a password hashed with a different hashing algorithm.")

    _args = parser.parse_args()

    if _args.readfrom is None and _args.set_password in None and not _args.prompt:
        print("You must specify either '--read-from', '--prompt' or '--set' to set an input method.")

    clear_password = None
    hashed_password = None
    if _args.readfrom is not None:
        clear_password = read_password(_args.readfrom)

    if _args.prompt:
        clear_password = getpass.getpass("Enter password: ")
        verify_password = getpass.getpass("Verify password: ")

        if clear_password != verify_password:
            print("Supplied passwords did not match.")
            sys.exit(1)
        verify_password = None

    if _args.set_password:
        hashed_password = _args.set_password
    else:
        hashed_password = make_password(clear_password)
        clear_password = None

    try:
        user = User.objects.create_user(_args.username, _args.email)
        user.password = hashed_password
        user.save()
    except ValidationError as e:
        print("Invalid user data")
        raise

    print("User %s (%s) created." % (_args.username, _args.email))

