# -* encoding: utf-8 *-
import argparse
import contextlib

import sys
from io import TextIOWrapper

from Crypto.PublicKey import RSA
from django.core.management import BaseCommand, CommandParser
from typing import Any, TextIO, Union

from django.db import DatabaseError

from mailauth import models


@contextlib.contextmanager
def stdout_or_file(path: str) -> Union[TextIOWrapper, TextIO]:
    if path == "-":
        yield sys.stdout
    else:
        fd = open(path, mode="w")
        yield fd
        fd.close()


class Command(BaseCommand):
    requires_migrations_checks = True

    def _pubkey(self, domain: str, output: str, key: str="jwt", create_key: bool=False, **kwargs: Any) -> None:
        try:
            domobj = models.Domain.objects.get(name=domain)
        except models.Domain.DoesNotExist:
            sys.stderr.write("Error: Domain %s does not exist\n" % domain)
            sys.exit(1)

        if key == "jwt":
            attr = "jwtkey"
        elif key == "dkim":
            attr = "dkimkey"
        else:
            sys.stderr.write("Unknown key type: %s\n" % key)
            sys.exit(1)

        if getattr(domobj, attr, "") == "":
            if create_key:
                privkey = RSA.generate(2048)
                setattr(domobj, attr, privkey.exportKey("PEM").decode("utf-8"))
                domobj.save()
            else:
                sys.stderr.write("Error: Domain %s has no private key of type %s and --create-key is not set\n" %
                                 (domain, key))
                sys.exit(1)
        else:
            privkey = RSA.importKey(getattr(domobj, attr))

        public_key = privkey.publickey().exportKey("PEM").decode('utf-8')
        public_key = public_key.replace("RSA PUBLIC KEY", "PUBLIC KEY")
        with stdout_or_file(output) as f:
            print(public_key, file=f)

    def _list(self, contains: str, **kwargs: Any) -> None:
        if contains:
            qs = models.Domain.objects.filter(name__icontains=contains)
        else:
            qs = models.Domain.objects.all()

        for domain in qs:
            print("%s%s - %s" % (" " * (4 - len(str(domain.id))), domain.id, domain.name))

    def add_arguments(self, parser: CommandParser) -> None:
        cmd = self

        class SubCommandParser(CommandParser):
            def __init__(self, **kwargs: Any) -> None:
                super().__init__(cmd, **kwargs)

        subparsers = parser.add_subparsers(
            dest='scmd',
            title="subcommands",
            parser_class=SubCommandParser
        )  # type: argparse._SubParsersAction

        domain_create = subparsers.add_parser("create", help="Create domain entries")
        domain_create.add_argument("domain",
                                   help="The domain name to create, should be a FQDN.")
        domain_remove = subparsers.add_parser("remove", help="Remove domain entries")
        domain_manage = subparsers.add_parser("manage", help="Manage domain entries")
        domain_pubkey = subparsers.add_parser("pubkey", help="Export public keys")
        domain_list = subparsers.add_parser("list", help="List domains")

        domain_pubkey.add_argument("--key", dest="key", choices=["jwt", "dkim"], default="jwt",
                                   help="Choose which domain key to export")
        domain_pubkey.add_argument("--create-key", dest="create_key", default=False, action="store_true",
                                   help="Create key on domain if it doesn't exist yet (Default: False)")
        domain_pubkey.add_argument("-o", "--output", dest="output", default="-",
                                   help="Output filename (or '-' for stdout)")
        domain_pubkey.add_argument("domain",
                                   help="The domain to export public keys from")

        domain_list.add_argument("contains", nargs="?",
                                 help="Filer list by this string")

    def handle(self, *args:Any, **options: Any) -> None:
        if options["scmd"] == "create":
            pass
        elif options["scmd"] == "remove":
            pass
        elif options["scmd"] == "manage":
            pass
        elif options["scmd"] == "pubkey":
            self._pubkey(**options)
        elif options["scmd"] == "list":
            self._list(**options)
        else:
            self.stderr.write("Please specify a command:\n")
            self.stderr.write("Use django-admin.py domain --settings=authserver.settings --help to get help.\n")
