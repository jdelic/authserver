# -* encoding: utf-8 *-
import argparse
import json
import re

import sys

from django.core.management import BaseCommand, CommandParser
from typing import Any, Union, List, cast, IO, Match

from django.db.models.query import QuerySet
from typing import Optional

from mailauth.utils import stdout_or_file, generate_rsa_key, import_rsa_key
from mailauth.models import Domain


KEY_CHOICES = ["jwt", "dkim"]


class Command(BaseCommand):
    requires_migrations_checks = True

    def _create(self, domain: str, create_keys: List[str]=None, dkim_selector: str="", redirect_to: str="",
                jwt_allow_subdomain_signing: bool=False, **kwargs: Any) -> None:
        try:
            domobj = Domain.objects.get(name__iexact=domain)
        except Domain.DoesNotExist:
            pass
        else:
            sys.stderr.write("Error: Domain %s already exists\n" % domain)
            sys.exit(1)

        domobj = Domain.objects.create(name=domain, dkimselector=dkim_selector, redirect_to=redirect_to,
                                              jwt_subdomains=jwt_allow_subdomain_signing)
        if create_keys is None:
            create_keys = []

        if "jwt" in create_keys:
            domobj.jwtkey = generate_rsa_key(2048)
        if "dkim" in create_keys:
            domobj.dkimkey = generate_rsa_key(2048)
        domobj.save()

        sys.stderr.write("Domain %s created" % domain)

    def _pubkey(self, domain: str, output: str, key: str="jwt", create_key: bool=False, format: str="pem",
                **kwargs: Any) -> None:
        try:
            domobj = Domain.objects.get(name=domain)
        except Domain.DoesNotExist:
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
                privkey = generate_rsa_key()
                setattr(domobj, attr, privkey.private_key)
                domobj.save()
            else:
                sys.stderr.write("Error: Domain %s has no private key of type %s and --create-key is not set\n" %
                                 (domain, key))
                sys.exit(1)
        else:
            privkey = import_rsa_key(getattr(domobj, attr))

        public_key = privkey.public_key
        with stdout_or_file(output) as f:
            if format == "pem":
                print(public_key, file=cast(IO[str], f))
            elif format == "dkimdns":
                outstr = "\"v=DKIM1\; k=rsa\; p=\" {split_key}".format(
                    split_key="\n".join(
                        ['"%s"' % line for line in
                         cast(Match[str], re.search("--\n(.*?)\n--", public_key, re.DOTALL)).group(1).split("\n")])
                )  # the cast tells mypy that re.search will not return None here
                print(outstr, file=cast(IO[str], f))

        if output != "-":
            sys.stderr.write("Public key exported to %s\n" % output)

    def _list(self, contains: str, include_parent_domain: bool=False, format: str="list",
              require_jwt_subdomains: bool=True, **kwargs: Any) -> None:
        if contains and include_parent_domain:
            try:
                dom = Domain.objects.find_parent_domain(
                    contains, require_jwt_subdomains_set=require_jwt_subdomains)  # type: Optional[Domain]
            except Domain.DoesNotExist:
                dom = None
            qs = [dom] if dom is not None else []  # type: Union[QuerySet, Domain]
        elif contains and not include_parent_domain:
            qs = Domain.objects.filter(name__icontains=contains)
        else:
            qs = Domain.objects.all()

        if qs:
            export = []
            for domain in qs:
                if format == "list":
                    print("%s%s   %s" % (" " * (4 - len(str(domain.id))), domain.id, domain.name))
                else:
                    export.append({
                        "name": domain.name,
                        "id": domain.id,
                        "jwt_sign_subdomains": domain.jwt_subdomains,
                        "dkimselector": domain.dkimselector,
                    })
            if format == "json":
                print(json.dumps(export))
        else:
            if format == "list":
                sys.stderr.write("No results.\n")
                sys.exit(1)
            else:
                print("[]")
                sys.exit(0)

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
        domain_create.add_argument("--jwt-allow-subdomain-signing", dest="jwt_allow_subdomain_signing",
                                   action="store_true", default=False,
                                   help="Allow this domain's JWT signing key to be used for subdomains")
        domain_create.add_argument("--redirect-all-email-to", dest="redirect_to", metavar="FQDN",
                                   default="", help="Redirect all email sent to this domain to FQDN")
        domain_create.add_argument("--create-key", dest="create_keys", choices=KEY_CHOICES, action="append", default=[],
                                   help="Create these keys when creating the domain")
        domain_create.add_argument("--dkim-selector", dest="dkim_selector", default="",
                                   help="The DKIM selector to print in the DKIM records (for the pubkey command, for "
                                        "example)")
        domain_create.add_argument("domain",
                                   help="The domain name to create as FQDN")

        domain_remove = subparsers.add_parser("remove", help="Remove domain entries")
        domain_remove.add_argument("--remove-multiple", dest="delete_multiple", action="store_true", default=False,
                                   help="If multiple domains are matched, remove all of them")
        domain_remove.add_argument("--yes", dest="approved", action="store_true", default=False,
                                   help="Do not ask for confirmation on removal")
        domain_remove.add_argument("contains",
                                   help="A string matching the domain(s) to remove")

        domain_manage = subparsers.add_parser("manage", help="Manage domain entries")

        domain_pubkey = subparsers.add_parser("pubkey", help="Export public keys")
        domain_pubkey.add_argument("--key", dest="key", choices=KEY_CHOICES, default="jwt",
                                   help="Choose which domain key to export")
        domain_pubkey.add_argument("--create-key", dest="create_key", default=False, action="store_true",
                                   help="Create key on domain if it doesn't exist yet (Default: False)")
        domain_pubkey.add_argument("--format", choices=["dkimdns", "pem"], default="pem",
                                   help="The output format: either 'dkimdns' or 'pem' (Default: 'pem'). 'dkimdns' is "
                                        "suitable for being added to a DNS TXT entry")
        domain_pubkey.add_argument("-o", "--output", dest="output", default="-",
                                   help="Output filename (or '-' for stdout)")
        domain_pubkey.add_argument("domain",
                                   help="The domain to export public keys from")

        domain_list = subparsers.add_parser("list", help="List domains")
        domain_list.add_argument("--include-parent-domain", dest="include_parent_domain", action="store_true",
                                 default=False, help="Return a parent domain if such a domain exists")
        domain_list.add_argument("--format", dest="format", choices=["json", "list"], default="list",
                                 help="The output format for the results")
        domain_list.add_argument("--no-require-subdomain-signing", dest="require_jwt_subdomains", action="store_false",
                                 default=True,
                                 help="Only find parent domains if they can sign for subdomains")
        domain_list.add_argument("contains", nargs="?",
                                 help="Filer list by this string")

    def handle(self, *args:Any, **options: Any) -> None:
        if options["scmd"] == "create":
            self._create(**options)
        elif options["scmd"] == "remove":
            sys.stderr.write("Not implemented yet.\n")
            sys.exit(1)
        elif options["scmd"] == "manage":
            sys.stderr.write("Not implemented yet.\n")
            sys.exit(1)
        elif options["scmd"] == "pubkey":
            self._pubkey(**options)
        elif options["scmd"] == "list":
            self._list(**options)
        else:
            self.stderr.write("Please specify a command:\n")
            self.stderr.write("Use django-admin.py domain --settings=authserver.settings --help to get help.\n")
