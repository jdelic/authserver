# -* encoding: utf-8 *-
import argparse
import json

import sys
from django.core.management import BaseCommand, CommandParser
from typing import Any

from django.db import DatabaseError

from mailauth import models


class Command(BaseCommand):
    requires_migrations_checks = True

    def _create(self, name: str, scope: str, **kwargs: Any) -> None:
        # permission create --name=xyz scope
        try:
            scobj = models.MNApplicationPermission.objects.create(
                name=name,
                scope_name=scope,
            )  # type: models.MNApplicationPermission
        except DatabaseError as e:
            self.stderr.write("Error while creating application permission scope: %s\n" % str(e))
            sys.exit(1)

        self.stderr.write(self.style.SUCCESS("Created scope %s (Human readable name: %s)\n") %
                          (scobj.scope_name, scobj.name))

    def _list(self, filter_scope: str=None, filter_name: str=None, format: str="table", **kwargs: Any) -> None:
        filter_args = {}
        if filter_scope:
            filter_args.update({
                "scope_name__icontains": kwargs["filter_scope"],
            })
        if filter_name:
            filter_args.update({
                "name__icontains": filter_name,
            })
        if filter_args == {}:
            scopes = list(models.MNApplicationPermission.objects.all())
        else:
            scopes = list(models.MNApplicationPermission.objects.filter(**filter_args))

        sclen = 10
        for sc in scopes:
            if len(sc.scope_name) + 2 > sclen:
                sclen = len(sc.scope_name) + 2

        if sclen > 30:
            sclen = 30

        if len(scopes) > 0:
            if format == "table":
                print("SCOPE%sNAME" % (" " * (sclen - 5)))
                print("-" * 78)
            export = []
            for scope in scopes:
                if format == "table":
                    print("%s%s%s" % (
                        scope.scope_name,
                        (" " * (sclen - len(scope.scope_name)) if sclen - len(scope.scope_name) < 30 else " "),
                        scope.name
                    ))
                else:
                    export.append({
                        "scope_name": scope.scope_name,
                        "name": scope.name,
                        "id": scope.id,
                    })
            if format == "json":
                print(json.dumps(export))
        else:
            if format == "table":
                sys.stderr.write("No matching scopes found.\n")
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

        create_sp = subparsers.add_parser("create", help="Create application permissions")
        create_sp.add_argument("--name", dest="name", required=True,
                               help="The human-readable name for this permission")
        create_sp.add_argument("scope",
                               help="The scope string to use in JWT claims and OAuth2 for this permission")

        list_sp = subparsers.add_parser("list", help="List application permissions")
        list_sp.add_argument("--filter-scope", dest="filter_scope", metavar="CONTAINS",
                             help="Filter the list for scopes containing this string")
        list_sp.add_argument("--filter-name", dest="filter_name", metavar="CONTAINS",
                             help="Filter the list for permission names containing this string")
        list_sp.add_argument("--format", dest="format", choices=["json", "table"], default="table",
                             help="The output format for the results")

        remove_sp = subparsers.add_parser("remove", help="Remove application permissions")
        remove_sp.add_argument("scope",
                               help="The scope name to be removed")

        grant_menu = subparsers.add_parser("grant", help="Grant application permission to an user or group")
        sps_grant = grant_menu.add_subparsers(
            dest='gcmd',
            title='grantcommands',
            parser_class=SubCommandParser
        )  # type: argparse._SubParsersAction
        grant_usp = sps_grant.add_parser("user", help="Grant application permission to an user")
        grant_usp.add_argument("user",
                               help="The user identifier or name to add the permission to")
        grant_usp.add_argument("scopes", nargs="+",
                               help="The permission scope to add to the user")
        grant_gsp = sps_grant.add_parser("group", help="Grant application permission to a group")
        grant_gsp.add_argument("group",
                               help="The group identifier UUID to add the permission to")
        grant_gsp.add_argument("scopes", nargs="+",
                               help="The permission scope to add to the group")

        revoke_menu = subparsers.add_parser("revoke", help="Revoke application permission from an user or group")
        sps_revoke = revoke_menu.add_subparsers(
            dest='rcmd',
            title='revokecommands',
            parser_class=SubCommandParser
        )  # type: argparse._SubParsersAction
        revoke_usp = sps_revoke.add_parser("user", help="Revoke application permission from an user")
        revoke_usp.add_argument("--all", dest="revoke_all", action="store_true",
                                help="Revoke all permissions from an user")
        revoke_usp.add_argument("user",
                                help="The user identifier UUID whose permission is being revoked")
        revoke_usp.add_argument("scopes", nargs='*',
                                help="The scopes to remove from the user")
        revoke_gsp = sps_revoke.add_parser("group", help="Revoke application permission from a group")
        revoke_gsp.add_argument("--all", dest="revoke_all", action="store_true",
                                help="Revoke all permissions from a group")
        revoke_gsp.add_argument("group",
                                help="The name of the group whose permission is being revoked")
        revoke_gsp.add_argument("scopes", nargs="*",
                                help="The scopes to remove from the group")

    def handle(self, *args:Any, **options: Any) -> None:
        if options["scmd"] == "create":
            self._create(**options)
        elif options["scmd"] == "list":
            self._list(**options)
        elif options["scmd"] == "remove":
            self._remove(**options)
        elif options["scmd"] == "grant":
            if options["gcmd"] == "user":
                sys.stderr.write("Not implemented yet.\n")
                sys.exit(1)
            elif options["gcmd"] == "group":
                sys.stderr.write("Not implemented yet.\n")
                sys.exit(1)
        elif options["scmd"] == "revoke":
            if options["rcmd"] == "user":
                sys.stderr.write("Not implemented yet.\n")
                sys.exit(1)
            elif options["rcmd"] == "group":
                sys.stderr.write("Not implemented yet.\n")
                sys.exit(1)
        else:
            self.stderr.write("Please specify a command.\n")
            self.stderr.write("Use django-admin.py permission --settings=authserver.settings --help to get help.\n\n")
