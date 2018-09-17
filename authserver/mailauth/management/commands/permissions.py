# -* encoding: utf-8 *-
import argparse
import json

import sys
from django.core.management import BaseCommand, CommandParser
from typing import Any, List

from django.db import DatabaseError, transaction
from django.db.models import Q

from mailauth import models


class Command(BaseCommand):
    requires_migrations_checks = True

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
                             help="Filter the list for permissions containing this string")
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
                               help="The permission to add to the user")
        grant_gsp = sps_grant.add_parser("group", help="Grant application permission to a group")
        grant_gsp.add_argument("group",
                               help="The group identifier UUID or name to add the permission to")
        grant_gsp.add_argument("scopes", nargs="+",
                               help="The permission to add to the group")

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
                                help="The user identifier UUID or name whose permission is being revoked")
        revoke_usp.add_argument("scopes", nargs="*",
                                help="The permissions to remove from the user")
        revoke_gsp = sps_revoke.add_parser("group", help="Revoke application permission from a group")
        revoke_gsp.add_argument("--all", dest="revoke_all", action="store_true",
                                help="Revoke all permissions from a group")
        revoke_gsp.add_argument("group",
                                help="The group UUID or name whose permission is being revoked")
        revoke_gsp.add_argument("scopes", nargs="*",
                                help="The permissions to remove from the group")

        require_menu = subparsers.add_parser("require", help="Require application permissions for an application")
        require_menu.add_argument("client_name", help="The client_name of the application. Must have been previously "
                                                      "created using 'manage.py oauth2 create'")
        require_menu.add_argument("perms", nargs="+",
                                  help="The permissions to require for this application")

        drop_menu = subparsers.add_parser("drop", help="Drop required application permissions from an "
                                                       "application")
        drop_menu.add_argument("client_name", help="The client_name of the application. Must have been previously "
                                                   "created using 'manage.py oauth2 create'")
        drop_menu.add_argument("perms", nargs="+",
                               help="The required permissions to drop from this application")

        show_menu = subparsers.add_parser("show", help="Show what permissions are required for an application")
        show_menu.add_argument("--format", dest="format", choices=["json", "table"], default="table",
                               help="The output format for the results")
        show_menu.add_argument("client_name", help="The client_name of the application. Must have been previously "
                                                   "created using 'manage.py oauth2 create'")

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

    def _remove(self, scope: str) -> None:
        try:
            models.MNApplicationPermission.objects.filter(scope_name=scope).delete()
        except DatabaseError as e:
            self.stderr.write("Error while deleting application permission scope: %s\n" % str(e))
            sys.exit(1)

        self.stderr.write(self.style.SUCCESS("Deleted scope %s\n") % scope)

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

        fmtstr = self._table_left_format_str([p.scope_name for p in scopes])

        if len(scopes) > 0:
            if format == "table":
                print(fmtstr.format("PERMISSION", "NAME"))
                print("-" * 78)
            export = []
            for scope in scopes:
                if format == "table":
                    print(fmtstr.format(scope.scope_name, scope.name))
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

    def _table_left_format_str(self, strs: List[str]) -> str:
        maxlen = 10
        for s in strs:
            if len(s) + 2 > maxlen:
                maxlen = len(s) + 2

        if maxlen > 30:
            maxlen = 30
        return "{:<%s.%s} {}" % (maxlen, maxlen)

    def _get_client(self, client_name: str) -> models.MNApplication:
        try:
            cl = models.MNApplication.objects.get(Q(name=client_name) | Q(client_id=client_name))
        except models.MNApplication.DoesNotExist as e:
            self.stderr.write("Client not found (%s): %s\n" % (client_name, str(e)))
            sys.exit(1)
        except DatabaseError as e:
            self.stderr.write("Error while loading client to add permissions: %s\n" % str(e))
            sys.exit(1)
        return cl

    def _require(self, client_name: str, perms: List[str], **kwargs: Any) -> None:
        cl = self._get_client(client_name)
        permissions_missing = False
        with transaction.atomic():
            for perm in perms:
                try:
                    p = models.MNApplicationPermission.objects.get(Q(scope_name=perm) | Q(name=perm))
                except models.MNApplicationPermission.DoesNotExist as e:
                    self.stderr.write("No such permission (%s): %s\n" % (perm, str(e)))
                    permissions_missing = True
                else:
                    cl.required_permissions.add(p)

        if not permissions_missing:
            self.stderr.write(self.style.SUCCESS("Added permission requirements to client '%s':\n%s") %
                              (cl.name, ", ".join(perms)))

    def _drop(self, client_name: str, perms: List[str], **kwargs: Any) -> None:
        cl = self._get_client(client_name)
        permissions_missing = False
        cur_perm = list(cl.required_permissions.all())
        with transaction.atomic():
            for perm in perms:
                try:
                    p = models.MNApplicationPermission.objects.get(Q(scope_name=perm) | Q(name=perm))
                except models.MNApplicationPermission.DoesNotExist as e:
                    self.stderr.write("No such permission (%s): %s\n" % (perm, str(e)))
                    permissions_missing = True
                else:
                    if p in cur_perm:
                        cl.required_permissions.remove(p)
                    else:
                        self.stderr.write("Client doesn't require permission: %s.\n" % perm)

        if not permissions_missing:
            self.stderr.write(self.style.SUCCESS("Dropped permission requirements from client '%s':\n%s\n"
                                                 "Remaining:\n%s") %
                              (cl.name, ", ".join(perms),
                               ", ".join([p.scope_name for p in cl.required_permissions.all()])))

    def _show(self, client_name: str, format: str="table", **kwargs) -> None:
        cl = self._get_client(client_name)
        if format == "table":
            fmtstr = self._table_left_format_str([p.scope_name for p in cl.required_permissions.all()])
            print(fmtstr.format("PERMISSION", "NAME"))
            print("-" * 78)
            for perm in cl.required_permissions.all():
                if format == "table":
                    print(fmtstr.format(perm.scope_name, perm.name))
        else:
            print(json.dumps([{perm.scope_name: perm.name} for perm in cl.required_permissions.all()]))

    def handle(self, *args: Any, **options: Any) -> None:
        if options["scmd"] == "create":
            self._create(**options)
        elif options["scmd"] == "list":
            self._list(**options)
        elif options["scmd"] == "remove":
            self._remove(**options)
        elif options["scmd"] == "require":
            self._require(**options)
        elif options["scmd"] == "drop":
            self._drop(**options)
        elif options["scmd"] == "show":
            self._show(**options)
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
