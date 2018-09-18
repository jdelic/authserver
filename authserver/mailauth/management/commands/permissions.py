# -* encoding: utf-8 *-
import argparse
import json

import sys
import uuid

from django.core.management import BaseCommand, CommandParser
from typing import Any, List, Optional

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
        grant_msp = sps_grant.add_parser("membership", help="Grant group membership to a user")
        grant_msp.add_argument("user",
                               help="The user identifier UUID or name to add to the groups")
        grant_msp.add_argument("groups", nargs="+",
                               help="Group UUIDs or names to add the user into")

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
        revoke_msp = sps_revoke.add_parser("membership", help="Revoke group membership from an user")
        revoke_msp.add_argument("--all", dest="revoke_all", action="store_true",
                                help="Revoke all permissions from a group")
        revoke_msp.add_argument("user",
                                help="The user identifier UUID or name to remove from the groups")
        revoke_msp.add_argument("groups", nargs="+",
                                help="Group UUIDs or names to remove the user from")

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

        show_menu = subparsers.add_parser("show", help="Show permissions for users, groups or required permissions for "
                                                       "applications")
        sps_show = show_menu.add_subparsers(
            dest='showcmd',
            title='showcommands',
            parser_class=SubCommandParser
        )  # type: argparse._SubParsersAction
        show_usp = sps_show.add_parser("user", help="Show permissions for an user")
        show_usp.add_argument("--format", dest="format", choices=["json", "table"], default="table",
                              help="The output format for the results")
        show_usp.add_argument("user", help="The user identifier to show permissions for")
        show_gsp = sps_show.add_parser("group", help="Show permissions for a group")
        show_gsp.add_argument("--format", dest="format", choices=["json", "table"], default="table",
                              help="The output format for the results")
        show_gsp.add_argument("group", help="The group identifier to show permissions for")
        show_csp = sps_show.add_parser("application", help="Show required permissions for an application")
        show_csp.add_argument("--format", dest="format", choices=["json", "table"], default="table",
                              help="The output format for the results")
        show_csp.add_argument("client_name", help="The client_name of the application. Must have been previously "
                                                  "created using 'manage.py oauth2 create'")
        show_msp = sps_show.add_parser("membership", help="Show group memberships for an user")
        show_msp.add_argument("--format", dest="format", choices=["json", "table"], default="table",
                              help="The output format for the results")
        show_msp.add_argument("user", help="The user to show group memberships for")

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

    def _get_user(self, name: str, exit: bool=True) -> Optional[models.MNUser]:
        u = None
        try:
            uuid.UUID(name)
            u = models.MNUser.objects.get(pk=name)
        except (ValueError, models.MNUser.DoesNotExist):
            try:
                u = models.MNUser.objects.resolve_user(name)
            except models.UnresolvableUserException as e:
                self.stderr.write("Unresolvable user %s: %s" % (name, str(e)))
        if not u and exit:
            sys.exit(1)
        return u

    def _get_group(self, name: str, exit: bool=True) -> Optional[models.MNGroup]:
        try:
            uuid.UUID(name)
            g = models.MNGroup.objects.get(Q(pk=name) | Q(name=name))
        except (ValueError, models.MNGroup.DoesNotExist):
            self.stderr.write("Unresolvable group %s" % name)
            if exit:
                sys.exit(1)
            else:
                return None
        return g

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
        added = set()
        with transaction.atomic():
            for perm in perms:
                try:
                    p = models.MNApplicationPermission.objects.get(Q(scope_name=perm) | Q(name=perm))
                except models.MNApplicationPermission.DoesNotExist as e:
                    self.stderr.write("No such permission (%s): %s\n" % (perm, str(e)))
                else:
                    cl.required_permissions.add(p)
                    added.add(p.scope_name)

        self.stderr.write(self.style.SUCCESS("Added permission requirements to client '%s':\n%s") %
                          (cl.name, ", ".join(list(added))))

    def _drop(self, client_name: str, perms: List[str], **kwargs: Any) -> None:
        cl = self._get_client(client_name)
        cur_perm = list(cl.required_permissions.all())
        removed = set()
        with transaction.atomic():
            for perm in perms:
                try:
                    p = models.MNApplicationPermission.objects.get(Q(scope_name=perm) | Q(name=perm))
                except models.MNApplicationPermission.DoesNotExist as e:
                    self.stderr.write("No such permission (%s): %s\n" % (perm, str(e)))
                else:
                    if p in cur_perm:
                        cl.required_permissions.remove(p)
                        removed.add(p.scope_name)
                    else:
                        self.stderr.write("Client doesn't require permission: %s.\n" % perm)

        self.stderr.write(self.style.SUCCESS("Dropped permission requirements from client '%s':\n%s\n"
                                             "Remaining:\n%s") %
                          (cl.name, ", ".join(list(removed)),
                           ", ".join([p.scope_name for p in cl.required_permissions.all()])))

    def _show_user(self, user: str, format: str="table", **kwargs: Any) -> None:
        user = self._get_user(user)
        if format == "table":
            fmtstr = self._table_left_format_str([p.scope_name for p in user.app_permissions.all()])
            print("Permissions for user %s (%s)" % (user.get_username(), str(user.uuid)))
            print(fmtstr.format("PERMISSION", "NAME"))
            print("-" * 78)
            for perm in user.app_permissions.all():
                print(fmtstr.format(perm.scope_name, perm.name))
        else:
            print(json.dumps([{perm.scope_name: perm.name} for perm in user.app_permissions.all()]))

    def _show_group(self, group: str, format: str="table", **kwargs: Any) -> None:
        group = self._get_group(group)
        if format == "table":
            fmtstr = self._table_left_format_str([p.scope_name for p in group.group_permissions.all()])
            print("Permissions for group %s (%s)" % (group.name, str(group.uuid)))
            print(fmtstr.format("PERMISSION", "NAME"))
            print("-" * 78)
            for perm in group.group_permissions.all():
                print(fmtstr.format(perm.scope_name, perm.name))
        else:
            print(json.dumps([{perm.scope_name: perm.name} for perm in group.group_permissions.all()]))

    def _show_client(self, client_name: str, format: str="table", **kwargs: Any) -> None:
        cl = self._get_client(client_name)
        if format == "table":
            fmtstr = self._table_left_format_str([p.scope_name for p in cl.required_permissions.all()])
            print("Permissions for client %s (%s)" % (cl.name, cl.client_id,))
            print(fmtstr.format("PERMISSION", "NAME"))
            print("-" * 78)
            for perm in cl.required_permissions.all():
                print(fmtstr.format(perm.scope_name, perm.name))
        else:
            print(json.dumps([{perm.scope_name: perm.name} for perm in cl.required_permissions.all()]))

    def _show_membership(self, user: str, format: str="table", **kwargs: Any) -> None:
        user = self._get_user(user)
        if format == "table":
            fmtstr = self._table_left_format_str([g.name for g in user.app_groups.all()])
            print("Group memberships for user %s (%s)" % (user.get_username(), str(user.uuid)))
            print(fmtstr.format("GROUP", "PERMISSIONS"))
            print("-" * 78)
            for group in user.app_groups.all():
                print(fmtstr.format(group.name, ", ".join([gp.scope_name for gp in group.group_permissions.all()])))
        else:
            print(json.dumps([{group.name: [gp.scope_name for gp in group.group_permissions.all()]}
                              for group in user.app_groups.all()]))

    def _grant_to_user(self, user: str, perms: List[str], **kwargs: Any) -> None:
        user = self._get_user(user)
        added = set()
        permissions_missing = False
        with transaction.atomic():
            for perm in perms:
                try:
                    p = models.MNApplicationPermission.objects.get(Q(name=perm) | Q(scope_name=perm))
                except models.MNApplicationPermission.DoesNotExist:
                    self.stderr.write("No such permission: %s" % perm)
                    permissions_missing = True
                else:
                    user.app_permissions.add(p)
                    added.add(p.scope_name)

            if permissions_missing:
                sys.exit(1)

        self.stderr.write(self.style.SUCCESS("Granted user %s (%s) permissions: %s" %
                                             (user.get_username(), str(user.uuid), ", ".join(list(added)))))

    def _grant_membership(self, user: str, groups: List[str], **kwargs) -> None:
        user = self._get_user(user)
        added = set()
        groups_missing = False

        with transaction.atomic():
            for group in groups:
                g = self._get_group(group, exit=False)
                if g:
                    user.app_groups.add(g)
                    added.add(g.name)
                else:
                    self.stderr.write("No such group: %s" % group)
                    groups_missing = True

            if groups_missing:
                sys.exit(1)

        self.stderr.write(self.style.SUCCESS("Granted user %s (%s) membership in: %s" %
                                             (user.get_username(), str(user.uuid), ", ".join(list(added)))))

    def _revoke_from_user(self, user: str, revoke_all: bool=False, perms: List[str]=None, **kwargs: Any) -> None:
        user = self._get_user(user)
        revoked = set()
        permissions_missing = False

        if not perms and not revoke_all:
            sys.stderr.write("No permissions to revoke and flag --all not set. Nothing to do.")
            sys.exit(1)

        if revoke_all:
            revoked = set([p.scope_name for p in user.app_permissions.all()])
            user.app_permissions.clear()
        else:
            with transaction.atomic():
                for perm in perms:
                    try:
                        p = models.MNApplicationPermission.objects.get(Q(name=perm) | Q(scope_name=perm))
                    except models.MNApplicationPermission.DoesNotExist:
                        self.stderr.write("No such permission: %s" % perm)
                        permissions_missing = True
                    else:
                        user.app_permissions.remove(p)
                        revoked.add(p.scope_name)

                if permissions_missing:
                    sys.exit(1)

        self.stderr.write(self.style.SUCCESS("Revoked permissions from user %s (%s): %s" %
                                             (user.get_username(), str(user.id), ", ".join(list(revoked)))))

    def _grant_to_group(self, group: str, perms: List[str], **kwargs: Any) -> None:
        group = self._get_group(group)
        added = set()
        permissions_missing = False

        with transaction.atomic():
            for perm in perms:
                try:
                    p = models.MNApplicationPermission.objects.get(Q(name=perm) | Q(scope_name=perm))
                except models.MNApplicationPermission.DoesNotExist:
                    self.stderr.write("No such permission: %s" % perm)
                    permissions_missing = True
                else:
                    group.group_permissions.add(p)
                    added.add(p.scope_name)

            if permissions_missing:
                sys.exit(1)

        self.stderr.write(self.style.SUCCESS("Granted group %s (%s) permissions: %s" %
                                             (group.name, str(group.id), ", ".join(list(added)))))

    def _revoke_from_group(self, group: str, revoke_all: bool=False, perms: List[str]=None, **kwargs: Any) -> None:
        group = self._get_group(group)
        revoked = set()
        permissions_missing = False

        if not perms and not revoke_all:
            sys.stderr.write("No permissions to revoke and flag --all not set. Nothing to do.")
            sys.exit(1)

        if revoke_all:
            revoked = set([p.scope_name for p in group.group_permissions.all()])
            group.group_permissions.clear()
        else:
            with transaction.atomic():
                for perm in perms:
                    try:
                        p = models.MNApplicationPermission.objects.get(Q(name=perm) | Q(scope_name=perm))
                    except models.MNApplicationPermission.DoesNotExist:
                        self.stderr.write("No such permission: %s" % perm)
                        permissions_missing = True
                    else:
                        group.group_permissions.remove(p)
                        revoked.add(p.scope_name)

                if permissions_missing:
                    sys.exit(1)

        self.stderr.write(self.style.SUCCESS("Revoked permissions from user %s (%s): %s" %
                                             (group.name, str(group.uuid), ", ".join(list(revoked)))))

    def _revoke_membership(self, user: str, revoke_all: bool=False, groups: List[str]=None, **kwargs: Any) -> None:
        user = self._get_user(user)
        revoked = set()

        if not groups and not revoke_all:
            sys.stderr.write("No memberships to revoke and flag --all not set. Nothing to do.")
            sys.exit(1)

        if revoke_all:
            revoked = set([g.name for g in user.app_groups.all()])
            user.app_groups.clear()
        else:
            with transaction.atomic():
                for group in groups:
                    g = self._get_group(group, exit=False)
                    if g:
                        user.app_groups.remove(g)
                        revoked.add(g.name)
                    else:
                        self.stderr.write("No such group: %s" % group)

        self.stderr.write(self.style.SUCCESS("Revoked membership from user %s (%s) in groups: %s" %
                                             (user.get_username(), str(user.uuid), ", ".join(list(revoked)))))

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
            if options["showcmd"] == "user":
                self._show_user(**options)
            elif options["showcmd"] == "group":
                self._show_group(**options)
            elif options["showcmd"] == "application":
                self._show_client(**options)
            elif options["showcmd"] == "membership":
                self._show_membership(**options)
        elif options["scmd"] == "grant":
            if options["gcmd"] == "user":
                self._grant_to_user(**options)
            elif options["gcmd"] == "group":
                self._grant_to_group(**options)
            elif options["gcmd"] == "membership":
                self._grant_membership(**options)
        elif options["scmd"] == "revoke":
            if options["rcmd"] == "user":
                self._revoke_from_user(**options)
            elif options["rcmd"] == "group":
                self._revoke_from_group(**options)
            elif options["rcmd"] == "membership":
                self._revoke_membership(**options)
        else:
            self.stderr.write("Please specify a command.\n")
            self.stderr.write("Use django-admin.py permission --settings=authserver.settings --help to get help.\n\n")
