# -* encoding: utf-8 *-
import argparse
import json

import sys
from django.core.management.base import BaseCommand, CommandParser
from typing import Any

from django.db import IntegrityError, DatabaseError
from django.db.models import Q

from mailauth.management.commands._common import table_left_format_str
from mailauth.models import MNGroup


class Command(BaseCommand):
    requires_migrations_checks = True

    def add_arguments(self, parser: CommandParser) -> None:
        class SubCommandParser(CommandParser):
            def __init__(self, **kwargs: Any) -> None:
                super().__init__(**kwargs)

        subparsers = parser.add_subparsers(
            dest='scmd',
            title="subcommands",
            parser_class=SubCommandParser
        )  # type: argparse._SubParsersAction

        create_sp = subparsers.add_parser("create", help="Create user groups")
        create_sp.add_argument("groupname", help="The name of the group to create")

        list_sp = subparsers.add_parser("list")
        list_sp.add_argument("--format", dest="format", choices=["json", "table"], default="table",
                             help="The output format for the results")

        remove_sp = subparsers.add_parser("remove", help="Remove user group")
        remove_sp.add_argument("groupname", help="The group's UUID or name")

    def _create(self, groupname: str, **kwargs: Any) -> None:
        try:
            group = MNGroup.objects.create(name=groupname)
        except DatabaseError as e:
            self.stderr.write("Error while creating user group: %s\n" % str(e))
            sys.exit(1)

        self.stderr.write(self.style.SUCCESS("Created group %s (Human readable name: %s)\n") %
                          (str(group.pk), group.name))

    def _list(self, format: str = "table", **kwargs: Any) -> None:
        groups = list(MNGroup.objects.all())
        fmtstr = table_left_format_str([str(g.pk) for g in groups])

        if len(groups) > 0:
            if format == "table":
                print(fmtstr.format("ID", "NAME"))
                print("-" * 78)
                for g in groups:
                    print(fmtstr.format(str(g.pk), g.name))
            elif format == "json":
                exp = []
                for g in groups:
                    exp.append({"name": g.name, "id": str(g.pk)})
                print(json.dumps(exp))
        else:
            if format == "table":
                sys.stderr.write("No groups found.\n")
                sys.exit(1)
            elif format == "json":
                print("[]")
                sys.exit(0)

    def _remove(self, groupname: str, **kwargs: Any) -> None:
        try:
            group = MNGroup.objects.get(Q(pk=groupname) | Q(name=groupname))
            group.delete()
        except MNGroup.DoesNotExist:
            sys.stderr.write("Group with name or id %s not found" % groupname)
            sys.exit(1)
        except DatabaseError as e:
            sys.stderr.write("Error while deleting group %s: %s" % (groupname, str(e)))
            sys.exit(1)

    def handle(self, *args: Any, **options: Any) -> None:
        if options["scmd"] == "create":
            self._create(**options)
        elif options["scmd"] == "list":
            self._list(**options)
        elif options["scmd"] == "remove":
            self._remove(**options)
        else:
            self.stderr.write("Please specify a command.\n")
            self.stderr.write("Use django-admin.py permission --settings=authserver.settings --help to get help.\n\n")
