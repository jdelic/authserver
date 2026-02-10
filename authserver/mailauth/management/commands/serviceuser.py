import argparse
import json
import sys
import uuid
from typing import Any, Dict, List

from django.core.exceptions import ValidationError
from django.core.management.base import BaseCommand, CommandParser
from django.db import DatabaseError, transaction
from django.db.models import Q
from django.utils.crypto import get_random_string

from mailauth import models
from mailauth.management.commands._common import table_left_format_str
from mailauth.management.commands._mgmt_helpers import ask_for_confirmation, resolve_user


class Command(BaseCommand):
    requires_migrations_checks = True

    def add_arguments(self, parser: CommandParser) -> None:
        class SubCommandParser(CommandParser):
            def __init__(self, **kwargs: Any) -> None:
                super().__init__(**kwargs)

        subparsers = parser.add_subparsers(dest="scmd", title="subcommands", parser_class=SubCommandParser)

        create_sp = subparsers.add_parser("create", help="Create service user")
        create_sp.add_argument("-u", "--user", dest="user", required=True,
                               help="Backing user identifier or resolvable email alias")
        create_sp.add_argument("--username", dest="username", default=None)
        create_sp.add_argument("--description", dest="description", default="")
        create_sp.add_argument("--password", dest="password", default=None,
                               help="If omitted, a random password is generated and printed")

        list_sp = subparsers.add_parser("list", help="List service users")
        self._add_selector_args(list_sp)
        list_sp.add_argument("-f", "--format", dest="format", choices=["table", "json"], default="table")

        show_sp = subparsers.add_parser("show", help="Show service users")
        self._add_selector_args(show_sp)
        show_sp.add_argument("-f", "--format", dest="format", choices=["table", "json"], default="table")

        edit_sp = subparsers.add_parser("edit", help="Edit service users")
        self._add_selector_args(edit_sp)
        edit_sp.add_argument("--set-description", dest="set_description", default=None)
        edit_sp.add_argument("--set-password", dest="set_password", default=None)
        edit_sp.add_argument("--set-username", dest="set_username", default=None)
        edit_sp.add_argument("--set-user", dest="set_user", default=None)
        edit_sp.add_argument("-y", "--yes", dest="approved", action="store_true", default=False)

        remove_sp = subparsers.add_parser("remove", help="Remove service users")
        self._add_selector_args(remove_sp)
        remove_sp.add_argument("-y", "--yes", dest="approved", action="store_true", default=False)

    def _add_selector_args(self, parser: CommandParser) -> None:
        parser.add_argument("selectors", nargs="*", help="Service user selectors: UUID or username")
        parser.add_argument("-c", "--contains", dest="contains", default=None)
        parser.add_argument("-u", "--user", dest="user", default=None)

    def _to_dict(self, obj: models.MNServiceUser) -> Dict[str, Any]:
        return {
            "id": str(obj.pk),
            "username": obj.username,
            "description": obj.description,
            "user_identifier": obj.user.identifier,
            "user_uuid": str(obj.user.pk),
        }

    def _render(self, items: List[models.MNServiceUser], format: str) -> None:
        if format == "json":
            print(json.dumps([self._to_dict(item) for item in items]))
            return

        if not items:
            self.stderr.write("No matching service users found.")
            sys.exit(1)

        fmtstr = table_left_format_str([item.username for item in items])
        print(fmtstr.format("USERNAME", "ID (USER)"))
        print("-" * 78)
        for item in items:
            print(fmtstr.format(item.username, "%s (%s)" % (item.pk, item.user.identifier)))

    def _select_service_users(self, require_selector: bool = False, **options: Any) -> List[models.MNServiceUser]:
        query = Q()
        used = False

        selectors = options.get("selectors") or []
        if selectors:
            sq = Q()
            for selector in selectors:
                try:
                    parsed = uuid.UUID(selector)
                except ValueError:
                    sq |= Q(username=selector)
                else:
                    sq |= Q(pk=parsed)
            query &= sq
            used = True

        if options.get("contains"):
            query &= (Q(username__icontains=options["contains"]) | Q(description__icontains=options["contains"]))
            used = True

        if options.get("user"):
            try:
                user = resolve_user(options["user"])
            except ValueError as exc:
                self.stderr.write(str(exc))
                sys.exit(1)
            query &= Q(user=user)
            used = True

        if require_selector and not used:
            self.stderr.write("You must provide at least one selector.")
            sys.exit(1)

        return list(models.MNServiceUser.objects.filter(query).select_related("user"))

    def _create(self, user: str, username: str = None, description: str = "", password: str = None,
                **kwargs: Any) -> None:
        try:
            user_obj = resolve_user(user)
        except ValueError as exc:
            self.stderr.write(str(exc))
            sys.exit(1)

        plain_password = password if password is not None else get_random_string(24)
        obj = models.MNServiceUser(
            user=user_obj,
            username=(username if username is not None else str(uuid.uuid4())),
            description=description,
        )
        obj.set_password(plain_password)

        try:
            obj.full_clean()
            obj.save()
        except ValidationError as exc:
            self.stderr.write("Validation failed: %s" % str(exc))
            sys.exit(1)
        except DatabaseError as exc:
            self.stderr.write("Could not create service user: %s" % str(exc))
            sys.exit(1)

        self.stderr.write(self.style.SUCCESS("Created service user %s for %s" % (obj.username, user_obj.identifier)))
        self.stdout.write(plain_password)

    def _edit(self, **options: Any) -> None:
        items = self._select_service_users(require_selector=True, **options)
        if not items:
            self.stderr.write("No matching service users found.")
            sys.exit(1)

        mutating = any([
            options.get("set_description") is not None,
            options.get("set_password") is not None,
            options.get("set_username") is not None,
            options.get("set_user") is not None,
        ])
        if not mutating:
            self.stderr.write("No changes requested.")
            sys.exit(1)

        if options.get("set_username") is not None and len(items) > 1:
            self.stderr.write("--set-username can only be used when exactly one service user is selected.")
            sys.exit(1)

        new_user = None
        if options.get("set_user") is not None:
            try:
                new_user = resolve_user(options["set_user"])
            except ValueError as exc:
                self.stderr.write(str(exc))
                sys.exit(1)

        if len(items) > 1 and not options["approved"]:
            self._render(items, "table")
            if not ask_for_confirmation("Apply changes to %s service users? [y/N]" % len(items), default=False):
                sys.exit(1)

        with transaction.atomic():
            for item in items:
                if options.get("set_description") is not None:
                    item.description = options["set_description"]
                if options.get("set_password") is not None:
                    item.set_password(options["set_password"])
                if options.get("set_username") is not None:
                    item.username = options["set_username"]
                if new_user is not None:
                    item.user = new_user
                try:
                    item.full_clean()
                    item.save()
                except ValidationError as exc:
                    self.stderr.write("Validation failed: %s" % str(exc))
                    sys.exit(1)
                except DatabaseError as exc:
                    self.stderr.write("Could not update service user %s: %s" % (item.pk, str(exc)))
                    sys.exit(1)

        self.stderr.write(self.style.SUCCESS("Edited %s service user(s)." % len(items)))

    def _remove(self, **options: Any) -> None:
        items = self._select_service_users(require_selector=True, **options)
        if not items:
            self.stderr.write("No matching service users found.")
            sys.exit(1)

        if not options["approved"]:
            self._render(items, "table")
            if not ask_for_confirmation("Delete %s service users? [y/N]" % len(items), default=False):
                sys.exit(1)

        try:
            deleted_count, _ = models.MNServiceUser.objects.filter(pk__in=[obj.pk for obj in items]).delete()
        except DatabaseError as exc:
            self.stderr.write("Could not remove service users: %s" % str(exc))
            sys.exit(1)

        self.stderr.write(self.style.SUCCESS("Deleted %s service user row(s)." % deleted_count))

    def handle(self, *args: Any, **options: Any) -> None:
        if options["scmd"] == "create":
            self._create(**options)
        elif options["scmd"] == "list":
            self._render(self._select_service_users(**options), options["format"])
        elif options["scmd"] == "show":
            self._render(self._select_service_users(require_selector=True, **options), options["format"])
        elif options["scmd"] == "edit":
            self._edit(**options)
        elif options["scmd"] == "remove":
            self._remove(**options)
        else:
            self.stderr.write("Please specify a command.")
            self.stderr.write("Use django-admin.py serviceuser --settings=authserver.settings --help to get help.")
