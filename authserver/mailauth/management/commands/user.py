import argparse
import json
import sys
import uuid
from typing import Any, Dict, List, Optional

from django.core.exceptions import ValidationError
from django.core.management.base import BaseCommand, CommandParser
from django.db import DatabaseError, transaction
from django.db.models import Q

from mailauth import models
from mailauth.management.commands._common import table_left_format_str
from mailauth.management.commands._mgmt_helpers import ask_for_confirmation, parse_alias_address, resolve_domain, resolve_user


class Command(BaseCommand):
    requires_migrations_checks = True

    def add_arguments(self, parser: CommandParser) -> None:
        class SubCommandParser(CommandParser):
            def __init__(self, **kwargs: Any) -> None:
                super().__init__(**kwargs)

        subparsers = parser.add_subparsers(dest="scmd", title="subcommands", parser_class=SubCommandParser)

        create_sp = subparsers.add_parser("create", help="Create user")
        create_sp.add_argument("identifier")
        create_sp.add_argument("fullname")
        create_sp.add_argument("--password", dest="password", default=None)
        create_sp.add_argument("--staff", dest="is_staff", action="store_true", default=False)

        list_sp = subparsers.add_parser("list", help="List users")
        self._add_selector_args(list_sp)
        list_sp.add_argument("-f", "--format", dest="format", choices=["table", "json"], default="table")

        show_sp = subparsers.add_parser("show", help="Show users")
        self._add_selector_args(show_sp)
        show_sp.add_argument("-f", "--format", dest="format", choices=["table", "json"], default="table")

        edit_sp = subparsers.add_parser("edit", help="Edit users")
        self._add_selector_args(edit_sp)
        edit_sp.add_argument("--set-fullname", dest="set_fullname", default=None)
        edit_sp.add_argument("--set-identifier", dest="set_identifier", default=None)
        edit_sp.add_argument("--set-password", dest="set_password", default=None)
        edit_sp.add_argument("--set-staff", dest="set_staff", action="store_true", default=False)
        edit_sp.add_argument("--unset-staff", dest="unset_staff", action="store_true", default=False)
        edit_sp.add_argument("-y", "--yes", dest="approved", action="store_true", default=False)

        activate_sp = subparsers.add_parser("activate", help="Set is_active=True")
        self._add_selector_args(activate_sp)
        activate_sp.add_argument("-y", "--yes", dest="approved", action="store_true", default=False)

        deactivate_sp = subparsers.add_parser("deactivate", help="Set is_active=False")
        self._add_selector_args(deactivate_sp)
        deactivate_sp.add_argument("-y", "--yes", dest="approved", action="store_true", default=False)

        set_delivery_sp = subparsers.add_parser("set-delivery-mailbox", help="Set delivery mailbox for users")
        self._add_selector_args(set_delivery_sp)
        set_delivery_sp.add_argument("alias", help="Alias in local@domain form")
        set_delivery_sp.add_argument("-y", "--yes", dest="approved", action="store_true", default=False)

        remove_sp = subparsers.add_parser("remove", help="Remove users")
        self._add_selector_args(remove_sp)
        remove_sp.add_argument("-y", "--yes", dest="approved", action="store_true", default=False)

    def _add_selector_args(self, parser: CommandParser) -> None:
        parser.add_argument("selectors", nargs="*", help="User selectors: UUID, identifier, or resolvable alias")
        parser.add_argument("-c", "--contains", dest="contains", default=None)
        parser.add_argument("--active", dest="active", action="store_true", default=False)
        parser.add_argument("--inactive", dest="inactive", action="store_true", default=False)

    def _to_dict(self, user: models.MNUser) -> Dict[str, Any]:
        delivery = None
        if user.delivery_mailbox is not None:
            delivery = "%s@%s" % (user.delivery_mailbox.mailprefix, user.delivery_mailbox.domain.name)
        return {
            "uuid": str(user.uuid),
            "identifier": user.identifier,
            "fullname": user.fullname,
            "delivery_mailbox": delivery,
            "is_active": user.is_active,
            "is_staff": user.is_staff,
        }

    def _render(self, users: List[models.MNUser], format: str) -> None:
        if format == "json":
            print(json.dumps([self._to_dict(user) for user in users]))
            return

        if not users:
            self.stderr.write("No matching users found.")
            sys.exit(1)

        fmtstr = table_left_format_str([user.identifier for user in users])
        print(fmtstr.format("IDENTIFIER", "UUID [ACTIVE/STAFF]"))
        print("-" * 78)
        for user in users:
            print(fmtstr.format(user.identifier, "%s [%s/%s]" % (
                user.uuid,
                "yes" if user.is_active else "no",
                "yes" if user.is_staff else "no",
            )))

    def _select_users(self, require_selector: bool = False, **options: Any) -> List[models.MNUser]:
        query = Q()
        used = False

        selectors = options.get("selectors") or []
        if selectors:
            sq = Q()
            for selector in selectors:
                try:
                    parsed = uuid.UUID(selector)
                except ValueError:
                    try:
                        user = resolve_user(selector)
                    except ValueError:
                        sq |= Q(identifier__iexact=selector)
                    else:
                        sq |= Q(pk=user.pk)
                else:
                    sq |= Q(pk=parsed)
            query &= sq
            used = True

        if options.get("contains"):
            query &= (Q(identifier__icontains=options["contains"]) | Q(fullname__icontains=options["contains"]))
            used = True

        if options.get("active"):
            query &= Q(is_active=True)
            used = True
        if options.get("inactive"):
            query &= Q(is_active=False)
            used = True

        if require_selector and not used:
            self.stderr.write("You must provide at least one selector.")
            sys.exit(1)

        return list(models.MNUser.objects.filter(query).select_related("delivery_mailbox", "delivery_mailbox__domain"))

    def _create(self, identifier: str, fullname: str, password: Optional[str] = None,
                is_staff: bool = False, **kwargs: Any) -> None:
        try:
            user = models.MNUser.objects.create_user(identifier=identifier, fullname=fullname, password=password,
                                                     is_staff=is_staff)
        except DatabaseError as exc:
            self.stderr.write("Could not create user: %s" % str(exc))
            sys.exit(1)

        self.stderr.write(self.style.SUCCESS("Created user %s (%s)" % (user.identifier, user.uuid)))

    def _edit(self, **options: Any) -> None:
        users = self._select_users(require_selector=True, **options)
        if not users:
            self.stderr.write("No matching users found.")
            sys.exit(1)

        if options["set_staff"] and options["unset_staff"]:
            self.stderr.write("You can't pass both --set-staff and --unset-staff")
            sys.exit(1)

        mutating = any([
            options.get("set_fullname") is not None,
            options.get("set_identifier") is not None,
            options.get("set_password") is not None,
            options["set_staff"],
            options["unset_staff"],
        ])
        if not mutating:
            self.stderr.write("No changes requested.")
            sys.exit(1)

        if len(users) > 1 and options.get("set_identifier") is not None:
            self.stderr.write("--set-identifier can only be used with a single user selection.")
            sys.exit(1)

        if len(users) > 1 and not options["approved"]:
            self._render(users, "table")
            if not ask_for_confirmation("Apply changes to %s users? [y/N]" % len(users), default=False):
                sys.exit(1)

        with transaction.atomic():
            for user in users:
                if options.get("set_fullname") is not None:
                    user.fullname = options["set_fullname"]
                if options.get("set_identifier") is not None:
                    user.identifier = options["set_identifier"]
                if options.get("set_password") is not None:
                    user.set_password(options["set_password"])
                if options["set_staff"]:
                    user.is_staff = True
                if options["unset_staff"]:
                    user.is_staff = False

                try:
                    user.full_clean()
                    user.save()
                except ValidationError as exc:
                    self.stderr.write("Validation failed: %s" % str(exc))
                    sys.exit(1)
                except DatabaseError as exc:
                    self.stderr.write("Could not update user %s: %s" % (user.identifier, str(exc)))
                    sys.exit(1)

        self.stderr.write(self.style.SUCCESS("Edited %s user(s)." % len(users)))

    def _set_active(self, set_active: bool, **options: Any) -> None:
        users = self._select_users(require_selector=True, **options)
        if not users:
            self.stderr.write("No matching users found.")
            sys.exit(1)

        if len(users) > 1 and not options["approved"]:
            self._render(users, "table")
            if not ask_for_confirmation("Set is_active=%s on %s users? [y/N]" % (str(set_active), len(users)), default=False):
                sys.exit(1)

        try:
            models.MNUser.objects.filter(pk__in=[user.pk for user in users]).update(is_active=set_active)
        except DatabaseError as exc:
            self.stderr.write("Could not update users: %s" % str(exc))
            sys.exit(1)

        self.stderr.write(self.style.SUCCESS("Updated active flag for %s users." % len(users)))

    def _set_delivery_mailbox(self, alias: str, **options: Any) -> None:
        users = self._select_users(require_selector=True, **options)
        if not users:
            self.stderr.write("No matching users found.")
            sys.exit(1)
        if len(users) != 1:
            self.stderr.write("set-delivery-mailbox requires selecting exactly one user.")
            sys.exit(1)

        try:
            mailprefix, domain_name = parse_alias_address(alias)
            domain = resolve_domain(domain_name)
        except ValueError as exc:
            self.stderr.write(str(exc))
            sys.exit(1)

        try:
            alias_obj = models.EmailAlias.objects.get(mailprefix__iexact=mailprefix, domain=domain)
        except models.EmailAlias.DoesNotExist:
            self.stderr.write("Alias not found: %s" % alias)
            sys.exit(1)

        user = users[0]
        if alias_obj.user_id is not None and alias_obj.user_id != user.pk:
            self.stderr.write("Alias %s belongs to another user and can't be used as this user's delivery mailbox." % alias)
            sys.exit(1)

        user.delivery_mailbox = alias_obj
        try:
            user.full_clean()
            user.save()
        except ValidationError as exc:
            self.stderr.write("Validation failed: %s" % str(exc))
            sys.exit(1)
        except DatabaseError as exc:
            self.stderr.write("Could not update user %s: %s" % (user.identifier, str(exc)))
            sys.exit(1)

        self.stderr.write(self.style.SUCCESS("Set delivery mailbox for user %s." % user.identifier))

    def _remove(self, **options: Any) -> None:
        users = self._select_users(require_selector=True, **options)
        if not users:
            self.stderr.write("No matching users found.")
            sys.exit(1)

        if not options["approved"]:
            self._render(users, "table")
            if not ask_for_confirmation("Delete %s users? [y/N]" % len(users), default=False):
                sys.exit(1)

        try:
            deleted_count, _ = models.MNUser.objects.filter(pk__in=[user.pk for user in users]).delete()
        except DatabaseError as exc:
            self.stderr.write("Could not remove users: %s" % str(exc))
            sys.exit(1)

        self.stderr.write(self.style.SUCCESS("Deleted %s user row(s)." % deleted_count))

    def handle(self, *args: Any, **options: Any) -> None:
        if options["scmd"] == "create":
            self._create(**options)
        elif options["scmd"] == "list":
            self._render(self._select_users(**options), options["format"])
        elif options["scmd"] == "show":
            self._render(self._select_users(require_selector=True, **options), options["format"])
        elif options["scmd"] == "edit":
            self._edit(**options)
        elif options["scmd"] == "activate":
            self._set_active(True, **options)
        elif options["scmd"] == "deactivate":
            self._set_active(False, **options)
        elif options["scmd"] == "set-delivery-mailbox":
            self._set_delivery_mailbox(**options)
        elif options["scmd"] == "remove":
            self._remove(**options)
        else:
            self.stderr.write("Please specify a command.")
            self.stderr.write("Use django-admin.py user --settings=authserver.settings --help to get help.")
