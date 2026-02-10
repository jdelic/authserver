import argparse
import json
import sys
from typing import Any, Dict, List

from django.core.exceptions import ValidationError
from django.core.management.base import BaseCommand, CommandParser
from django.db import DatabaseError, transaction
from django.db.models import Q

from mailauth import models
from mailauth.management.commands._common import table_left_format_str
from mailauth.management.commands._mgmt_helpers import ask_for_confirmation, resolve_mailing_list


class Command(BaseCommand):
    requires_migrations_checks = True

    def add_arguments(self, parser: CommandParser) -> None:
        class SubCommandParser(CommandParser):
            def __init__(self, **kwargs: Any) -> None:
                super().__init__(**kwargs)

        subparsers = parser.add_subparsers(dest="scmd", title="subcommands", parser_class=SubCommandParser)

        create_sp = subparsers.add_parser("create", help="Create mailing list")
        create_sp.add_argument("name")
        create_sp.add_argument("addresses", nargs="*")
        create_sp.add_argument("--new-mailfrom", dest="new_mailfrom", default="")

        list_sp = subparsers.add_parser("list", help="List mailing lists")
        self._add_selector_args(list_sp)
        list_sp.add_argument("-f", "--format", dest="format", choices=["table", "json"], default="table")

        show_sp = subparsers.add_parser("show", help="Show mailing list")
        self._add_selector_args(show_sp)
        show_sp.add_argument("-f", "--format", dest="format", choices=["table", "json"], default="table")

        edit_sp = subparsers.add_parser("edit", help="Edit mailing list")
        self._add_selector_args(edit_sp)
        edit_sp.add_argument("--set-name", dest="set_name", default=None)
        edit_sp.add_argument("--set-new-mailfrom", dest="set_new_mailfrom", default=None)
        edit_sp.add_argument("-y", "--yes", dest="approved", action="store_true", default=False)

        remove_sp = subparsers.add_parser("remove", help="Remove mailing list")
        self._add_selector_args(remove_sp)
        remove_sp.add_argument("-y", "--yes", dest="approved", action="store_true", default=False)

        add_addr_sp = subparsers.add_parser("add-address", help="Add addresses to a mailing list")
        add_addr_sp.add_argument("-m", "--mailing-list", dest="mailing_list", required=True)
        add_addr_sp.add_argument("addresses", nargs="+", help="Addresses or '-' to read from stdin")

        remove_addr_sp = subparsers.add_parser("remove-address", help="Remove addresses from a mailing list")
        remove_addr_sp.add_argument("-m", "--mailing-list", dest="mailing_list", required=True)
        remove_addr_sp.add_argument("addresses", nargs="+", help="Addresses or '-' to read from stdin")

        set_addr_sp = subparsers.add_parser("set-addresses", help="Replace addresses of a mailing list")
        set_addr_sp.add_argument("-m", "--mailing-list", dest="mailing_list", required=True)
        set_addr_sp.add_argument("addresses", nargs="+", help="Addresses or '-' to read from stdin")

    def _add_selector_args(self, parser: CommandParser) -> None:
        parser.add_argument("selectors", nargs="*", help="List id or name")
        parser.add_argument("-c", "--contains", dest="contains", default=None)

    def _read_addresses(self, values: List[str]) -> List[str]:
        result = []  # type: List[str]
        for value in values:
            if value == "-":
                for line in sys.stdin:
                    line = line.strip()
                    if line:
                        result.append(line)
            else:
                result.append(value)
        return result

    def _to_dict(self, mailing_list: models.MailingList) -> Dict[str, Any]:
        return {
            "id": mailing_list.pk,
            "name": mailing_list.name,
            "new_mailfrom": mailing_list.new_mailfrom,
            "addresses": mailing_list.addresses,
        }

    def _render(self, lists: List[models.MailingList], format: str) -> None:
        if format == "json":
            print(json.dumps([self._to_dict(item) for item in lists]))
            return

        if not lists:
            self.stderr.write("No mailing lists found.")
            sys.exit(1)

        fmtstr = table_left_format_str([str(item.pk) for item in lists])
        print(fmtstr.format("ID", "NAME (ADDR COUNT)"))
        print("-" * 78)
        for item in lists:
            print(fmtstr.format(str(item.pk), "%s (%s)" % (item.name, len(item.addresses))))

    def _select_lists(self, require_selector: bool = False, **options: Any) -> List[models.MailingList]:
        query = Q()
        used = False

        selectors = options.get("selectors") or []
        if selectors:
            sq = Q()
            for selector in selectors:
                try:
                    sid = int(selector)
                except ValueError:
                    sq |= Q(name__iexact=selector)
                else:
                    sq |= Q(pk=sid)
            query &= sq
            used = True

        contains = options.get("contains")
        if contains:
            query &= Q(name__icontains=contains)
            used = True

        if require_selector and not used:
            self.stderr.write("You must pass at least one selector.")
            sys.exit(1)

        return list(models.MailingList.objects.filter(query))

    def _create(self, name: str, addresses: List[str], new_mailfrom: str = "", **kwargs: Any) -> None:
        addresses = self._read_addresses(addresses)
        obj = models.MailingList(name=name, addresses=addresses, new_mailfrom=new_mailfrom)
        try:
            obj.full_clean()
            obj.save()
        except ValidationError as exc:
            self.stderr.write("Validation failed: %s" % str(exc))
            sys.exit(1)
        except DatabaseError as exc:
            self.stderr.write("Could not create mailing list: %s" % str(exc))
            sys.exit(1)

        self.stderr.write(self.style.SUCCESS("Created mailing list %s (%s)" % (obj.name, obj.pk)))

    def _edit(self, **options: Any) -> None:
        items = self._select_lists(require_selector=True, **options)
        if not items:
            self.stderr.write("No matching mailing lists found.")
            sys.exit(1)

        if options.get("set_name") is None and options.get("set_new_mailfrom") is None:
            self.stderr.write("No changes requested.")
            sys.exit(1)

        if len(items) > 1 and not options["approved"]:
            self._render(items, "table")
            if not ask_for_confirmation("Apply edit to %s mailing lists? [y/N]" % len(items), default=False):
                sys.exit(1)

        with transaction.atomic():
            for item in items:
                if options.get("set_name") is not None:
                    item.name = options["set_name"]
                if options.get("set_new_mailfrom") is not None:
                    item.new_mailfrom = options["set_new_mailfrom"]
                try:
                    item.full_clean()
                    item.save()
                except ValidationError as exc:
                    self.stderr.write("Validation failed: %s" % str(exc))
                    sys.exit(1)
                except DatabaseError as exc:
                    self.stderr.write("Could not update mailing list %s: %s" % (item.pk, str(exc)))
                    sys.exit(1)

        self.stderr.write(self.style.SUCCESS("Edited %s mailing list(s)." % len(items)))

    def _remove(self, **options: Any) -> None:
        items = self._select_lists(require_selector=True, **options)
        if not items:
            self.stderr.write("No matching mailing lists found.")
            sys.exit(1)

        if not options["approved"]:
            self._render(items, "table")
            if not ask_for_confirmation("Delete %s mailing list(s)? [y/N]" % len(items), default=False):
                sys.exit(1)

        try:
            deleted_count, _ = models.MailingList.objects.filter(pk__in=[x.pk for x in items]).delete()
        except DatabaseError as exc:
            self.stderr.write("Could not remove mailing lists: %s" % str(exc))
            sys.exit(1)

        self.stderr.write(self.style.SUCCESS("Deleted %s mailing list row(s)." % deleted_count))

    def _add_address(self, mailing_list: str, addresses: List[str], **kwargs: Any) -> None:
        try:
            obj = resolve_mailing_list(mailing_list)
        except ValueError as exc:
            self.stderr.write(str(exc))
            sys.exit(1)

        to_add = self._read_addresses(addresses)
        addr_set = set(obj.addresses)
        addr_set.update(to_add)
        obj.addresses = list(addr_set)

        try:
            obj.full_clean()
            obj.save()
        except ValidationError as exc:
            self.stderr.write("Validation failed: %s" % str(exc))
            sys.exit(1)

        self.stderr.write(self.style.SUCCESS("Added %s address(es) to list %s" % (len(to_add), obj.name)))

    def _remove_address(self, mailing_list: str, addresses: List[str], **kwargs: Any) -> None:
        try:
            obj = resolve_mailing_list(mailing_list)
        except ValueError as exc:
            self.stderr.write(str(exc))
            sys.exit(1)

        to_remove = set(self._read_addresses(addresses))
        obj.addresses = [address for address in obj.addresses if address not in to_remove]

        try:
            obj.full_clean()
            obj.save()
        except ValidationError as exc:
            self.stderr.write("Validation failed: %s" % str(exc))
            sys.exit(1)

        self.stderr.write(self.style.SUCCESS("Removed addresses from list %s" % obj.name))

    def _set_addresses(self, mailing_list: str, addresses: List[str], **kwargs: Any) -> None:
        try:
            obj = resolve_mailing_list(mailing_list)
        except ValueError as exc:
            self.stderr.write(str(exc))
            sys.exit(1)

        obj.addresses = self._read_addresses(addresses)
        try:
            obj.full_clean()
            obj.save()
        except ValidationError as exc:
            self.stderr.write("Validation failed: %s" % str(exc))
            sys.exit(1)

        self.stderr.write(self.style.SUCCESS("Replaced addresses on list %s" % obj.name))

    def handle(self, *args: Any, **options: Any) -> None:
        if options["scmd"] == "create":
            self._create(**options)
        elif options["scmd"] == "list":
            self._render(self._select_lists(**options), options["format"])
        elif options["scmd"] == "show":
            self._render(self._select_lists(require_selector=True, **options), options["format"])
        elif options["scmd"] == "edit":
            self._edit(**options)
        elif options["scmd"] == "remove":
            self._remove(**options)
        elif options["scmd"] == "add-address":
            self._add_address(**options)
        elif options["scmd"] == "remove-address":
            self._remove_address(**options)
        elif options["scmd"] == "set-addresses":
            self._set_addresses(**options)
        else:
            self.stderr.write("Please specify a command.")
            self.stderr.write("Use django-admin.py mailinglist --settings=authserver.settings --help to get help.")
