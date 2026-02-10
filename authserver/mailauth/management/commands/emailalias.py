import argparse
import json
import sys
from typing import Any, Dict, List, Optional

from django.core.management.base import BaseCommand, CommandParser
from django.core.exceptions import ValidationError
from django.db import DatabaseError, transaction
from django.db.models import Q

from mailauth import models
from mailauth.management.commands._common import table_left_format_str
from mailauth.management.commands._mgmt_helpers import (
    ask_for_confirmation,
    fail_with_validation_error,
    parse_alias_address,
    parse_bool_flag,
    resolve_domain,
    resolve_mailing_list,
    resolve_user,
)


class Command(BaseCommand):
    requires_migrations_checks = True

    def add_arguments(self, parser: CommandParser) -> None:
        class SubCommandParser(CommandParser):
            def __init__(self, **kwargs: Any) -> None:
                super().__init__(**kwargs)

        subparsers = parser.add_subparsers(
            dest="scmd",
            title="subcommands",
            parser_class=SubCommandParser,
        )  # type: argparse._SubParsersAction

        list_sp = subparsers.add_parser("list", help="List email aliases")
        self._add_selector_arguments(list_sp)
        list_sp.add_argument("-f", "--format", dest="format", choices=["table", "json"], default="table")

        show_sp = subparsers.add_parser("show", help="Show email aliases")
        self._add_selector_arguments(show_sp)
        show_sp.add_argument("-f", "--format", dest="format", choices=["table", "json"], default="table")

        create_sp = subparsers.add_parser("create", help="Create email aliases")
        create_sp.add_argument("alias", nargs="?", help="Alias address in local@domain form")
        create_sp.add_argument("--mailprefix", dest="mailprefix", default=None)
        create_sp.add_argument("-d", "--domain", dest="domain", default=None)
        create_target = create_sp.add_mutually_exclusive_group(required=True)
        create_target.add_argument("-u", "--user", dest="user", default=None,
                                   help="User identifier or primary delivery email")
        create_target.add_argument("-m", "--mailing-list", dest="mailing_list", default=None,
                                   help="Mailing list id or name")
        create_sp.add_argument("--blacklisted", dest="blacklisted", action="store_true", default=False)

        edit_sp = subparsers.add_parser("edit", help="Edit email aliases")
        self._add_selector_arguments(edit_sp)
        edit_sp.add_argument("--set-user", dest="set_user", default=None)
        edit_sp.add_argument("--set-mailing-list", dest="set_mailing_list", default=None)
        edit_sp.add_argument("--set-mailprefix", dest="set_mailprefix", default=None)
        edit_sp.add_argument("--set-domain", dest="set_domain", default=None)
        edit_sp.add_argument("--set-blacklisted", dest="set_blacklisted", action="store_true", default=False)
        edit_sp.add_argument("--unset-blacklisted", dest="unset_blacklisted", action="store_true", default=False)
        edit_sp.add_argument("-y", "--yes", dest="approved", action="store_true", default=False)

        remove_sp = subparsers.add_parser("remove", help="Remove email aliases")
        self._add_selector_arguments(remove_sp)
        remove_sp.add_argument("-y", "--yes", dest="approved", action="store_true", default=False)

        blacklist_sp = subparsers.add_parser("blacklist", help="Set blacklisted=True")
        blacklist_sp.add_argument("aliases", nargs="+", help="Alias addresses local@domain")
        blacklist_sp.add_argument("--create-if-missing", dest="create_missing", action="store_true", default=False)
        blacklist_target = blacklist_sp.add_mutually_exclusive_group(required=False)
        blacklist_target.add_argument("-u", "--user", dest="user", default=None,
                                      help="User identifier or primary delivery email")
        blacklist_target.add_argument("-m", "--mailing-list", dest="mailing_list", default=None,
                                      help="Mailing list id or name")

        unblacklist_sp = subparsers.add_parser("unblacklist", help="Set blacklisted=False")
        self._add_selector_arguments(unblacklist_sp)
        unblacklist_sp.add_argument("-y", "--yes", dest="approved", action="store_true", default=False)

    def _add_selector_arguments(self, parser: CommandParser) -> None:
        parser.add_argument("aliases", nargs="*", help="Alias addresses local@domain")
        parser.add_argument("--mailprefix", dest="mailprefix", default=None)
        parser.add_argument("-d", "--domain", dest="domain", default=None)
        parser.add_argument("-c", "--contains", dest="contains", default=None)
        parser.add_argument("-u", "--user", dest="user", default=None)
        parser.add_argument("-m", "--mailing-list", dest="mailing_list", default=None)
        parser.add_argument("--blacklisted", dest="blacklisted", action="store_true", default=False)
        parser.add_argument("--not-blacklisted", dest="not_blacklisted", action="store_true", default=False)

    def _alias_to_dict(self, alias: models.EmailAlias) -> Dict[str, Any]:
        target_type = ""
        target_value = ""
        if alias.user is not None:
            target_type = "user"
            target_value = alias.user.identifier
        elif alias.forward_to is not None:
            target_type = "mailing-list"
            target_value = alias.forward_to.name

        return {
            "id": alias.pk,
            "alias": "%s@%s" % (alias.mailprefix, alias.domain.name),
            "mailprefix": alias.mailprefix,
            "domain": alias.domain.name,
            "target_type": target_type,
            "target": target_value,
            "blacklisted": alias.blacklisted,
        }

    def _render_aliases(self, aliases: List[models.EmailAlias], format: str) -> None:
        if format == "json":
            print(json.dumps([self._alias_to_dict(a) for a in aliases]))
            return

        if not aliases:
            self.stderr.write("No matching aliases found.")
            sys.exit(1)

        fmtstr = table_left_format_str(["%s@%s" % (a.mailprefix, a.domain.name) for a in aliases])
        print(fmtstr.format("ALIAS", "TARGET (TYPE) [BLACKLISTED]"))
        print("-" * 78)
        for alias in aliases:
            d = self._alias_to_dict(alias)
            print(fmtstr.format(
                d["alias"],
                "%s (%s) [%s]" % (d["target"], d["target_type"], "yes" if d["blacklisted"] else "no")
            ))

    def _resolve_alias_components(self, alias: Optional[str], mailprefix: Optional[str], domain: Optional[str]) -> Any:
        if alias is not None:
            return parse_alias_address(alias)
        if mailprefix is not None and domain is not None:
            return mailprefix, domain
        self.stderr.write("You must provide alias as local@domain or provide both --mailprefix and --domain")
        sys.exit(1)

    def _select_aliases(self, require_selector: bool = False, **options: Any) -> List[models.EmailAlias]:
        query = Q()
        filters_used = False

        aliases = options.get("aliases") or []
        if aliases:
            address_query = Q()
            for address in aliases:
                try:
                    mailprefix, domain = parse_alias_address(address)
                except ValueError as exc:
                    self.stderr.write(str(exc))
                    sys.exit(1)
                address_query |= Q(mailprefix__iexact=mailprefix, domain__name__iexact=domain)
            query &= address_query
            filters_used = True

        if options.get("mailprefix"):
            query &= Q(mailprefix__iexact=options["mailprefix"])
            filters_used = True

        if options.get("domain"):
            query &= Q(domain__name__iexact=options["domain"])
            filters_used = True

        if options.get("contains"):
            query &= (Q(mailprefix__icontains=options["contains"]) | Q(domain__name__icontains=options["contains"]))
            filters_used = True

        if options.get("user"):
            try:
                user = resolve_user(options["user"])
            except ValueError as exc:
                self.stderr.write(str(exc))
                sys.exit(1)
            query &= Q(user=user)
            filters_used = True

        if options.get("mailing_list"):
            try:
                mlist = resolve_mailing_list(options["mailing_list"])
            except ValueError as exc:
                self.stderr.write(str(exc))
                sys.exit(1)
            query &= Q(forward_to=mlist)
            filters_used = True

        if options.get("blacklisted"):
            query &= Q(blacklisted=True)
            filters_used = True

        if options.get("not_blacklisted"):
            query &= Q(blacklisted=False)
            filters_used = True

        if require_selector and not filters_used:
            self.stderr.write("You must specify at least one selector for this command.")
            sys.exit(1)

        qs = models.EmailAlias.objects.filter(query).select_related("domain", "user", "forward_to")
        return list(qs)

    def _create(self, **options: Any) -> None:
        mailprefix, domain_name = self._resolve_alias_components(options["alias"], options["mailprefix"], options["domain"])

        try:
            domain = resolve_domain(domain_name)
        except ValueError as exc:
            self.stderr.write(str(exc))
            sys.exit(1)

        target_user = None
        target_list = None
        try:
            if options.get("user"):
                target_user = resolve_user(options["user"])
            elif options.get("mailing_list"):
                target_list = resolve_mailing_list(options["mailing_list"])
        except ValueError as exc:
            self.stderr.write(str(exc))
            sys.exit(1)

        alias = models.EmailAlias(
            mailprefix=mailprefix,
            domain=domain,
            user=target_user,
            forward_to=target_list,
            blacklisted=options["blacklisted"],
        )

        try:
            alias.full_clean()
            alias.save()
        except ValidationError as exc:
            fail_with_validation_error("Validation failed", exc)
        except DatabaseError as exc:
            self.stderr.write("Error while creating alias: %s" % str(exc))
            sys.exit(1)

        self.stderr.write(self.style.SUCCESS("Created alias %s@%s" % (alias.mailprefix, alias.domain.name)))

    def _edit(self, **options: Any) -> None:
        aliases = self._select_aliases(require_selector=True, **options)
        if not aliases:
            self.stderr.write("No matching aliases found.")
            sys.exit(1)

        bl_update = None
        try:
            bl_update = parse_bool_flag(options["set_blacklisted"], options["unset_blacklisted"], "blacklisted")
        except ValueError as exc:
            self.stderr.write(str(exc))
            sys.exit(1)

        mutating = any([
            options.get("set_user") is not None,
            options.get("set_mailing_list") is not None,
            options.get("set_mailprefix") is not None,
            options.get("set_domain") is not None,
            bl_update is not None,
        ])
        if not mutating:
            self.stderr.write("No changes requested. Use --set-* options.")
            sys.exit(1)

        if options.get("set_user") and options.get("set_mailing_list"):
            self.stderr.write("You can't set both --set-user and --set-mailing-list")
            sys.exit(1)

        new_user = None
        new_list = None
        if options.get("set_user"):
            try:
                new_user = resolve_user(options["set_user"])
            except ValueError as exc:
                self.stderr.write(str(exc))
                sys.exit(1)
        if options.get("set_mailing_list"):
            try:
                new_list = resolve_mailing_list(options["set_mailing_list"])
            except ValueError as exc:
                self.stderr.write(str(exc))
                sys.exit(1)

        new_domain = None
        if options.get("set_domain"):
            try:
                new_domain = resolve_domain(options["set_domain"])
            except ValueError as exc:
                self.stderr.write(str(exc))
                sys.exit(1)

        if len(aliases) > 1 and not options["approved"]:
            self._render_aliases(aliases, "table")
            if not ask_for_confirmation("Apply edit to %s aliases? [y/N]" % len(aliases), default=False):
                sys.exit(1)

        with transaction.atomic():
            for alias in aliases:
                if new_user is not None:
                    alias.user = new_user
                    alias.forward_to = None
                if new_list is not None:
                    alias.forward_to = new_list
                    alias.user = None
                if options.get("set_mailprefix"):
                    alias.mailprefix = options["set_mailprefix"]
                if new_domain is not None:
                    alias.domain = new_domain
                if bl_update is not None:
                    alias.blacklisted = bl_update

                try:
                    alias.full_clean()
                    alias.save()
                except ValidationError as exc:
                    fail_with_validation_error("Validation failed for alias %s" % alias.pk, exc)
                except DatabaseError as exc:
                    self.stderr.write("Error while editing alias %s: %s" % (alias.pk, str(exc)))
                    sys.exit(1)

        self.stderr.write(self.style.SUCCESS("Edited %s alias(es)." % len(aliases)))

    def _remove(self, **options: Any) -> None:
        aliases = self._select_aliases(require_selector=True, **options)
        if not aliases:
            self.stderr.write("No matching aliases found.")
            sys.exit(1)

        if not options["approved"]:
            self._render_aliases(aliases, "table")
            if not ask_for_confirmation("Delete %s aliases? [y/N]" % len(aliases), default=False):
                sys.exit(1)

        try:
            deleted_count, _ = models.EmailAlias.objects.filter(pk__in=[a.pk for a in aliases]).delete()
        except DatabaseError as exc:
            self.stderr.write("Error while deleting aliases: %s" % str(exc))
            sys.exit(1)

        self.stderr.write(self.style.SUCCESS("Deleted %s alias row(s)." % deleted_count))

    def _blacklist(self, aliases: List[str], create_missing: bool = False, user: str = None,
                   mailing_list: str = None, **kwargs: Any) -> None:
        if create_missing and not user and not mailing_list:
            self.stderr.write("--create-if-missing requires --user/-u or --mailing-list/-m")
            sys.exit(1)

        resolved_user = None
        resolved_list = None

        try:
            if user:
                resolved_user = resolve_user(user)
            if mailing_list:
                resolved_list = resolve_mailing_list(mailing_list)
        except ValueError as exc:
            self.stderr.write(str(exc))
            sys.exit(1)

        updated = 0
        created = 0

        with transaction.atomic():
            for address in aliases:
                try:
                    mailprefix, domain_name = parse_alias_address(address)
                except ValueError as exc:
                    self.stderr.write(str(exc))
                    sys.exit(1)

                existing = models.EmailAlias.objects.filter(
                    mailprefix__iexact=mailprefix,
                    domain__name__iexact=domain_name,
                ).select_related("domain").first()

                if existing is not None:
                    existing.blacklisted = True
                    try:
                        existing.full_clean()
                        existing.save()
                    except ValidationError as exc:
                        fail_with_validation_error("Validation failed for alias %s" % address, exc)
                    except DatabaseError as exc:
                        self.stderr.write("Error while updating alias %s: %s" % (address, str(exc)))
                        sys.exit(1)
                    updated += 1
                    continue

                if not create_missing:
                    self.stderr.write("Alias not found: %s" % address)
                    sys.exit(1)

                try:
                    domain = resolve_domain(domain_name)
                except ValueError as exc:
                    self.stderr.write(str(exc))
                    sys.exit(1)

                alias = models.EmailAlias(
                    mailprefix=mailprefix,
                    domain=domain,
                    user=resolved_user,
                    forward_to=resolved_list,
                    blacklisted=True,
                )
                try:
                    alias.full_clean()
                    alias.save()
                except ValidationError as exc:
                    fail_with_validation_error("Validation failed for alias %s" % address, exc)
                except DatabaseError as exc:
                    self.stderr.write("Error while creating alias %s: %s" % (address, str(exc)))
                    sys.exit(1)
                created += 1

        self.stderr.write(self.style.SUCCESS("Blacklisted aliases: updated=%s created=%s" % (updated, created)))

    def _unblacklist(self, **options: Any) -> None:
        aliases = self._select_aliases(require_selector=True, **options)
        if not aliases:
            self.stderr.write("No matching aliases found.")
            sys.exit(1)

        if len(aliases) > 1 and not options["approved"]:
            self._render_aliases(aliases, "table")
            if not ask_for_confirmation("Unblacklist %s aliases? [y/N]" % len(aliases), default=False):
                sys.exit(1)

        with transaction.atomic():
            for alias in aliases:
                alias.blacklisted = False
                try:
                    alias.full_clean()
                    alias.save()
                except ValidationError as exc:
                    fail_with_validation_error("Validation failed for alias %s" % alias.pk, exc)
                except DatabaseError as exc:
                    self.stderr.write("Error while editing alias %s: %s" % (alias.pk, str(exc)))
                    sys.exit(1)

        self.stderr.write(self.style.SUCCESS("Unblacklisted %s alias(es)." % len(aliases)))

    def handle(self, *args: Any, **options: Any) -> None:
        if options["scmd"] == "list":
            aliases = self._select_aliases(**options)
            self._render_aliases(aliases, options["format"])
        elif options["scmd"] == "show":
            aliases = self._select_aliases(require_selector=True, **options)
            self._render_aliases(aliases, options["format"])
        elif options["scmd"] == "create":
            self._create(**options)
        elif options["scmd"] == "edit":
            self._edit(**options)
        elif options["scmd"] == "remove":
            self._remove(**options)
        elif options["scmd"] == "blacklist":
            self._blacklist(**options)
        elif options["scmd"] == "unblacklist":
            self._unblacklist(**options)
        else:
            self.stderr.write("Please specify a command.")
            self.stderr.write("Use django-admin.py emailalias --settings=authserver.settings --help to get help.")
