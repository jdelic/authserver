import argparse
import json
import sys
from typing import Any

from django.core.management.base import BaseCommand, CommandParser

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

        create_sp = subparsers.add_parser("create", help="Create an email agent auth token")
        create_sp.add_argument(
            "-u",
            "--user",
            dest="user",
            required=True,
            help="Backing user identifier or resolvable email alias",
        )
        create_sp.add_argument(
            "-f",
            "--format",
            dest="format",
            choices=["plain", "json"],
            default="plain",
            help="Output format for the created token",
        )

        list_sp = subparsers.add_parser("list", help="List email agent auth tokens")
        list_sp.add_argument(
            "-u",
            "--user",
            dest="user",
            default=None,
            help="Filter tokens to a backing user identifier or resolvable email alias",
        )
        list_sp.add_argument("-f", "--format", dest="format", choices=["table", "json"], default="table")

        check_sp = subparsers.add_parser("check", help="Check whether a token is currently valid")
        check_sp.add_argument("token", help="Plaintext token value")
        check_sp.add_argument("-f", "--format", dest="format", choices=["plain", "json"], default="plain")

        burn_sp = subparsers.add_parser("burn", help="Burn a token without first validating it")
        burn_sp.add_argument("token", help="Plaintext token value")

        cleanup_sp = subparsers.add_parser("cleanup", help="Delete burned email agent auth tokens")
        cleanup_sp.add_argument(
            "-u",
            "--user",
            dest="user",
            default=None,
            help="Limit cleanup to a backing user identifier or resolvable email alias",
        )
        cleanup_sp.add_argument("-y", "--yes", dest="approved", action="store_true", default=False)

        check_and_burn_sp = subparsers.add_parser(
            "check-and-burn",
            help="Atomically validate a token and burn it on success",
        )
        check_and_burn_sp.add_argument("token", help="Plaintext token value")
        check_and_burn_sp.add_argument("-f", "--format", dest="format", choices=["plain", "json"], default="plain")

    def _to_dict(self, token: models.EmailAgentAuthToken, *, valid: bool) -> dict[str, Any]:
        primary_email = None
        if token.creator.delivery_mailbox is not None:
            primary_email = f"{token.creator.delivery_mailbox.mailprefix}@{token.creator.delivery_mailbox.domain.name}"

        return {
            "valid": valid,
            "burned": token.burned,
            "token": token.token,
            "token_hint": token.token_hint,
            "creator": {
                "identifier": token.creator.identifier,
                "uuid": str(token.creator.uuid),
                "primary_email": primary_email,
            },
            "created_at": token.created_at.isoformat(),
            "used_at": token.used_at.isoformat() if token.used_at is not None else None,
        }

    def _emit_validation_result(
        self,
        token: models.EmailAgentAuthToken | None,
        *,
        valid: bool,
        format: str,
    ) -> None:
        if format == "json":
            if token is None:
                self.stdout.write(json.dumps({"valid": False}))
            else:
                self.stdout.write(json.dumps(self._to_dict(token, valid=valid)))
        else:
            self.stdout.write("VALID" if valid else "INVALID")

        raise SystemExit(0 if valid else 1)

    def _create(self, user: str, format: str = "plain", **kwargs: Any) -> None:
        try:
            creator = resolve_user(user)
        except ValueError as exc:
            self.stderr.write(str(exc))
            sys.exit(1)

        token, raw_token = models.EmailAgentAuthToken.objects.issue_token(creator)
        self.stderr.write(self.style.SUCCESS("Created email agent auth token for %s" % creator.identifier))
        if format == "json":
            self.stdout.write(json.dumps(self._to_dict(token, valid=not token.burned)))
        else:
            self.stdout.write(raw_token)

    def _list(self, user: str | None = None, format: str = "table", **kwargs: Any) -> None:
        queryset = models.EmailAgentAuthToken.objects.select_related("creator").order_by("-created_at")
        if user is not None:
            try:
                creator = resolve_user(user)
            except ValueError as exc:
                self.stderr.write(str(exc))
                sys.exit(1)
            queryset = queryset.filter(creator=creator)

        items = list(queryset)
        if format == "json":
            self.stdout.write(json.dumps([self._to_dict(item, valid=not item.burned) for item in items]))
            return

        if not items:
            self.stderr.write("No matching email agent auth tokens found.")
            sys.exit(1)

        fmtstr = table_left_format_str([item.token for item in items])
        print(fmtstr.format("TOKEN", "CREATOR / STATE"))
        print("-" * 78)
        for item in items:
            print(fmtstr.format(item.token, "%s (%s)" % (item.creator.identifier, "burned" if item.burned else "active")))

    def _check(self, token: str, format: str = "plain", **kwargs: Any) -> None:
        obj = models.EmailAgentAuthToken.objects.check_token(token)
        self._emit_validation_result(obj, valid=obj is not None, format=format)

    def _burn(self, token: str, **kwargs: Any) -> None:
        obj = models.EmailAgentAuthToken.objects.burn_token(token)
        if obj is None:
            self.stderr.write("Email agent auth token not found.")
            sys.exit(1)

        if obj.used_at is None:
            self.stderr.write("Email agent auth token burn did not update usage metadata.")
            sys.exit(1)

        if obj.burned:
            self.stderr.write(self.style.SUCCESS("Email agent auth token is burned."))
        sys.exit(0)

    def _cleanup(self, user: str | None = None, approved: bool = False, **kwargs: Any) -> None:
        queryset = models.EmailAgentAuthToken.objects.select_related("creator").filter(burned=True).order_by("-created_at")
        if user is not None:
            try:
                creator = resolve_user(user)
            except ValueError as exc:
                self.stderr.write(str(exc))
                sys.exit(1)
            queryset = queryset.filter(creator=creator)

        items = list(queryset)
        if not items:
            self.stderr.write("No burned email agent auth tokens found.")
            return

        if user is None and not approved:
            fmtstr = table_left_format_str([item.token for item in items])
            print(fmtstr.format("TOKEN", "CREATOR"))
            print("-" * 78)
            for item in items:
                print(fmtstr.format(item.token, item.creator.identifier))
            if not ask_for_confirmation("Delete %s burned email agent auth token(s)? [y/N]" % len(items), default=False):
                sys.exit(1)

        deleted_count, _ = queryset.delete()
        self.stderr.write(self.style.SUCCESS("Deleted %s burned email agent auth token(s)." % deleted_count))

    def _check_and_burn(self, token: str, format: str = "plain", **kwargs: Any) -> None:
        obj = models.EmailAgentAuthToken.objects.validate_and_burn(token)
        self._emit_validation_result(obj, valid=obj is not None, format=format)

    def handle(self, *args: Any, **options: Any) -> None:
        if options["scmd"] == "create":
            self._create(**options)
        elif options["scmd"] == "list":
            self._list(**options)
        elif options["scmd"] == "check":
            self._check(**options)
        elif options["scmd"] == "burn":
            self._burn(**options)
        elif options["scmd"] == "cleanup":
            self._cleanup(**options)
        elif options["scmd"] == "check-and-burn":
            self._check_and_burn(**options)
        else:
            self.stderr.write("Please specify a command.")
            self.stderr.write("Use django-admin.py emailagenttoken --settings=authserver.settings --help to get help.")
