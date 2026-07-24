import secrets
import sys
from datetime import datetime, timedelta
from datetime import timezone as dt_timezone
from typing import Any

from django.core.management.base import BaseCommand, CommandParser
from django.utils import timezone
from oauth2_provider.models import get_access_token_model

from mailauth.dcr import INITIAL_ACCESS_TOKEN_SCOPE

AccessToken = get_access_token_model()


class Command(BaseCommand):
    """
    Manage RFC 7591 initial access tokens: pre-shared bearer tokens minted by
    an operator that allow a client to self-register through the DCR
    endpoint (see mailauth/dcr.py, InitialAccessTokenDCRPermission).
    """

    requires_migrations_checks = True

    def add_arguments(self, parser: CommandParser) -> None:
        class SubCommandParser(CommandParser):
            def __init__(self, **kwargs: Any) -> None:
                super().__init__(**kwargs)

        subparsers = parser.add_subparsers(dest="scmd", title="subcommands", parser_class=SubCommandParser)

        create_sp = subparsers.add_parser("create", help="Create an initial access token for DCR")
        create_sp.add_argument(
            "--expires-days",
            dest="expires_days",
            type=int,
            default=30,
            help="Number of days until the token expires. 0 means no expiry (year 9999). "
                 "Default: 30",
        )

        subparsers.add_parser("list", help="List initial access tokens for DCR")

        revoke_sp = subparsers.add_parser("revoke", help="Revoke (delete) an initial access token")
        revoke_sp.add_argument(
            "id_or_prefix",
            help="The numeric id or a token prefix (as shown by 'dcrtoken list') of the token to revoke",
        )

    def _create(self, expires_days: int = 30, **kwargs: Any) -> None:
        if expires_days == 0:
            expires = datetime(9999, 12, 31, 23, 59, 59, tzinfo=dt_timezone.utc)
        else:
            expires = timezone.now() + timedelta(days=expires_days)

        raw_token = secrets.token_urlsafe(32)
        AccessToken.objects.create(
            application=None,
            user=None,
            token=raw_token,
            scope=INITIAL_ACCESS_TOKEN_SCOPE,
            expires=expires,
        )

        self.stderr.write(
            self.style.WARNING(
                "Store this token now - it will not be shown again. It grants the bearer the "
                "ability to register OAuth2 clients via Dynamic Client Registration."
            )
        )
        self.stdout.write(raw_token)

    def _list(self, **kwargs: Any) -> None:
        tokens = list(
            AccessToken.objects.filter(scope=INITIAL_ACCESS_TOKEN_SCOPE).order_by("-created")
        )
        if not tokens:
            self.stderr.write("No initial access tokens found (yet)")
            return

        fmtstr = "{:<6} {:<12} {:<26} {}"
        self.stdout.write(fmtstr.format("ID", "TOKEN", "EXPIRES", "CREATED"))
        for token in tokens:
            self.stdout.write(
                fmtstr.format(
                    token.id,
                    "%s…" % token.token[:8],
                    token.expires.isoformat(),
                    token.created.isoformat(),
                )
            )

    def _revoke(self, id_or_prefix: str, **kwargs: Any) -> None:
        base_qs = AccessToken.objects.filter(scope=INITIAL_ACCESS_TOKEN_SCOPE)

        matches = None
        if id_or_prefix.isdigit():
            matches = list(base_qs.filter(pk=int(id_or_prefix)))

        if not matches:
            matches = list(base_qs.filter(token__startswith=id_or_prefix))

        if not matches:
            self.stderr.write(self.style.ERROR("No initial access token found matching %s" % id_or_prefix))
            sys.exit(1)

        if len(matches) > 1:
            self.stderr.write(
                self.style.ERROR(
                    "Ambiguous prefix %s matches %d tokens; use a longer prefix or the numeric id"
                    % (id_or_prefix, len(matches))
                )
            )
            sys.exit(1)

        token = matches[0]
        token_id = token.id
        token.delete()
        self.stderr.write(self.style.SUCCESS("Revoked initial access token %s" % token_id))

    def handle(self, *args: Any, **options: Any) -> None:
        if options["scmd"] == "create":
            self._create(**options)
        elif options["scmd"] == "list":
            self._list(**options)
        elif options["scmd"] == "revoke":
            self._revoke(**options)
        else:
            self.stderr.write("Please specify a command.")
            self.stderr.write("Use django-admin.py dcrtoken --settings=authserver.settings --help to get help.")
