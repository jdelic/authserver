# -* encoding: utf-8 *-
import argparse

from django.core.management.base import BaseCommand
from oauth2_provider import models as oauth2_models
from typing import Any

from mailauth.management.commands._common import _handle_client_registration, _add_publishing_args

appmodel = oauth2_models.get_application_model()  # type: oauth2_models.Application


class Command(BaseCommand):
    requires_migrations_checks = True

    def add_arguments(self, parser: argparse.ArgumentParser) -> None:
        _add_publishing_args(parser)

        parser.add_argument_group("OAuth2 options")
        parser.add_argument("--skip-authorization", dest="skip_authorization", default=False, action="store_true",
                            help="Skip user authorization screen when connecting this application. Only use this "
                                 "for internal applications and when you know what you're doing!")
        parser.add_argument("--redirect-uri", dest="redirect_uris", default=[], action="append",
                            help="Valid redirect URIs for this OAuth2 client. Can be specified multiple times.")
        parser.add_argument("--client-type", dest="client_type", default="confidential",
                            choices=["public", "confidential"],
                            help="Choose the OAuth2 client type between 'public' and 'confidential'")
        parser.add_argument("--grant-type", dest="grant_type", default=appmodel.GRANT_AUTHORIZATION_CODE,
                            choices=[appmodel.GRANT_AUTHORIZATION_CODE, appmodel.GRANT_IMPLICIT,
                                     appmodel.GRANT_CLIENT_CREDENTIALS, appmodel.GRANT_PASSWORD],
                            help="Choose the OAuth2 grant type for this client.")

        parser.add_argument("client_name",
                            help="A human-readable name for the OAuth2 client that can be used to rerieve the same "
                                 "credentials later using this command.")

    def handle(self, *args: Any, **options: Any) -> None:
        client = None
        try:
            client = appmodel.objects.get(name=options["client_name"])
        except appmodel.DoesNotExist:
            client = appmodel.objects.create(
                name=options["client_name"],
                redirect_uris="\n".join(options["redirect_uris"]),
                skip_authorization=options["skip_authorization"],
                authorization_grant_type=options["grant_type"],
            )

        if _handle_client_registration(client, self, **options):
            self.stderr.write(self.style.SUCCESS("Created client %s (ID: %s)") % (options["client_name"],
                                                                                  client.client_id))
