# -* encoding: utf-8 *-
import argparse
import json
import os

import consul
import hvac

from django.core.management.base import BaseCommand
from django.conf import settings
from oauth2_provider import models as oauth2_models
from typing import Any


appmodel = oauth2_models.get_application_model()  # type: oauth2_models.Application


class Command(BaseCommand):
    requires_migrations_checks = True

    def add_arguments(self, parser: argparse.ArgumentParser) -> None:
        parser.add_argument_group("Config output options")
        parser.add_argument("--publish-to-stdout", dest="publish_to_stdout", action="store_true", default=False,
                            help="write the OAuth2 credentials to stdout as a JSON object.")
        parser.add_argument("--publish-to-consulkv", dest="publish_to_consulkv", default=None,
                            help="write the OAuth2 credentials to Hashicorp Consul. The credentials will be stored in "
                                 "key/value pairs under the specified path.")
        parser.add_argument("--publish-to-vault", dest="publish_to_vault", default=None,
                            help="write the OAuth2 credentials to Hashicorp Vault. The credentials will be stored in "
                                 "key/value paris under the specified path. The path must reside in a Vault 'secret' "
                                 "backend. Set environment variables as specified by '12factor-vault' to configure "
                                 "Vault authentication in the Authserver settings.")
        parser.add_argument("--consul-url", dest="consul_url",
                            default=os.getenv("CONSUL_HTTP_ADDR", "http://127.0.0.1:8500/"),
                            help="URL to use to contact the local Consul agent. Will use $CONSUL_HTTP_ADDR from the "
                                 "environment if it exists.")
        parser.add_argument("--consul-token", dest="consul_token",
                            default=None,
                            help="An optional Consul ACL token. Will use the value of $CONSUL_TOKEN from the "
                                 "environment if it exists.")

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

        parser.add_argument("client_name", nargs="?", required=True,
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

        credentials = {
            "name": client.name,
            "client_id": client.client_id,
            "client_secret": client.client_secret,
        }

        json_str = json.dumps(credentials, indent=4)

        if options["publish_to_stdout"]:
            self.stdout.write(json_str)

        if options["publish_to_consulkv"]:
            con = consul.Consul(host=options["consul_url"], token=options["consul_token"])
            path = options["publish_to_consulkv"]
            con.kv.put("%s/json" % path, json_str)
            con.kv.put("%s/name" % path, client.name)
            con.kv.put("%s/client_id" % path, client.client_id)
            con.kv.put("%s/client_secret" % path, client.client_secret)

        if options["publish_to_vault"]:
            cl = settings.VAULT.authenticated_client()  # type: hvac.Client
            cl.write(options["publish_to_vault"],
                **credentials
            )

        self.stderr.write(self.style.SUCCESS("Created client %s (ID: %s)") % (options["client_name"],
                                                                              client.client_id))
