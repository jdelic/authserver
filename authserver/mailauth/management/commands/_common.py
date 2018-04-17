# -* encoding: utf-8 *-
import argparse
import json
import os
from typing import TypeVar, Any
from urllib.parse import urlparse

import consul
import hvac
import hvac.exceptions
from consul.base import ConsulException
from django.conf import settings
from django.core.management.base import BaseCommand
from oauth2_provider import models as oauth2_models
from vault12factor import VaultCredentialProviderException


OT = TypeVar('OT', bound=oauth2_models.AbstractApplication)
CMDT = TypeVar('CMDT', bound=BaseCommand)


def _add_publishing_args(parser: argparse.ArgumentParser) -> None:
    out_gr = parser.add_argument_group("Config output options")
    out_gr.add_argument("--publish-to-stdout", dest="publish_to_stdout", action="store_true", default=False,
                        help="write the OAuth2 credentials to stdout as a JSON object.")
    out_gr.add_argument("--publish-to-consulkv", dest="publish_to_consulkv", default=None,
                        help="write the OAuth2 credentials to Hashicorp Consul. The credentials will be stored in "
                             "key/value pairs under the specified path.")
    out_gr.add_argument("--publish-to-vault", dest="publish_to_vault", default=None,
                        help="write the OAuth2 credentials to Hashicorp Vault. The credentials will be stored in "
                             "key/value paris under the specified path. The path must reside in a Vault 'secret' "
                             "backend. Set environment variables as specified by '12factor-vault' to configure "
                             "Vault authentication in the Authserver settings.")
    out_gr.add_argument("--consul-url", dest="consul_url",
                        default=os.getenv("CONSUL_HTTP_ADDR", "http://127.0.0.1:8500/"),
                        help="URL to use to contact the local Consul agent. Will use $CONSUL_HTTP_ADDR from the "
                             "environment if it exists.")
    out_gr.add_argument("--consul-token", dest="consul_token",
                        default=None,
                        help="An optional Consul ACL token. Will use the value of $CONSUL_TOKEN from the "
                             "environment if it exists.")


def _handle_client_registration(client: OT, mgr: CMDT, **options: Any) -> bool:
    credentials = {
        "name": client.name,
        "client_id": client.client_id,
        "client_secret": client.client_secret,
    }

    json_str = json.dumps(credentials, indent=4)

    if options["publish_to_stdout"]:
        mgr.stdout.write(json_str)

    if options["publish_to_consulkv"]:
        urp = urlparse(options["consul_url"])
        if ":" in urp.netloc:
            host, port = urp.netloc.split(":", 1)
        else:
            host = urp.netloc
            port = 8500

        try:
            con = consul.Consul(host=host, port=port, scheme=urp.scheme,
                                token=options.get("consul_token", os.getenv("CONSUL_HTTP_TOKEN", None)))
            path = options["publish_to_consulkv"]
            con.kv.put("%s/json" % path, json_str)
            con.kv.put("%s/name" % path, client.name)
            con.kv.put("%s/client_id" % path, client.client_id)
            con.kv.put("%s/client_secret" % path, client.client_secret)
        except ConsulException as e:
            mgr.stderr.write(mgr.style.ERROR("ERROR: Request to Consul failed: %s" % str(e)))
            return False

        mgr.stderr.write(mgr.style.SUCCESS("INFO: Client credentials published to Consul"))

    if options["publish_to_vault"]:
        try:
            cl = settings.VAULT.authenticated_client(
                url=settings.VAULT_ADDRESS,
                verify=os.getenv("VAULT_CA", "https" in settings.VAULT_ADDRESS)
            )  # type: hvac.Client
            cl.write(
                options["publish_to_vault"],
                **credentials
            )
        except VaultCredentialProviderException as e:
            mgr.stderr.write(mgr.style.ERROR("Can't create Vault credentials: %s" % str(e)))
            return False
        except hvac.exceptions.VaultError as e:
            mgr.stderr.write(mgr.style.ERROR("Can't write to Vault: %s" % str(e)))
            return False

        mgr.stderr.write(mgr.style.SUCCESS("INFO: Client credentials published to Vault"))

    return True
