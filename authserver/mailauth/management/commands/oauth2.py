# -* encoding: utf-8 *-
from argparse import _SubParsersAction

import sys
from typing import List

from django.core.management.base import BaseCommand, CommandParser
from django.db import transaction
from django.db.models.query_utils import Q
from django.db.utils import DatabaseError
from oauth2_provider import models as oauth2_models
from typing import Any

from mailauth.management.commands._common import _handle_client_registration, _add_publishing_args

appmodel = oauth2_models.get_application_model()  # type: oauth2_models.Application


class Command(BaseCommand):
    requires_migrations_checks = True

    def add_arguments(self, parser: CommandParser) -> None:
        cmd = self

        class SubCommandParser(CommandParser):
            def __init__(self, **kwargs: Any) -> None:
                super().__init__(cmd, **kwargs)

        subparsers = parser.add_subparsers(
            dest='scmd',
            title="subcommands",
            parser_class=SubCommandParser
        )  # type: _SubParsersAction

        create_sp = subparsers.add_parser("create", help="Create OAuth2 clients")
        _add_publishing_args(create_sp)
        create_gr = create_sp.add_argument_group("Create options")
        create_gr.add_argument("--skip-authorization", dest="skip_authorization", default=False, action="store_true",
                               help="Skip user authorization screen when connecting this application. Only use this "
                                    "for internal applications and when you know what you're doing!")
        create_gr.add_argument("--redirect-uri", dest="redirect_uris", default=[], action="append",
                               help="Valid redirect URIs for this OAuth2 client. Can be specified multiple times.")
        create_gr.add_argument("--client-type", dest="client_type", default="confidential",
                               choices=["public", "confidential"],
                               help="Choose the OAuth2 client type between 'public' and 'confidential'")
        create_gr.add_argument("--grant-type", dest="grant_type", default=appmodel.GRANT_AUTHORIZATION_CODE,
                               choices=[appmodel.GRANT_AUTHORIZATION_CODE, appmodel.GRANT_IMPLICIT,
                                        appmodel.GRANT_CLIENT_CREDENTIALS, appmodel.GRANT_PASSWORD],
                               help="Choose the OAuth2 grant type for this client.")
        create_gr.add_argument("client_name",
                               help="A human-readable name for the OAuth2 client that can be used to rerieve the same "
                                    "credentials later using this command.")

        list_sp = subparsers.add_parser("list", help="List OAuth2 clients")
        list_sp.add_argument("--search-client-id", dest="search_client_id", default=None,
                             help="Find the name matching the client id")
        list_sp.add_argument("--search-client-name", dest="search_client_name", default=None,
                             help="Find the client id matching the name")

        publish_sp = subparsers.add_parser("publish", help="Publish OAuth2 clients to consul")
        _add_publishing_args(publish_sp)

        remove_sp = subparsers.add_parser("remove", help="Delete OAuth2 clients")
        remove_sp.add_argument("client_id_or_name", nargs="?",
                               help="The OAuth2 client name or id to remove")

    def _create(self, **kwargs: Any) -> None:
        client = None
        with transaction.atomic():
            try:
                client = appmodel.objects.get(name=kwargs["client_name"])
            except appmodel.DoesNotExist:
                try:
                    client = appmodel.objects.create(
                        name=kwargs["client_name"],
                        redirect_uris="\n".join(kwargs["redirect_uris"]),
                        skip_authorization=kwargs["skip_authorization"],
                        authorization_grant_type=kwargs["grant_type"],
                    )
                except DatabaseError as e:
                    self.stderr.write("Error while creating oauth2 client: %s" % str(e))
                    sys.exit(1)

            if not _handle_client_registration(client, self, **kwargs):
                self.stderr.write(self.style.WARNING("OAuth2 client was created, but not registered"))
                sys.exit(2)

        self.stderr.write(self.style.SUCCESS("Created client %s (ID: %s)") % (kwargs["client_name"],
                                                                              client.client_id))

    def _list(self, **kwargs: Any) -> None:
        clients = []  # type: List[oauth2_models.Application]
        if kwargs["search_client_id"]:
            try:
                clients = list(appmodel.objects.filter(client_id__ilike=kwargs["search_client_id"]))
            except appmodel.DoesNotExist:
                self.stderr.write(self.style.ERROR("Client ID not found %s" % kwargs["search_client_id"]))

        elif kwargs["search_client_name"]:
            try:
                clients = list(appmodel.objects.file(name__ilike=kwargs["search_client_name"]))
            except appmodel.DoesNotExist:
                self.stderr.write(self.style.ERROR("Client name not found %s" % kwargs["search_client_name"]))

        else:
            clients = list(appmodel.objects.all())

        maxlen = 0
        for cl in clients:
            if len(cl.name) > maxlen:
                maxlen = len(cl.name)
        maxlen += 1

        if clients:
            self.stdout.write("NAME%sID" % ((maxlen - 2) * " "))
            for cl in clients:
                self.stdout.write("%s%s%s" % (cl.name, (maxlen - len(cl.name) + 2) * " ", cl.client_id))
        else:
            self.stderr.write("No clients registered (yet)")

    def _publish(self, **kwargs: Any) -> None:
        clients = list(appmodel.objects.all())

        names = []
        for cl in clients:
            if _handle_client_registration(cl, self, **kwargs):
                names.append(cl.name)

        self.stderr.write(self.style.SUCCESS("(Re-)Published Clients: %s") % (" ".join(names)))

    def _remove(self, **kwargs: Any) -> None:
        try:
            client = appmodel.objects.get(
                Q(client_id=kwargs["client_id_or_name"]) |
                Q(name=kwargs["client_id_or_name"])
            )
        except appmodel.MultipleObjectsReturned:
            self.stderr.write(self.style.ERROR("Found multiple objects for %s. Do you have a two clients where one's "
                                               "ID is the other's name? You'll need to fix that in the database." %
                                               kwargs["client_id_or_name"]))
            sys.exit(1)
        except appmodel.DoesNotExist:
            self.stderr.write(self.style.ERROR("Client %s not found." % kwargs["client_id_or_name"]))
            sys.exit(1)
        else:
            client.delete()
            self.stderr.write(self.style.SUCCESS("Client deleted: %s - %s") % (client.name, client.client_id))

    def handle(self, *args: Any, **options: Any) -> None:
        if options["scmd"] == "create":
            self._create(**options)
        elif options["scmd"] == "list":
            self._list(**options)
        elif options["scmd"] == "publish":
            self._publish(**options)
        elif options["scmd"] == "remove":
            self._remove(**options)
        else:
            self.stderr.write("Please specify a command.")
            self.stderr.write("Use django-admin.py oauth2 --settings=authserver.settings --help to get help.")
