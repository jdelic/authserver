# -* encoding: utf-8 *-
import argparse
from typing import Any

from django.core.management.base import BaseCommand
from oauth2_provider import models as oauth2_models
from django.db.models import Q


appmodel = oauth2_models.get_application_model()  # type: oauth2_models.Application


class Command(BaseCommand):
    def add_arguments(self, parser: argparse.ArgumentParser) -> None:
        parser.add_argument("client_id_or_name", nargs="?",
                            help="The OAuth2 client name or id to remove")

    def handle(self, *args: Any, **options: Any) -> None:
        try:
            client = appmodel.objects.get(
                Q(client_id=options["client_id_or_name"]) |
                Q(name=options["client_id_or_name"])
            )
        except appmodel.MultipleObjectsReturned:
            self.stderr.write(self.style.ERROR("Found multiple objects for %s. Do you have a two clients where one's "
                                               "ID is the other's name? You'll need to fix that in the database." %
                                               options["client_id_or_name"]))

        client.delete()
        self.stderr.write(self.style.SUCCESS("Client deleted: %s - %s") % (client.name, client.client_id))
