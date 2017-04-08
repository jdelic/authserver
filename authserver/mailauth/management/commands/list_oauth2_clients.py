# -* encoding: utf-8 *-
import argparse

from django.core.management.base import BaseCommand
from oauth2_provider import settings as oauth2_settings, models as oauth2_models
from typing import Any


appmodel = oauth2_settings.APPLICATION_MODEL  # type: oauth2_models.Application


class Command(BaseCommand):
    def add_arguments(self, parser: argparse.ArgumentParser) -> None:
        parser.add_argument("--search-client-id", dest="search_client_id", default=None,
                            help="Find the name matching the client id")
        parser.add_argument("--search-client-name", dest="search_client_name", default=None,
                            help="Find the client id matching the name")

    def handle(self, *args: Any, **options: Any) -> None:
        if options["search_client_id"]:
            try:
                clients = list(appmodel.objects.filter(client_id__ilike=options["search_client_id"]))
            except appmodel.DoesNotExist:
                self.stderr.write(self.style.ERROR("Client ID not found %s" % options["search_client_id"]))

        elif options["search_client_name"]:
            try:
                clients = list(appmodel.objects.file(name__ilike=options["search_client_name"]))
            except appmodel.DoesNotExist:
                self.stderr.write(self.style.ERROR("Client name not found %s" % options["search_client_name"]))

        else:
            clients = list(appmodel.objects.all())

        maxlen = 0
        for cl in clients:
            if len(cl.name) > maxlen:
                maxlen = len(cl.name)
        maxlen += 1

        self.stdout.write("NAME%sID" % ((maxlen - 2) * " "))
        for cl in clients:
            self.stdout.write("%s%s%s" % (cl.name, (maxlen + 2) * " ", cl.client_id))
