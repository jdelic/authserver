# -* encoding: utf-8 *-
import argparse
from typing import Any

from oauth2_provider import models as oauth2_models
from django.core.management.base import BaseCommand

from mailauth.management.commands._common import _handle_client_registration, _add_publishing_args


appmodel = oauth2_models.get_application_model()  # type: oauth2_models.Application


class Command(BaseCommand):
    def add_arguments(self, parser: argparse.ArgumentParser) -> None:
        _add_publishing_args(parser)

    def handle(self, *args: Any, **options: Any) -> None:
        clients = list(appmodel.objects.all())

        names = []
        for cl in clients:
            if _handle_client_registration(cl, self, **options):
                names.append(cl.name)

        self.stderr.write(self.style.SUCCESS("(Re-)Published Clients: %s") % (" ".join(names)))
