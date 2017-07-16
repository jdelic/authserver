# -* encoding: utf-8 *-
import argparse

from django.core.management.base import BaseCommand


class DockerAuthCommand(BaseCommand):
    def add_arguments(self, parser: argparse.ArgumentParser) -> None:
        gr_docker = parser.add_argument_group("Docker Auth Commands")
