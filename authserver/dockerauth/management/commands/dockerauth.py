# -* encoding: utf-8 *-
from argparse import ArgumentParser

from django.core.management.base import BaseCommand, CommandParser


class Command(BaseCommand):
    def add_arguments(self, parser: CommandParser) -> None:

        cmd = self

        class SubCommandParser(CommandParser):
            def __init__(self, **kwargs) -> None:
                super().__init__(cmd, **kwargs)

        subparsers = parser.add_subparsers(
            dest='type',
            title="subcommands",
            parser_class=SubCommandParser
        )  # type: ArgumentParser

        registry_parser = subparsers.add_parser("registry", help="Manage Docker Registry access")
        repo_parser = subparsers.add_parser("repo", help="Manage Docker Repository access")

        reg_subparser = registry_parser.add_subparsers(title="Registry access", parser_class=SubCommandParser)
        reg_add_parser = reg_subparser.add_parser("add", help="Add a Docker Registry")
        reg_remove_parser = reg_subparser.add_parser("remove", help="Remove a Docker Registry")

    def handle(self, *args, **options) -> None:
        pass
