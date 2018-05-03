# -* encoding: utf-8 *-
import sys
from argparse import _SubParsersAction
from typing import Type, Any, Optional

from django.core.management.base import BaseCommand, CommandParser
from django.db.models.query_utils import Q
from django.db.utils import DatabaseError

from dockerauth.models import DockerRegistry
from mailauth.models import MNGroup, Domain
from mailauth.models import MNUser


class Command(BaseCommand):
    def _add_permission_subparsers(self, subparser: _SubParsersAction, parser_class: Type[CommandParser]) -> None:
        group_parser = subparser.add_parser("group", help="Manage group permissions (unimplemented)")
        group_sp = group_parser.add_subparsers(title="Manage group permissions (unimplemented)",
                                               parser_class=parser_class,
                                               dest="accesssubcmd")  # type: _SubParsersAction
        user_parser = subparser.add_parser("user", help="Manage user permissions (unimplemented)")
        user_sp = user_parser.add_subparsers(title="Manage user permissions (unimplemented)",
                                             parser_class=parser_class,
                                             dest="accesssubcmd")  # type: _SubParsersAction

        def create_allow_deny_cmds(localsubparser: _SubParsersAction, entity_name: str) -> None:
            allow_p = localsubparser.add_parser("allow", help="Give a %s access" % entity_name)  # type: CommandParser
            allow_p.add_argument("--name", dest="name", default=None,
                                 help="Find %s by name." % entity_name)
            deny_p = localsubparser.add_parser("deny", help="Deny a %s access" % entity_name)  # type: CommandParser
            deny_p.add_argument("--name", dest="name", default=None,
                                help="Find %s by name." % entity_name)
            list_p = localsubparser.add_parser("list", help="List all %ss" % entity_name)  # type: CommandParser

        create_allow_deny_cmds(group_sp, "group")
        create_allow_deny_cmds(user_sp, "user")

    def add_arguments(self, parser: CommandParser) -> None:
        cmd = self

        class SubCommandParser(CommandParser):
            def __init__(self, **kwargs: Any) -> None:
                super().__init__(cmd, **kwargs)

        subparsers = parser.add_subparsers(
            dest='type',
            title="subcommands",
            parser_class=SubCommandParser
        )  # type: _SubParsersAction

        registry_parser = subparsers.add_parser("registry", help="Manage Docker registries")
        repo_parser = subparsers.add_parser("repo", help="Manage Docker repositories in a registry (unimplemented)")

        reg_subparser = registry_parser.add_subparsers(title="Registry management", parser_class=SubCommandParser,
                                                       dest="subcommand")  # type: _SubParsersAction
        reg_add_parser = reg_subparser.add_parser("create", help="Add a Docker Registry")  # type: CommandParser

        reg_add_parser.add_argument("--client-id", dest="client_id", required=True,
                                    help="The client_id/service id to set (docker config value: "
                                         "REGISTRY_AUTH_TOKEN_SERVICE)")
        reg_add_parser.add_argument("--name", dest="name", required=True,
                                    help="Human-readable name for the Docker registry.")
        reg_add_parser.add_argument("--domain", dest="domain", required=True,
                                    help="Specify the domain name to connect this registry to for JWT handling")
        reg_add_parser.add_argument("--domain-exact-match", dest="domain_exact_match", action="store_true",
                                    default=False,
                                    help="'--domain' must match an exact domain (parent domains that have the flag for "
                                         "signing JWTs for subdomains set are ignored")
        reg_add_parser.add_argument("--allow-unauthenticated-pull", dest="unauthenticated_pull", action="store_true",
                                    default=False)
        reg_add_parser.add_argument("--allow-unauthenticated-push", dest="unauthenticated_push", action="store_true",
                                    default=False)

        reg_remove_parser = reg_subparser.add_parser("remove", help="Remove a Docker registry")  # type: CommandParser
        reg_remove_parser.add_argument("--name", dest="name", default=None,
                                       help="Delete the registry with this name.")
        reg_remove_parser.add_argument("--client-id", dest="client_id", default=None,
                                       help="Delete the registry with this client_id.")
        reg_remove_parser.add_argument("--force", dest="force", action="store_true", default=False,
                                       help="Do not ask for confirmation.")

        reg_list_parser = reg_subparser.add_parser("list", help="List Docker registries")  # type: CommandParser
        reg_show_parser = reg_subparser.add_parser("show", help="Show details for a Docker registry.")
        reg_show_parser.add_argument("--name", dest="name", default=None,
                                     help="Human-readable name for the Docker registry.")
        reg_show_parser.add_argument("--client-id", dest="client_id", default=None,
                                     help="The client_id/service id to set (docker config value: "
                                          "REGISTRY_AUTH_TOKEN_SERVICE)")
        reg_show_parser.add_argument("--allow-partial", dest="allow_partial", action="store_true", default=False,
                                     help="Allow partial matches for name or client id as long as the match is "
                                          "unambiguous.")
        reg_show_parser.add_argument("--case-insensitive", dest="case_insensitive", action="store_true", default=False,
                                     help="Allow case insensitive matching.")
        reg_show_parser.add_argument("--allow-multiple", dest="allow_multiple", action="store_true", default=False,
                                     help="Allow (and output) more than a single match.")
        reg_show_parser.add_argument("--output-private-key", dest="output_private_key", action="store_true",
                                     default=False,
                                     help="When set, the registry's private key will be written to stdout as well.")
        self._add_permission_subparsers(reg_subparser, SubCommandParser)
        # self._add_permission_subparsers(repo_subparser)

    def _list_registries(self) -> None:
        registries = DockerRegistry.objects.all()
        if registries.count() > 0:
            for reg in DockerRegistry.objects.all():
                self.stdout.write("\"%s\" %s" % (reg.name, reg.client_id))
            self.stdout.write("(%s found)" % registries.count())
        else:
            self.stdout.write("No Docker registries have been setup for Docker Token Auth. (0 found)")

    def _show_registry(self, name: str=None, client_id: str=None, allow_partial: bool=False,
                       case_insensitive: bool=False, allow_multiple: bool=False,
                       output_private_key: bool=False) -> None:
        name_query = "name__"
        clientid_query = "client_id__"
        if case_insensitive:
            name_query = "%si" % name_query
            clientid_query = "%si" % clientid_query
        if allow_partial:
            name_query = "%scontains" % name_query
            clientid_query = "%scontains" % clientid_query
        else:
            name_query = "%sexact" % name_query
            clientid_query = "%sexact" % clientid_query

        query = {}
        if name:
            query[name_query] = name
        if client_id:
            query[clientid_query] = client_id

        registries = DockerRegistry.objects.filter(**query)
        if registries.count() > 1 and not allow_multiple:
            self.stderr.write("The specified criteria match more than one Docker registry. You can specify "
                              "--allow-multiple if you want to output them.")
            sys.exit(1)

        for reg in registries:  # type: DockerRegistry
            self.stdout.write("Name: %s" % reg.name)
            self.stdout.write("Client id: %s" % reg.client_id)
            self.stdout.write("Allow unauthenticated pull: %s" % ("Yes" if reg.unauthenticated_pull else "No"))
            self.stdout.write("Allow unauthenticated push: %s" % ("Yes" if reg.unauthenticated_push else "No"))
            if reg.user_pull_access.count() > 0:
                self.stdout.write("Users with pull access:")
                for user in reg.user_pull_access.all():  # type: MNUser
                    self.stdout.write("    %s (%s)" % (user.get_username(), user.pk))
            if reg.user_push_access.count() > 0:
                self.stdout.write("Users with push access:")
                for user in reg.user_push_access.all():
                    self.stdout.write("    %s (%s)" % (user.get_username(), user.pk))
            if reg.group_pull_access.count() > 0:
                self.stdout.write("Groups with pull access:")
                for group in reg.group_pull_access.all():  # type: MNGroup
                    self.stdout.write("    %s (%s)" % (group.name, group.pk))
            if reg.group_push_access.count() > 0:
                self.stdout.write("Groups with push access:")
                for group in reg.group_push_access.all():
                    self.stdout.write("    %s (%s)" % (group.name, group.pk))
            if output_private_key:
                self.stdout.write("Private key:\n%s\n" % reg.sign_key)
            self.stdout.write("\n")

    def _create_registry(self, name: str, client_id: str, domain: str, domain_exact_match: bool=False,
                         unauthenticated_pull: bool=False,
                         unauthenticated_push: bool=False) -> None:
        if DockerRegistry.objects.filter(name=name).count() > 0:
            self.stderr.write("A Docker registry with the same name exists! (%s)" % name)
            sys.exit(1)
        elif DockerRegistry.objects.filter(client_id=client_id).count() > 0:
            self.stderr.write("A Docker registry with the same client id already exists! (%s)" % client_id)
            sys.exit(1)

        try:
            if domain_exact_match:
                dom = Domain.objects.get(name__iexact=domain)
            else:
                dom = Domain.objects.find_parent_domain(domain)
        except Domain.DoesNotExist:
            self.stderr.write("Can't find domain for Docker registry: %s does not exist or there is no parent domain "
                              "which is allowed to sign JWTs for subdomains." % domain)
            sys.exit(1)

        try:
            reg = DockerRegistry.objects.create(
                name=name,
                client_id=client_id,
                domain=dom,
                unauthenticated_pull=unauthenticated_pull,
                unauthenticated_push=unauthenticated_push,
            )
        except DatabaseError as e:
            self.stderr.write("Failed to create Docker registry in database.\n"
                              "Error message: %s" % str(e))
            sys.exit(1)

        self.stderr.write(self.style.SUCCESS("Created Docker registry %s (client id=%s)" % (name, client_id)))

    def _ask_confirmation(self, question: str, default: bool=None) -> bool:
        result = input("%s " % question)
        if not result and default is not None:
            return default
        while len(result) < 1 or result[0].lower() not in "yn":
            result = input("Please answer yes or no: ")
        return result[0].lower() == "y"

    def _remove_registry(self, name: Optional[str]=None, client_id: Optional[str]=None, force: bool=False) -> None:
        query = Q()
        if name:
            query |= Q(name__exact=name)
        if client_id:
            query |= Q(client_id__exact=client_id)

        registry = DockerRegistry.objects.filter(query)
        if registry.count() == 0:
            self.stderr.write("No matching registry found for the given criteria.")
            sys.exit(1)
        elif registry.count() > 1:
            self.stderr.write("Criteria matched more than a single registry.")
            sys.exit(1)
        else:
            self.stdout.write("\nRegistry-----------\nName:      %s\nClient id: %s\n\n" %
                              (registry[0].name, registry[0].client_id))
            if force or self._ask_confirmation("Really delete the above registry? [yN]", default=False):
                regname = registry[0].name
                registry.delete()
                self.stderr.write(self.style.SUCCESS("Removed docker registry \"%s\"." % regname))
                return
            else:
                sys.exit(1)

    def handle(self, *args: Any, **options: Any) -> None:
        if options["type"] == "registry":
            if options["subcommand"] == "list":
                self._list_registries()
            elif options["subcommand"] == "show":
                if not options["name"] and not options["client_id"]:
                    self.stderr.write("You have to provide at least ONE of --name or --client-id to this command.")
                    sys.exit(1)
                self._show_registry(options["name"], options["client_id"], options["allow_partial"],
                                    options["case_insensitive"], options["allow_multiple"],
                                    options["output_private_key"])
            elif options["subcommand"] == "create":
                if options["passphrase_env"] and options["passphrase_file"]:
                    self.stderr.write("You can specify either --passphrase-env or --passphrase-file, not both.")
                    sys.exit(1)
                self._create_registry(options["name"], options["client_id"], options["domain"],
                                      options["domain_exact_match"],
                                      unauthenticated_pull=options["unauthenticated_pull"],
                                      unauthenticated_push=options["unauthenticated_push"])
            elif options["subcommand"] == "remove":
                if not options["name"] and not options["client_id"]:
                    self.stderr.write("You have to provide at least ONE of --name or --client-id or both.")
                    sys.exit(1)
                self._remove_registry(options["name"], options["client_id"], options["force"])
        if "accesssubcmd" in options:
            if options["accesssubcmd"] == "user":
                pass
            elif options["accesssubcmd"] == "group":
                pass
        else:
            self.stderr.write("Please specify a command.")
            self.stderr.write("Use django-admin.py dockerauth --settings=authserver.settings --help to get help.")
