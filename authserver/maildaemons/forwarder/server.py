#!/usr/bin/env python3 -u
import argparse
import json
import logging
import signal
import sys
import os
import time

from types import FrameType
from typing import Tuple, Sequence, Any, Union, Optional, List, Dict, cast
from concurrent.futures import Future, ThreadPoolExecutor as Pool

import daemon
from django.db.utils import OperationalError

import authserver
from maildaemons.utils import SMTPWrapper, SaneSMTPServer, AddressTuple, IPAddressTuple
from aiosmtpd.smtp import SMTP, Envelope, Session
from aiosmtpd.controller import Controller

_log = logging.getLogger(__name__)
pool = Pool()


class ForwarderServer(SaneSMTPServer):
    def __init__(self, localaddr: IPAddressTuple, daemon_name: str,
                 remote_relay: AddressTuple, local_delivery: AddressTuple,
                 server_name: Optional[str] = None) -> None:
        super().__init__(localaddr, daemon_name, server_name)
        self.smtp = SMTPWrapper(
            relay=remote_relay,
            error_relay=local_delivery,
        )

    # ** must be thread-safe, don't modify shared state,
    # _log should be thread-safe as stated by the docs. Django ORM should be as well.
    def _process_message(self, peer: IPAddressTuple, helo_name: str, mailfrom: str,
                         rcpttos: Sequence[str], data: bytes) -> str:
        # we can't import the Domain model before Django has been initialized
        from mailauth.models import EmailAlias, Domain

        data = self.add_received_header(peer, helo_name, data)

        remaining_rcpttos = list(rcpttos)  # ensure that new_rcpttos is a mutable list
        combined_rcptto = {}  # type: Dict[str, List[str]]  # { new_mailfrom: [recipients] }

        def add_rcptto(mfrom: str, rcpt: Union[str, List[str]]) -> None:
            if mfrom in combined_rcptto:
                if isinstance(rcpt, list):
                    combined_rcptto[mfrom] += rcpt
                else:
                    combined_rcptto[mfrom].append(rcpt)
            else:
                if isinstance(rcpt, list):
                    combined_rcptto[mfrom] = rcpt
                else:
                    combined_rcptto[mfrom] = [rcpt]

        # we're going to modify remaining_rcpttos so we start from its end
        for ix in range(len(remaining_rcpttos) - 1, -1, -1):
            rcptto = rcpttos[ix].lower()
            rcptuser, rcptdomain = rcptto.split("@", 1)

            # implement domain catch-all redirect
            domain = None  # type: Optional[Domain]
            try:
                domain = Domain.objects.get(name=rcptdomain)
            except Domain.DoesNotExist:
                pass
            except OperationalError:
                _log.exception("Database unavailable.")
                return "421 Processing problem. Please try again later."

            if domain:
                if domain.redirect_to:
                    _log.debug("ix: %s - rcptto: %s - remaining rcpttos: %s", ix, rcptto, remaining_rcpttos)
                    del remaining_rcpttos[ix]
                    new_rcptto = "%s@%s" % (rcptuser, domain.redirect_to)
                    _log.info("Forwarding email from <%s> to <%s> to domain @%s",
                              mailfrom, rcptto, domain.redirect_to)
                    add_rcptto(mailfrom, new_rcptto)
                    continue

            # follow the same path like the stored procedure authserver_resolve_alias(...)
            if "-" in rcptuser:
                # convert the first - to a +
                user_mailprefix = "%s+%s" % tuple(rcptuser.split("-", 1))
            else:
                user_mailprefix = rcptuser

            if "+" in user_mailprefix:
                # if we had a dashext, or a plusext, we're left with just the prefix after this
                user_mailprefix = user_mailprefix.split("+", 1)[0]

            try:
                alias = EmailAlias.objects.get(mailprefix__iexact=user_mailprefix,
                                               domain__name__iexact=rcptdomain)  # type: EmailAlias
            except EmailAlias.DoesNotExist:
                # OpenSMTPD shouldn't even call us for invalid addresses if we're configured correctly
                _log.error("Unknown mail address: %s (from: %s, prefix: %s)",
                           rcptto, mailfrom, user_mailprefix)
                continue
            except OperationalError:
                _log.exception("Database unavailable.")
                return "421 Processing problem. Please try again later."

            if alias.forward_to is not None:
                # it's a mailing list, forward the email to all connected addresses
                del remaining_rcpttos[ix]  # remove this recipient from the list
                _newmf = mailfrom
                if alias.forward_to.new_mailfrom != "":
                    _newmf = alias.forward_to.new_mailfrom
                _log.info("Forwarding email from <%s> with new sender <%s> to <%s>",
                          mailfrom, _newmf, alias.forward_to.addresses)
                add_rcptto(_newmf, alias.forward_to.addresses)

        # if there are any remaining non-list/non-forward recipients, we inject them back to OpenSMTPD here
        if len(remaining_rcpttos) > 0:
            _log.info("Delivering email from <%s> to remaining recipients <%s>",
                      mailfrom, remaining_rcpttos)
            add_rcptto(mailfrom, remaining_rcpttos)

        if len(combined_rcptto.keys()) == 1:
            _log.debug("Only one mail envelope sender, forwarding is atomic")

        results = {k: "unsent" for k in combined_rcptto.keys()}  # type: Dict[str, str]
        for new_mailfrom in combined_rcptto.keys():
            _log.debug("Injecting email from <%s> to <%s>", new_mailfrom, combined_rcptto[new_mailfrom])
            ret = self.smtp.sendmail(new_mailfrom, combined_rcptto[new_mailfrom], data)
            if ret is not None:
                results[new_mailfrom] = "failure"
                if len(combined_rcptto.keys()) > 1:
                    _log.error("Non-atomic mail sending failed from <%s> in dict(%s)", combined_rcptto.keys(),
                               json.dumps(results))
                return ret
            results[new_mailfrom] = "success"

        # TODO: log results
        _log.debug("Done processing.")
        return "250 Processing complete."

    async def handle_DATA(self, server: SMTP, session: Session, envelope: Envelope, *args: Any,
                          **kwargs: Any) -> str:
        future: Future[str] = pool.submit(ForwarderServer._process_message, self,
                                          # this cast is necessary until
                                          # https://github.com/typeddjango/django-stubs/pull/2742 lands
                                          cast(IPAddressTuple, session.peer),
                                          session.host_name if session.host_name is not None else "<nohostname>",
                                          envelope.mail_from if envelope.mail_from is not None else "<nomailfrom>",
                                          envelope.rcpt_tos,
                                          envelope.original_content if envelope.original_content is not None else b"")
        return future.result()


def run(_args: argparse.Namespace) -> None:
    server = ForwarderServer(
        remote_relay=(_args.remote_relay_ip, _args.remote_relay_port),
        local_delivery=(_args.local_delivery_ip, _args.local_delivery_port),
        localaddr=(_args.input_ip, _args.input_port),
        daemon_name="mailforwarder",
    )
    ctrl = Controller(
        server,
        hostname=_args.input_ip,
        port=_args.input_port,
        decode_data=False,
        auth_exclude_mechanism=["LOGIN", "PLAIN"],
        ident="mailforwarder v%s" % authserver.version
    )
    ctrl.start()
    while True:
        time.sleep(1)


def _sigint_handler(sig: int, frame: Optional[FrameType]) -> None:
    print("CTRL+C exiting")
    pool.shutdown(wait=False)
    sys.exit(1)


def _main() -> None:
    signal.signal(signal.SIGINT, _sigint_handler)

    parser = argparse.ArgumentParser(
        description="This is a SMTP daemon that is used through OpenSMTPD configuration "
                    "to check whether incoming emails are addressed to a forwarding email alias "
                    "and if they are, inject emails to all list delivery addresses / expand the alias."
    )

    grp_daemon = parser.add_argument_group("Daemon options")
    grp_daemon.add_argument("-p", "--pidfile", dest="pidfile", default="./mailforwarder-server.pid",
                            help="Path to a pidfile")
    grp_daemon.add_argument("-u", "--user", dest="user", default=None, help="Drop privileges and switch to this user")
    grp_daemon.add_argument("-g", "--group", dest="group", default=None,
                            help="Drop privileges and switch to this group")
    grp_daemon.add_argument("-d", "--daemonize", dest="daemonize", default=False, action="store_true",
                            help="If set, fork into background")
    grp_daemon.add_argument("-v", "--verbose", dest="verbose", default=False, action="store_true",
                            help="Output extra logging (not implemented right now)")
    grp_daemon.add_argument("-C", "--chdir", dest="chdir", default=".",
                            help="Change working directory to the provided value")

    grp_network = parser.add_argument_group("Network options")
    grp_network.add_argument("--input-ip", dest="input_ip", default="127.0.0.1", help="The network address to bind to")
    grp_network.add_argument("--input-port", dest="input_port", metavar="PORT", type=int, default=10046,
                             help="The port to bind to")
    grp_network.add_argument("--local-delivery-ip", dest="local_delivery_ip", default="127.0.0.1",
                             help="The OpenSMTPD instance IP for local email to be delivered.")
    grp_network.add_argument("--local-delivery-port", dest="local_delivery_port", metavar="PORT", type=int,
                             default=10045, help="The port where OpenSMTPD listens for local email to be delivered")
    grp_network.add_argument("--remote-relay-ip", dest="remote_relay_ip", default="127.0.0.1",
                             help="The OpenSMTPD instance IP that accepts mail for relay to external domains.")
    grp_network.add_argument("--remote-relay-port", dest="remote_relay_port", default=10045,
                             help="The port where OpenSMTPD listens for mail to relay.")

    grp_django = parser.add_argument_group("Django options")
    grp_django.add_argument("--settings", dest="django_settings", default="authserver.settings",
                            help="The Django settings module to use for authserver database access (default: "
                                 "authserver.settings)")

    _args = parser.parse_args()

    os.environ.setdefault("DJANGO_SETTINGS_MODULE", _args.django_settings)
    # noinspection PyUnresolvedReferences
    from django.conf import settings  # initialize Django
    import django

    django.setup()

    _log.info("mailforwarder v%s: Forwarding Alias Service starting (aiosmtpd)" % authserver.version)
    _log.info("Django ORM initialized")

    pidfile = open(_args.pidfile, "w")

    ctx = daemon.DaemonContext(
        working_directory=_args.chdir,
        pidfile=pidfile,
        uid=_args.user,
        gid=_args.group,
        detach_process=_args.daemonize,
        files_preserve=[1, 2, 3, pidfile],
        stdin=sys.stdin,
        stdout=sys.stdout,
        stderr=sys.stderr,
    )

    with ctx:
        run(_args)


def main() -> None:
    try:
        _main()
    except Exception as e:
        _log.critical("Unhandled exception", exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    main()
