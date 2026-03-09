#!/usr/bin/env python3 -u
import argparse
import json
import logging
import signal
import sys
import os
import time

from types import FrameType
from typing import Tuple, Sequence, Any, Union, Optional, List, Dict, Protocol, runtime_checkable
from concurrent.futures import ThreadPoolExecutor as Pool

import authserver
import daemon
import srslib

from django.db.utils import OperationalError
from maildaemons.utils import SMTPWrapper, SaneSMTPServer, AddressTuple
from aiosmtpd.smtp import SMTP, Envelope, Session
from aiosmtpd.controller import Controller


_log = logging.getLogger(__name__)
pool = Pool()


class ForwarderServer(SaneSMTPServer):
    def __init__(self, localaddr: AddressTuple, daemon_name: str,
                 remote_relay: AddressTuple,
                 transactional_relay: Optional[AddressTuple],
                 local_delivery: AddressTuple,
                 server_name: Optional[str] = None,
                 srs_secret: str = "") -> None:
        super().__init__(localaddr, daemon_name, server_name)
        self.smtp = SMTPWrapper(
            relay=remote_relay,
            error_relay=local_delivery,
        )
        self.transactional_smtp = SMTPWrapper(
            relay=transactional_relay,
            error_relay=local_delivery,
        ) if transactional_relay else None
        self.srs = srslib.SRS(srs_secret)

    # ** must be thread-safe, don't modify shared state,
    # _log should be thread-safe as stated by the docs. Django ORM should be as well.
    def _process_message(self, peer: AddressTuple, helo_name: str, mailfrom: str,
                         rcpttos: Sequence[str], data: bytes) -> Optional[str]:
        # we can't import the Domain model before Django has been initialized
        from mailauth.models import EmailAlias, Domain

        data = self.add_received_header(peer, helo_name, data)

        remaining_rcpttos = list(rcpttos)  # ensure that new_rcpttos is a mutable list
        combined_rcptto = {}  # type: Dict[str, List[str]]  # { new_mailfrom: [recipients] }

        def add_rcptto(mfrom: str, rcpt: Union[str, List]) -> None:
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

            # Drop explicitly blacklisted full aliases (including dash/plus extensions).
            try:
                if EmailAlias.objects.filter(
                        mailprefix__iexact=rcptuser,
                        domain__name__iexact=rcptdomain,
                        blacklisted=True,
                ).exists():
                    _log.info("Dropping blacklisted alias <%s> (from: %s)", rcptto, mailfrom)
                    del remaining_rcpttos[ix]
                    continue
            except OperationalError:
                _log.exception("Database unavailable.")
                return "421 Processing problem. Please try again later."

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
                    if "@" in domain.redirect_to:
                        new_rcptto = domain.redirect_to
                    else:
                        new_rcptto = "%s@%s" % (rcptuser, domain.redirect_to)
                    _log.info("Forwarding email from <%s> to <%s> to %s",
                              mailfrom, rcptto, domain.redirect_to)
                    add_rcptto(self.srs.forward(mailfrom, domain.name), new_rcptto)
                    continue

            # follow the same path like the stored procedure authserver_resolve_alias(...)
            if "-" in rcptuser:
                # convert the first - to a +
                user_mailprefix = "%s+%s" % tuple(rcptuser.split("-", 1))  # type: ignore
            else:
                user_mailprefix = rcptuser

            if "+" in user_mailprefix:
                # if we had a dashext, or a plusext, we're left with just the prefix after this
                user_mailprefix = user_mailprefix.split("+", 1)[0]

            # Drop if the normalized alias is blacklisted.
            try:
                if EmailAlias.objects.filter(
                        mailprefix__iexact=user_mailprefix,
                        domain__name__iexact=rcptdomain,
                        blacklisted=True,
                ).exists():
                    _log.info("Dropping blacklisted alias <%s> (from: %s)", rcptto, mailfrom)
                    del remaining_rcpttos[ix]
                    continue
            except OperationalError:
                _log.exception("Database unavailable.")
                return "421 Processing problem. Please try again later."

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
                _newmf = self.srs.forward(mailfrom, alias.domain.name)
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
            _, mfdomain = new_mailfrom.split("@", 1)

            try:
                domain = Domain.objects.get(name=mfdomain)
            except Domain.DoesNotExist:
                pass

            if (new_mailfrom == mailfrom and self.transactional_smtp is not None and
                    domain is not None and domain.can_use_transactional_relay):
                _log.debug("Injecting email from <%s> to <%s> through transactional relay", new_mailfrom,
                           combined_rcptto[new_mailfrom])
                ret = self.transactional_smtp.sendmail(new_mailfrom, combined_rcptto[new_mailfrom], data)
            else:
                _log.debug("Injecting email from <%s> to <%s> through standard relay", new_mailfrom,
                           combined_rcptto[new_mailfrom])
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
                          **kwargs: Any) -> Optional[str]:
        future = pool.submit(ForwarderServer._process_message, self, session.peer, session.host_name,
                             envelope.mail_from, envelope.rcpt_tos, envelope.original_content)
        return future.result().encode("utf-8")


def run(_args: argparse.Namespace) -> None:
    _log.info("Starting ForwarderServer on %s:%s with \n"
              "    remote relay %s:%s\n"
              "    transactional relay %s:%s\n"
              "    local delivery %s:%s",
              _args.remote_relay_ip, _args.remote_relay_port, _args.transactional_relay_ip,
              _args.transactional_relay_port, _args.local_delivery_ip, _args.local_delivery_port,
              _args.input_ip, _args.input_port)
    server = ForwarderServer(
        remote_relay=(_args.remote_relay_ip, _args.remote_relay_port),
        transactional_relay=(_args.transactional_relay_ip, _args.transactional_relay_port) if _args.transactional_relay_ip else None,
        local_delivery=(_args.local_delivery_ip, _args.local_delivery_port),
        localaddr=(_args.input_ip, _args.input_port),
        daemon_name="mailforwarder",
        srs_secret=_args.srs_secret,
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
    grp_daemon.add_argument("-p", "--pidfile", dest="pidfile",
                            default=os.getenv("MAILFORWARDER_PIDFILE", "./mailforwarder-server.pid"),
                            help="Path to a pidfile")
    grp_daemon.add_argument("-u", "--user", dest="user",
                            default=os.getenv("MAILFORWARDER_USER", None),
                            help="Drop privileges and switch to this user")
    grp_daemon.add_argument("-g", "--group", dest="group",
                            default=os.getenv("MAILFORWARDER_GROUP", None),
                            help="Drop privileges and switch to this group")
    grp_daemon.add_argument("-d", "--daemonize", dest="daemonize",
                            default=os.getenv("MAILFORWARDER_DAEMONIZE", False),
                            action="store_true",
                            help="If set, fork into background")
    grp_daemon.add_argument("-v", "--verbose", dest="verbose",
                            default=os.getenv("MAILFORWARDER_LOG_VERBOSE", False),
                            action="store_true",
                            help="Output extra logging (not implemented right now)")
    grp_daemon.add_argument("-C", "--chdir", dest="chdir",
                            default=os.getenv("MAILFORWARDER_WORKDIR", "."),
                            help="Change working directory to the provided value")

    grp_network = parser.add_argument_group("Network options")
    grp_network.add_argument("--input-ip", dest="input_ip",
                             default=os.getenv("MAILFORWARDER_INPUT_IP", "127.0.0.1"),
                             help="The network address to bind to (env: MAILFORWARDER_INPUT_IP, default: 127.0.0.1)")
    grp_network.add_argument("--input-port", dest="input_port", metavar="PORT", type=int,
                             default=int(os.getenv("MAILFORWARDER_INPUT_PORT", 10046)),
                             help="The port to bind to (env: MAILFORWARDER_INPUT_PORT, default: 10046)")
    grp_network.add_argument("--local-delivery-ip", dest="local_delivery_ip",
                             default=os.getenv("MAILFORWARDER_LOCALDELIVERY_IP", "127.0.0.1"),
                             help="The OpenSMTPD instance IP for local email to be delivered. "
                                  "(env: MAILFORWARDER_LOCALDELIVERY_IP, default: 127.0.0.1)")
    grp_network.add_argument("--local-delivery-port", dest="local_delivery_port", metavar="PORT", type=int,
                             default=int(os.getenv("MAILFORWARDER_LOCALDELIVERY_PORT", 10045)),
                             help="The port where OpenSMTPD listens for local email to be delivered. "
                                  "(env: MAILFORWARDER_LOCALDELIVERY_PORT, default: 10045)")
    grp_network.add_argument("--remote-relay-ip", dest="remote_relay_ip",
                             default=os.getenv("MAILFORWARDER_REMOTERELAY_IP", "127.0.0.1"),
                             help="The OpenSMTPD instance IP that accepts mail for relay to external domains. "
                                  "(env: MAILFORWARDER_REMOTERELAY_IP, default: 127.0.0.1)")
    grp_network.add_argument("--remote-relay-port", dest="remote_relay_port",
                             default=int(os.getenv("MAILFORWARDER_REMOTERELAY_PORT", 10045)),
                             help="The port where OpenSMTPD listens for mail to relay. "
                                  "(env: MAILFORWARDER_REMOTERELAY_PORT, default: 10045)")
    grp_network.add_argument("--transactional-relay-ip", dest="transactional_relay_ip",
                             default=os.getenv("MAILFORWARDER_TRANSACTIONALRELAY_IP", None),
                             help="The OpenSMTPD instance IP that accepts mail for transactional email (non-forwarded "
                                  "email from domains that have the 'can_use_transactional_relay' flag set), i.e. are "
                                  "registered with, for example, Amazon SES or Scaleway. This is optional. If not set, "
                                  "transactional email will be sent through the same relay as regular email. "
                                  "(env: MAILFORWARDER_TRANSACTIONALRELAY_IP)")
    grp_network.add_argument("--transactional-relay-port", dest="transactional_relay_port",
                             default=int(os.getenv("MAILFORWARDER_TRANSACTIONALRELAY_PORT", 10047)),
                             help="The port where OpenSMTPD listens for transcational mail. "
                                  "(env: MAILFORWARDER_TRANSACTIONALRELAY_PORT)")
    grp_network.add_argument("--srs-secret", dest="srs_secret",
                             default=os.getenv("MAILFORWARDER_SRS_SECRET", ""),
                             help="SRS secret used to rewrite forwarding envelope sender addresses "
                                  "(env: MAILFORWARDER_SRS_SECRET).")

    grp_django = parser.add_argument_group("Django options")
    grp_django.add_argument("--settings", dest="django_settings",
                            default=os.getenv("DJANGO_SETTINGS_MODULE", "authserver.settings"),
                            help="The Django settings module to use for authserver database access (default: "
                                 "authserver.settings) (env: DJANGO_SETTINGS_MODULE)")

    _args = parser.parse_args()

    if _args.srs_secret == "":
        _log.fatal("No SRS secret provided (set MAILFORWARDER_SRS_SECRET or use --srs-secret), exiting.")
        sys.exit(1)

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
