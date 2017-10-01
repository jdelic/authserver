#!/usr/bin/env python3 -u
# -* encoding: utf-8 *-

import argparse
import asyncore
import logging
import smtplib
import signal
import sys
import os

from types import FrameType
from smtpd import SMTPServer, SMTPChannel
from typing import Tuple, Sequence, Any, Union
from concurrent.futures import ThreadPoolExecutor as Pool

import daemon
from django.db.utils import OperationalError

_args = None  # type: argparse.Namespace
_log = logging.getLogger(__name__)
pool = None  # type: Pool


class ForwarderSMTPChannel(SMTPChannel):
    def handle_error(self) -> None:
        # handle exceptions through asyncore. Using this implementation will make it go
        # through logging and the JSON wrapper
        _log.exception("Unexpected error")
        self.handle_close()


class ForwarderServer(SMTPServer):
    channel_class = ForwarderSMTPChannel

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)

    # ** must be thread-safe, don't modify shared state,
    # _log should be thread-safe as stated by the docs. Django ORM should be as well.
    def _process_message(self, peer: Tuple[str, int], mailfrom: str, rcpttos: Sequence[str], data: bytes,
                         **kwargs: Any) -> Union[str, None]:
        # we can't import the Domain model before Django has been initialized
        from mailauth.models import EmailAlias, Domain

        remaining_rcpttos = list(rcpttos)  # ensure that new_rcpttos is a mutable list
        # we're going to modify remaining_rcpttos so we start from its end
        for ix in range(len(remaining_rcpttos) - 1, -1, -1):
            rcptto = rcpttos[ix].lower()
            rcptuser, rcptdomain = rcptto.split("@", 1)

            # implement domain catch-all redirect
            domain = None  # type: Domain
            try:
                domain = Domain.objects.get(name=rcptdomain)
            except Domain.DoesNotExist:
                pass
            except OperationalError:
                # this is a hacky hack, but psycopg2 falls over when haproxy closes the connection on us
                _log.info("Database connection closed, Operational Error, retrying")
                from django.db import connection
                connection.close()
                if "retry" in kwargs and kwargs["retry"]:
                    _log.exception("(Retry) Database unavailable.")
                    return "421 Processing problem. Please try again later."
                else:
                    # any already-processed rcptto will have been removed from the array. We retry all other ones.
                    return self.process_message(peer, mailfrom, remaining_rcpttos, data, retry=True, **kwargs)

            if domain:
                if domain.redirect_to:
                    _log.debug("ix: %s - rcptto: %s - remaining rcpttos: %s", ix, rcptto, remaining_rcpttos)
                    del remaining_rcpttos[ix]
                    new_rcptto = "%s@%s" % (rcptuser, domain.redirect_to)
                    with smtplib.SMTP(_args.remote_relay_ip, _args.remote_relay_port) as smtp:  # type: ignore
                        _log.info("%sForwarding email from <%s> to <%s> to domain @%s",
                                  "(Retry) " if "retry" in kwargs and kwargs["retry"] else "",
                                  mailfrom, rcptto, domain.redirect_to)
                        smtp.sendmail(mailfrom, new_rcptto, data)
                    continue

            # follow the same path like the stored procedure authserver_resolve_alias(...)
            if "-" in rcptuser:
                user_mailprefix = "%s+%s" % tuple(rcptuser.split("-", 1))  # convert the first - to a +
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
                _log.error("%sUnknown mail address: %s (from: %s, prefix: %s)",
                           "(Retry) " if "retry" in kwargs and kwargs["retry"] else "",
                           rcptto, mailfrom, user_mailprefix)
                continue
            except OperationalError:
                # this is a hacky hack, but psycopg2 falls over when haproxy closes the connection on us
                _log.info("Database connection closed, Operational Error, retrying")
                from django.db import connection
                connection.close()
                if "retry" in kwargs and kwargs["retry"]:
                    _log.exception("(Retry) Database unavailable.")
                    return "421 Processing problem. Please try again later."
                else:
                    # any already-processed rcptto will have been removed from the array. We retry all other ones.
                    return self.process_message(peer, mailfrom, remaining_rcpttos, data, retry=True, **kwargs)

            if alias.forward_to is not None:
                # it's a mailing list, forward the email to all connected addresses
                del remaining_rcpttos[ix]  # remove this recipient from the list
                with smtplib.SMTP(_args.remote_relay_ip, _args.remote_relay_port) as smtp:  # type: ignore
                    _newmf = mailfrom
                    if alias.forward_to.new_mailfrom != "":
                        _newmf = alias.forward_to.new_mailfrom
                    _log.info("%sForwarding email from <%s> with new sender <%s> to <%s>",
                              "(Retry) " if "retry" in kwargs and kwargs["retry"] else "",
                              mailfrom, _newmf, alias.forward_to.addresses)
                    smtp.sendmail(_newmf, alias.forward_to.addresses, data)

        # if there are any remaining non-list/non-forward recipients, we inject them back to OpenSMTPD here
        if len(remaining_rcpttos) > 0:
            with smtplib.SMTP(_args.local_delivery_ip, _args.local_delivery_port) as smtp:  # type: ignore
                _log.info("%sReinjecting email from <%s> to remaining recipients <%s>",
                          "(Retry) " if "retry" in kwargs and kwargs["retry"] else "",
                          mailfrom, remaining_rcpttos)
                smtp.sendmail(mailfrom, remaining_rcpttos, data)

        _log.debug("Done processing.")
        return None

    def process_message(self, *args: Any, **kwargs: Any) -> Union[str, None]:
        future = pool.submit(ForwarderServer._process_message, self, *args, **kwargs)
        return future.result()


def run() -> None:
    global pool
    pool = Pool()
    server = ForwarderServer((_args.input_ip, _args.input_port), None, decode_data=False)
    asyncore.loop()


def _sigint_handler(sig: int, frame: FrameType) -> None:
    print("CTRL+C exiting")
    pool.shutdown(wait=False)
    sys.exit(1)


def _main() -> None:
    signal.signal(signal.SIGINT, _sigint_handler)

    global _args
    parser = argparse.ArgumentParser(
        description="This is a SMTP daemon that is used through OpenSMTPD configuration "
                    "to check whether incoming emails are addressed to a forwarding email alias "
                    "and if they are, inject emails to all list delivery addresses / expand the alias."
    )

    grp_daemon = parser.add_argument_group("Daemon options")
    grp_daemon.add_argument("-p", "--pidfile", dest="pidfile", default="./dkimsigner-server.pid",
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
    grp_network.add_argument("--remote-relay-port", dest="remote_relay_port", default=10036,
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

    _log.info("Forwarding Alias Service starting")
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
        run()


def main() -> None:
    try:
        _main()
    except Exception as e:
        _log.fatal("Unhandled exception", exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    main()
