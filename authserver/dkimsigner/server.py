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
from smtpd import SMTPServer
from typing import Tuple, Sequence, Any, Union

import dkim
import daemon
from django.db.utils import OperationalError

_args = None  # type: argparse.Namespace
_log = logging.getLogger(__name__)


class DKIMSignerServer(SMTPServer):
    def process_message(self, peer: Tuple[str, int], mailfrom: str, rcpttos: Sequence[str], data: bytes,
                        **kwargs: Any) -> Union[str, None]:
        # we can't import the Domain model before Django has been initialized
        from mailauth.models import Domain

        mfdomain = mailfrom.split("@", 1)[1]
        dom = None
        try:
            dom = Domain.objects.get(name=mfdomain)  # type: Domain
        except Domain.DoesNotExist:
            _log.debug("Unknown domain: %s (%s)", mfdomain, mailfrom)
        except OperationalError:
            # this is a hacky hack, but psycopg2 falls over when haproxy closes the connection on us
            _log.info("Database connection closed, Operational Error, retrying")
            from django.db import connection
            connection.close()
            if "retry" in kwargs:
                _log.exception("Database unavailable.")
                return "421 Processing problem. Please try again later."
            else:
                return self.process_message(peer, mailfrom, rcpttos, data, retry=True, **kwargs)

        if dom is not None and dom.dkimkey:
            sig = dkim.sign(data, dom.dkimselector.encode("utf-8"), dom.name.encode("utf-8"),
                            dom.dkimkey.replace("\r\n", "\n").encode("utf-8"))
            data = b"%s%s" % (sig, data)
            try:
                logstr = data.decode('utf-8')
                enc = "utf-8"
            except UnicodeDecodeError:
                logstr = data.decode('latin1')
                enc = "latin1"
            _log.debug("Signed output (%s):\n%s", enc, logstr)

        # now send the mail back to be processed
        with smtplib.SMTP(_args.output_ip, _args.output_port) as smtp:  # type: ignore
            _log.info("Sending DKIM signed email from <%s> to <%s>", mailfrom, rcpttos)
            smtp.sendmail(mailfrom, rcpttos, data)

        return None

    def handle_error(self) -> None:
        # handle exceptions through asyncore. Using this implementation will make it go
        # through logging and the JSON wrapper
        _log.exception("Unexpected error")
        self.handle_close()


def run() -> None:
    server = DKIMSignerServer((_args.input_ip, _args.input_port), None, decode_data=False)
    asyncore.loop()


def _sigint_handler(sig: int, frame: FrameType) -> None:
    print("CTRL+C exiting")
    sys.exit(1)


def _main() -> None:
    signal.signal(signal.SIGINT, _sigint_handler)

    global _args
    parser = argparse.ArgumentParser(
        description="This is a SMTP daemon that is used through OpenSMTPD configuration "
                    "to DKIM sign email received on one port and then relay the signed email "
                    "through a relay listener."
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
    grp_network.add_argument("--input-port", dest="input_port", metavar="PORT", type=int, default=10035,
                             help="The port to bind to")
    grp_network.add_argument("--output-ip", dest="output_ip", default="127.0.0.1",
                             help="The OpenSMTPD instance IP to return processed email to")
    grp_network.add_argument("--output-port", dest="output_port", metavar="PORT", type=int, default=10036,
                             help="THe port where OpenSMTPD listens for processed email")

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

    _log.info("DKIM signer starting")
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
