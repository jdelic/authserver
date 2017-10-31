# -* encoding: utf-8 *-
import logging
import smtpd
import smtplib
import socket
from email.message import Message
from email.parser import BytesParser
from typing import Union, List, Sequence, Tuple, Any, Optional

from django.utils import timezone

_log = logging.getLogger(__name__)


denied_recipients_template = """
Hi there,

this is the mailforwarder daemon writing to you. The following recipients of 
your email were denied by their downstream email server:

{rcptlist}

Sorry, there is nothing I can do about that.
"""


class SMTPWrapper:
    """
    Sends email via the external relay, handling all exceptions defined by smtplib.SMTP.
    On certain exceptions (like denied recipients) generates an email back to the sender
    through the internal relay (if one is specified).
    """
    def __init__(self, *,
                 external_ip: str, external_port: int,
                 internal_ip: str=None, internal_port: int=None) -> None:
        self.external_ip = external_ip
        self.external_port = external_port
        self.internal_ip = internal_ip
        self.internal_port = internal_port

    def _format_denied_recipients(self, original_mail: bytes, recipients: Sequence[str]) -> bytes:
        parser = BytesParser()
        msg = parser.parsebytes(original_mail, True)  # type: Message
        msg["Subject"] = "[mailforwarder error] Re: %s" % msg["Subject"]
        msg["To"] = msg["From"]
        msg["From"] = "mailforwarder bounce <>"

        rcptlist = ""
        for rcpt in recipients:
            rcptlist = "%s\n%s" % ("  * %s" % rcpt, rcptlist,)
        txt = denied_recipients_template.format(rcptlist=rcptlist)
        msg.set_payload(txt, charset='utf-8')
        return msg.as_bytes()

    def sendmail(self, from_addr: str, to_addrs: Sequence[str], msg: bytes, mail_options: List[str]=[],
                 rcpt_options: List[str]=[]) -> Union[str, None]:
        """
        Wraps smtplib.sendmail and handles all the exceptions it can throw.
        :return: a SMTP return string or None
        """
        with smtplib.SMTP(self.external_ip, self.external_port) as smtp:
            try:
                smtp.sendmail(from_addr, to_addrs, msg, mail_options, rcpt_options)
            except smtplib.SMTPSenderRefused as e:
                _log.info("Downstream server refused sender: %s (%s %s)", e.sender, e.smtp_code, e.smtp_error)
                return "%s %s" % (e.smtp_code, e.smtp_error)
            except smtplib.SMTPResponseException as e:
                # This exception baseclass is for all exceptions that have a SMTP response code.
                # Return the downstream error code upstream
                _log.info("Unexpected response from server (passed upstream): %s %s", e.smtp_code, e.smtp_error)
                return "%s %s" % (e.smtp_code, e.smtp_error)
            except smtplib.SMTPRecipientsRefused as e:
                _log.info("Some recipients where refused by the downstream server: %s", " ".join(e.recipients))
                if self.internal_ip and self.internal_port:
                    with smtplib.SMTP(self.internal_ip, self.internal_port) as smtp_r:
                        try:
                            smtp_r.sendmail(
                                "<>",
                                [from_addr],
                                self._format_denied_recipients(msg, e.recipients)
                            )
                        except smtplib.SMTPException as ex:
                            _log.exception("Error while sending denied recipients reply: %s", str(ex))
                return None
            except smtplib.SMTPServerDisconnected as e:
                _log.info("Downstream server unexpectedly disconnected: %s", str(e))
                return "421 Possible network problem. Please try again."
            return None


# patch the SMTP channel implementation to pass us a reference to the channel
# and use sane logging
class PatchedSMTPChannel(smtpd.SMTPChannel):
    def __init__(self, server: smtpd.SMTPServer, conn: socket.socket, addr: Any,  **kwargs: Any) -> None:
        super().__init__(server, server, conn, addr, **kwargs)
        self.__real_pm = self.smtp_server.process_message

        def wrapper(*args: Any, **kwargs: Any):
            if "channel" not in kwargs:
                kwargs["channel"] = self
            self.__real_pm(*args, **kwargs)

        self.smtp_server.process_message = wrapper

    def handle_error(self) -> None:
        # handle exceptions through asyncore. Using this implementation will make it go
        # through logging and the JSON wrapper
        _log.exception("Unexpected error")
        self.handle_close()


_Address = Tuple[str, int]


class SaneSMTPServer(smtpd.SMTPServer):
    channel_class = PatchedSMTPChannel

    def __init__(self, localaddr: _Address, remoteaddr: _Address, *,
                 daemon_name: str, server_name: str=None, **kwargs) -> None:
        super().__init__(localaddr, remoteaddr, **kwargs)
        self.server_name = socket.gethostname() if server_name is None else server_name
        self.daemon_name = daemon_name

    def add_received_header(self, peer: Tuple[str, int], msg: bytes, channel: PatchedSMTPChannel) -> bytes:
        parser = BytesParser()
        new_msg = parser.parsebytes(msg, True)  # type: Message
        new_msg.add_header("Received",
                           "from %s (%s:%s) by %s (%s [%s:%s]) with SMTP for <%s>; %s" %
                           (channel.seen_greeting, peer[0], peer[1], self.server_name, self.daemon_name,
                            self._localaddr[0], self._localaddr[1], new_msg["To"],
                            timezone.now().strftime("%a, %d %b %Y %H:%M:%S %z (%Z)")))
        return new_msg.as_bytes()

    def process_message(self, peer: _Address, mailfrom: str, rcpttos: List[str], data: bytes,
                        **kwargs: Any) -> Optional[str]:
        raise NotImplementedError
