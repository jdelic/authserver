# -* encoding: utf-8 *-
import logging
import smtplib
from typing import Union, List, Sequence

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
    def __init__(self, *, external_ip: str, external_port: int,
                 internal_ip: str=None, internal_port: int=None) -> None:
        self.external_ip = external_ip
        self.external_port = external_port
        self.internal_ip = internal_ip
        self.internal_port = internal_port

    def _format_denied_recipients(self, recipients: Sequence[str]) -> bytes:
        rcptlist = ""
        for rcpt in recipients:
            rcptlist = "%s\n%s" % ("  * %s" % rcpt, rcptlist,)
        return denied_recipients_template.format(rcptlist=rcptlist).encode('utf-8')

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
                            smtp_r.sendmail("<>", [from_addr], self._format_denied_recipients(e.recipients))
                        except smtplib.SMTPException as ex:
                            _log.exception("Error while sending denied recipients reply: %s", str(ex))
                return None
            except smtplib.SMTPServerDisconnected as e:
                _log.info("Downstream server unexpectedly disconnected: %s", str(e))
                return "421 Possible network problem. Please try again."
            return None
