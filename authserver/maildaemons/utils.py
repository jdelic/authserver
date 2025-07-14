import logging
import smtplib
import socket
from email import policy

from email._policybase import Policy, compat32
from email.header import Header
from email.message import Message, _formatparam, SEMISPACE  # type: ignore


from email.parser import BytesParser
from typing import Union, List, Sequence, Tuple, Any, Optional, cast

from django.utils import timezone

_log = logging.getLogger(__name__)
_compat32_smtp_policy = policy.compat32.clone(linesep='\r\n')


denied_recipients_template = """
Hi there,

this is the mailforwarder daemon writing to you. The following recipients of
your email were denied by their downstream email server:

{rcptlist}

Sorry, there is nothing I can do about that.
"""


AddressTuple = Tuple[Optional[str], Optional[int]]


class SMTPWrapper:
    """
    Sends email via the external relay, handling all exceptions defined by smtplib.SMTP.
    On certain exceptions (like denied recipients) generates an email back to the sender
    through the internal relay (if one is specified).
    """
    def __init__(self, *,
                 relay: AddressTuple,
                 error_relay: AddressTuple = (None, None)) -> None:
        self.external_ip = relay[0]
        self.external_port = relay[1]
        self.error_relay_ip = error_relay[0]
        self.error_relay_port = error_relay[1]

    def _format_denied_recipients(self, original_mail: bytes, recipients: Sequence[str]) -> bytes:
        parser = BytesParser()
        msg = parser.parsebytes(original_mail, True)  # type: ignore
        msg["Subject"] = "[mailforwarder error] Re: %s" % msg["Subject"]
        # this should never be None at this point, but typewise it could be
        msg["To"] = cast(str, msg["From"])
        msg["From"] = "mailforwarder bounce <>"

        rcptlist = ""
        for rcpt in recipients:
            rcptlist = "%s\n%s" % ("  * %s" % rcpt, rcptlist,)
        txt = denied_recipients_template.format(rcptlist=rcptlist)
        msg.set_payload(txt, charset='utf-8')
        return msg.as_bytes(policy=policy.SMTP)

    def sendmail(self, from_addr: str, to_addrs: Sequence[str], msg: bytes, mail_options: List[str] = [],
                 rcpt_options: List[str] = []) -> str:
        """
        Wraps smtplib.sendmail and handles all the exceptions it can throw.
        :return: a SMTP return string
        """
        if not self.external_ip or not self.external_port:
            _log.error("No external relay configured. Cannot send email.")
            return "421 No external relay configured. Please try again later."

        with smtplib.SMTP(self.external_ip, self.external_port) as smtp:
            try:
                smtp.sendmail(from_addr, to_addrs, msg, mail_options, rcpt_options)
            except smtplib.SMTPSenderRefused as e:
                if isinstance(e.smtp_error, bytes):
                    errorstr = e.smtp_error.decode("utf-8", errors="ignore")
                else:
                    errorstr = str(e.smtp_error)
                _log.info("Downstream server refused sender: %s (%s %s)", e.sender, e.smtp_code, errorstr)
                return "%s %s" % (e.smtp_code, errorstr)
            except smtplib.SMTPResponseException as e:
                # This exception baseclass is for all exceptions that have a SMTP response code.
                # Return the downstream error code upstream
                if isinstance(e.smtp_error, bytes):
                    errorstr = e.smtp_error.decode("utf-8", errors="ignore")
                else:
                    errorstr = str(e.smtp_error)
                _log.info("Unexpected response from server (passed upstream): %s %s", e.smtp_code, errorstr)
                return "%s %s" % (e.smtp_code, errorstr)
            except smtplib.SMTPRecipientsRefused as e:
                _log.info("Some or all recipients where refused by the downstream server: %s",
                          ", ".join(e.recipients.keys()))
                if self.error_relay_ip and self.error_relay_port:
                    with smtplib.SMTP(self.error_relay_ip, self.error_relay_port) as smtp_r:
                        try:
                            smtp_r.sendmail(
                                "<>",
                                [from_addr],
                                self._format_denied_recipients(msg, list(e.recipients.keys()))
                            )
                        except smtplib.SMTPException as ex:
                            _log.exception("Error while sending denied recipients reply: %s", str(ex))
                if set(to_addrs) == set(e.recipients.keys()):
                    # All recipients were denied. Let's tell upstream to try again. It's likely that downstream
                    # has a delivery problem (like a set sticky bit on the maildir)
                    return "421 Downstream delivery failure. Please come again."
                else:
                    # Only some recipients were denied. It's probably wrong to tell the upstream to repeat
                    # sending the email
                    return "250 Some recipients refused"
            except smtplib.SMTPServerDisconnected as e:
                _log.info("Downstream server unexpectedly disconnected: %s", str(e))
                return "421 Possible network problem. Please try again."
            return "250 Message relayed."


class SaneMessage(Message):
    def __init__(self, *args: Any) -> None:
        self.policy = compat32  # type: Policy
        self._headers = []  # type: List[Any]
        super().__init__(*args)

    def prepend(self, name: str, val: str) -> None:
        """Set the value of a header.

        Note: this does not overwrite an existing header with the same field
        name.  Use __delitem__() first to delete any existing headers.
        """
        max_count = self.policy.header_max_count(name)
        if max_count:
            lname = name.lower()
            found = 0
            for k, v in self._headers:
                if k.lower() == lname:
                    found += 1
                    if found >= max_count:
                        raise ValueError("There may be at most {} {} headers "
                                         "in a message".format(max_count, name))
        self._headers.insert(0, self.policy.header_store_parse(name, val))

    def prepend_header(self, _name: str, _value: str, **_params: Union[str, Sequence[str]]) -> None:
        """Extended header setting.

        Like add_header, but prepends the header. This is useful for Received:.

        Examples:

        msg.add_header('content-disposition', 'attachment', filename='bud.gif')
        msg.add_header('content-disposition', 'attachment',
                       filename=('utf-8', '', Fußballer.ppt'))
        msg.add_header('content-disposition', 'attachment',
                       filename='Fußballer.ppt'))
        """
        parts = []
        for k, v in _params.items():
            if v is None:
                parts.append(k.replace('_', '-'))
            else:
                parts.append(_formatparam(k.replace('_', '-'), v))
        if _value is not None:
            parts.insert(0, _value)
        self.prepend(_name, SEMISPACE.join(parts))


class SaneSMTPServer:

    server_name: str
    daemon_name: str

    def __init__(self, localaddr: AddressTuple,
                 daemon_name: str, server_name: Optional[str] = None) -> None:
        self._localaddr = localaddr
        self.server_name = socket.gethostname() if server_name is None else server_name
        self.daemon_name = daemon_name

    def add_received_header(self, peer: Tuple[str, int], helo_name: str, msg: bytes) -> bytes:
        parser = BytesParser(_class=SaneMessage, policy=_compat32_smtp_policy)
        new_msg = cast(SaneMessage, parser.parsebytes(msg))
        new_msg.prepend_header("Received",
                               "from %s (%s:%s)\r\n\tby %s (%s [%s:%s]) with SMTP;\r\n\t%s" %
                               (helo_name, peer[0], peer[1], self.server_name, self.daemon_name,
                                self._localaddr[0], self._localaddr[1],
                                timezone.now().strftime("%a, %d %b %Y %H:%M:%S %z (%Z)")))
        return new_msg.as_bytes()
