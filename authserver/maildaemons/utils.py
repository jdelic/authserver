# -* encoding: utf-8 *-
import logging
import smtplib
from typing import Any, Union


_log = logging.getLogger(__name__)


def smtp_sendmail_wrapper(smtpobj: smtplib.SMTP, *args: Any, **kwargs: Any) -> Union[str, None]:
    """
    Wraps smtp.sendmail and handles all the exceptions it can throw
    :param smtpobj: the smtplib.SMTP object to wrap
    :param args: will be passed to .sendmail
    :param kwargs: will be passed to .sendmail
    :return: a SMTP return string or None
    """
    try:
        smtpobj.sendmail(*args, **kwargs)
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
        # TODO: find good error code
    except smtplib.SMTPServerDisconnected as e:
        _log.info("Downstream server unexpectedly disconnected: %s", str(e))
        return "421 Possible network problem. Please try again."
    return None
