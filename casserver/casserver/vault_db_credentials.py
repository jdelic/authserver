# -* encoding: utf-8 *-
import datetime
import logging
from typing import Dict

import hvac
import pytz
from requests.exceptions import RequestException


_log = logging.getLogger(__name__)


class VaultCredentialProviderException(Exception):
    pass


class VaultCredentialProvider:
    def __init__(self, vaulturl: str, accesstoken: str, secretpath: str, pin_cacert: str=None,
                 ssl_verify: bool=False, debug_output: bool=False) -> None:
        self.vaulturl = vaulturl
        self.accesstoken = accesstoken
        self.secretpath = secretpath
        self.pin_cacert = pin_cacert
        self.ssl_verify = ssl_verify
        self.debug_output = debug_output
        self._cache = None  # type: Dict[str. str]
        self._leasetime = None  # type: datetime.datetime
        self._updatetime = None  # type: datetime.datetime
        self._lease_id = None  # type: str

    def _now(self):
        return datetime.datetime.now(tz=pytz.UTC)

    def _refresh(self):
        vcl = hvac.Client(url=self.vaulturl,
                          token=self.accesstoken,
                          verify=self.pin_cacert if self.pin_cacert else self.ssl_verify)

        if not vcl.is_authenticated():
            raise VaultCredentialProviderException(
                "Unable to authenticate with provided Vault token. Token: %s" %
                self.accesstoken if self.debug_output else "Token withheld, debug output is disabled"
            )

        try:
            result = vcl.read(self.secretpath)
        except RequestException as e:
            raise VaultCredentialProviderException(
                "Unable to read credentials from path '%s' with request error: %s" %
                (self.secretpath, str(e))
            ) from e

        if "data" not in result or "username" not in result["data"] or "password" not in result["data"]:
            raise VaultCredentialProviderException(
                "Read dict from Vault path %s did not match expected structure (data->{username, password}): %s" %
                (self.secretpath, str(result))
            )

        self._cache = result["data"]
        self._lease_id = result["lease_id"]
        self._leasetime = self._now()
        self._updatetime = self._leasetime + datetime.timedelta(seconds=int(result["lease_duration"]))

        _log.debug("Loaded new Vault DB credentials for %s:\nlease_id=%s\nleasetime=%s\nduration=%s\n"
                   "username=%s\npassword=%s",
                   self._lease_id, str(self._leasetime), result["lease_duration"], self._cache["username"],
                   self._cache["password"] if self.debug_output else "Password withheld, debug output is disabled")

    def _get_or_update(self, key):
        if self._cache is None or (self._updatetime - self._now()).total_seconds() < 10:
            # if we have less than 10 seconds in a lease ot no lease at all, we get new credentials
            _log.info("Vault DB credential lease has expired, refreshing for %s" % key)
            self._refresh()
            _log.info("refresh done (%s, %s)" % (self._lease_id, str(self._updatetime)))

        return self._cache[key]

    @property
    def username(self) -> str:
        return self._get_or_update("username")

    @property
    def password(self) -> str:
        return self._get_or_update("password")
