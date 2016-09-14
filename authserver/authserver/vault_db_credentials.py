# -* encoding: utf-8 *-
import datetime
import logging
import os
from typing import Dict, Tuple, Union, Any

import hvac
import pytz
from requests.exceptions import RequestException


_log = logging.getLogger(__name__)


class VaultCredentialProviderException(Exception):
    pass


class VaultAuthentication:
    def __init__(self) -> None:
        self.credentials = None  # type: Union[str, Tuple[str, str]]
        self.authtype = None  # type: str
        self.unwrap_response = False
        super().__init__()

    @staticmethod
    def app_id(app_id: str, user_id: str) -> 'VaultAuthentication':
        i = VaultAuthentication()
        i.credentials = (app_id, user_id)
        i.authtype = "app-id"
        return i

    @staticmethod
    def ssl_client_cert(certfile: str, keyfile: str) -> 'VaultAuthentication':
        if not os.path.isfile(certfile) or not os.access(certfile, os.R_OK):
            raise VaultCredentialProviderException("File not found or not readable: %s" % certfile)

        if not os.path.isfile(keyfile) or not os.access(keyfile, os.R_OK):
            raise VaultCredentialProviderException("File not found or not readable: %s" % keyfile)

        i = VaultAuthentication()
        i.credentials = (certfile, keyfile)
        i.authtype = "ssl"
        return i

    @staticmethod
    def token(token: str) -> 'VaultAuthentication':
        i = VaultAuthentication()
        i.credentials = token
        i.authtype = "token"
        return i

    @staticmethod
    def has_envconfig() -> bool:
        if (os.getenv("VAULT_TOKEN", None) or
           (os.getenv("VAULT_APPID", None) and os.getenv("VAULT_USERID", None)) or
           (os.getenv("VAULT_SSLCERT", None) and os.getenv("VAULT_SSLKEY", None))):
            return True

        return False

    @staticmethod
    def fromenv() -> 'VaultAuthentication':
        i = None
        if os.getenv("VAULT_TOKEN", None):
            i = VaultAuthentication.token(os.getenv("VAULT_TOKEN"))
        elif os.getenv("VAULT_APPID", None) and os.getenv("VAULT_USERID", None):
            i = VaultAuthentication.app_id(os.getenv("VAULT_APPID"), os.getenv("VAULT_USERID"))
        elif os.getenv("VAULT_SSLCERT", None) and os.getenv("VAULT_SSLKEY", None):
            i = VaultAuthentication.ssl_client_cert(os.getenv("VAULT_SSLCERT"), os.getenv("VAULT_SSLKEY"))

        if i:
            e = os.getenv("VAULT_UNWRAP", "False")
            if e.lower() in ["true", "1", "yes"]:
                i.unwrap_response = True
            return i

        raise VaultCredentialProviderException("Unable to configure Vault authentication from the environment")

    def authenticated_client(self, *args: Any, **kwargs: Any) -> hvac.Client:
        if self.authtype == "token":
            cl = hvac.Client(token=self.credentials, *args, **kwargs)
        elif self.authtype == "app-id":
            cl = hvac.Client(*args, **kwargs)
            cl.auth_app_id(*self.credentials)
        elif self.authtype == "ssl":
            cl = hvac.Client(cert=self.credentials, *args, **kwargs)
            cl.auth_tls()
        else:
            raise VaultCredentialProviderException("no auth config")

        if not cl.is_authenticated():
            raise VaultCredentialProviderException("Unable to authenticate Vault client using provided credentials "
                                                   "(type=%s)" % self.authtype)
        return cl


class VaultCredentialProvider:
    def __init__(self, vaulturl: str, vaultauth: VaultAuthentication, secretpath: str, pin_cacert: str=None,
                 ssl_verify: bool=False, debug_output: bool=False) -> None:
        self.vaulturl = vaulturl
        self._vaultauth = vaultauth
        self.secretpath = secretpath
        self.pin_cacert = pin_cacert
        self.ssl_verify = ssl_verify
        self.debug_output = debug_output
        self._cache = None  # type: Dict[str, str]
        self._leasetime = None  # type: datetime.datetime
        self._updatetime = None  # type: datetime.datetime
        self._lease_id = None  # type: str

    def _now(self) -> datetime.datetime:
        return datetime.datetime.now(pytz.timezone("UTC"))

    def _refresh(self) -> None:
        vcl = self._vaultauth.authenticated_client(
            url=self.vaulturl,
            verify=self.pin_cacert if self.pin_cacert else self.ssl_verify
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

    def _get_or_update(self, key: str) -> str:
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
