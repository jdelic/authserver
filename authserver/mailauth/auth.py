# -* encoding: utf-8 *-
import logging
from collections import OrderedDict
from typing import Tuple, Dict, Optional

from django.contrib.auth import hashers
from django.core.exceptions import ValidationError
from django.utils.translation import ugettext_lazy as _
from typing import Union

from mailauth.models import Domain, EmailAlias, MNUser, MNServiceUser
# noinspection PyUnresolvedReferences
from passlib.hash import sha256_crypt


_log = logging.getLogger(__name__)


class UnixCryptCompatibleSHA256Hasher(object):
    """
    This uses passlib to implement a Django password hasher that encodes passwords using
    the Debian mkpasswd supported "lowest common denominator but still secure" password
    storage algorithm SHA256_crypt. **Unlike** Django's hashers, however, this hasher
    stores the password string in modular crypt format, this way making the database
    entry compatible with other tools reading directly from the database.
    """

    # double the default
    rounds = 1070000  # type: int
    # algorithm must be non-empty for hackish compatibility with django.contrib.auth.hashers so
    # identify_hasher can find us
    algorithm = "sha256_passlib"  # type: str

    def _split_encoded(self, encoded: str) -> Tuple[int, str, str]:
        _, five, rounds, salt, hash = encoded.split("$")

        if five != "5":
            raise ValueError("Not a SHA256 crypt hash %s" % encoded)

        if not rounds.startswith("rounds="):
            raise ValueError("Rounds parameter not found or garbled %s" % encoded)

        roundcount = int(rounds[len("rounds="):])

        return roundcount, salt, hash

    def salt(self) -> str:
        """
        Generates a cryptographically secure nonce salt in ASCII
        """
        return hashers.get_random_string()

    def verify(self, password: str, encoded: str) -> bool:
        """
        Checks if the given password is correct
        """
        # we get passed the value modified by the password getter in MNUser, so we need to remove
        # the fake algorithm identification string
        if encoded.startswith(self.algorithm):
            encoded = encoded[len(self.algorithm):]
        return sha256_crypt.verify(password, encoded)

    def encode(self, password: str, salt: str) -> str:
        """
        Creates an encoded database value

        The result is normally formatted as "algorithm$salt$hash" and
        must be fewer than 128 characters.
        """
        return sha256_crypt.encrypt(password, salt=salt, rounds=UnixCryptCompatibleSHA256Hasher.rounds)

    def safe_summary(self, encoded: str) -> Dict[str, str]:
        """
        Returns a summary of safe values

        The result is a dictionary and will be used where the password field
        must be displayed to construct a safe representation of the password.
        """
        roundcount, salt, hash = self._split_encoded(encoded)
        return OrderedDict([
            (_('algorithm'), self.algorithm),
            (_('iterations'), str(roundcount)),
            (_('salt'), hashers.mask_hash(salt)),
            (_('hash'), hashers.mask_hash(hash)),
        ])

    def must_update(self, encoded: str) -> bool:
        return False

    def harden_runtime(self, password: str, encoded: str) -> None:
        """
        Bridge the runtime gap between the work factor supplied in `encoded`
        and the work factor suggested by this hasher.

        Taking PBKDF2 as an example, if `encoded` contains 20000 iterations and
        `self.iterations` is 30000, this method should run password through
        another 10000 iterations of PBKDF2. Similar approaches should exist
        for any hasher that has a work factor. If not, this method should be
        defined as a no-op to silence the warning.
        """
        roundcount, salt, hash = self._split_encoded(encoded)
        extra_rounds = UnixCryptCompatibleSHA256Hasher.rounds - roundcount
        if extra_rounds > 0:
            sha256_crypt.encrypt(password, salt=salt, rounds=extra_rounds)


class MNUserAuthenticationBackend(object):
    def authenticate(self, username: str, password: str) -> Optional[MNUser]:
        # the argument names must be 'username' and 'password' because the authenticator interface is tightly coupled
        # to the parameter names between login forms and authenticators

        tocheck_password = None  # type: Optional[str]
        if "@" not in username or username.count("@") > 1:
            try:
                service_user = MNServiceUser.objects.get(username=username)
            except (MNServiceUser.DoesNotExist, ValidationError):
                try:
                    user = MNUser.objects.get(identifier=username)
                except MNUser.DoesNotExist:
                    _log.debug("No user found %s for identifier login", username)
                    return None

                # if the user is a staff user, they may also log in using their identifier
                if user.is_staff:
                    _log.debug("User %s is staff, allowing identifier login", username)
                    if hashers.check_password(password, user.password):
                        _log.debug("User %s logged in with correct password", username)
                        return user
                    else:
                        _log.debug("Incorrect password for user %s (%s)", username, user.password)
                else:
                    _log.debug("Must provide an email address. %s is not an email address", username)
                    return None
            else:
                # It's a valid MNServiceUser
                _log.debug("Logging in service user %s as %s", service_user.username, service_user.user.identifier)
                tocheck_password = service_user.password
                user = service_user.user
        else:
            _log.debug("logging in email alis %s", username)
            mailprefix, domain = username.split("@")

            if Domain.objects.filter(name=domain).count() == 0:
                _log.debug("Domain %s does not exist", domain)
                return None

            try:
                user = EmailAlias.objects.get(mailprefix__istartswith=mailprefix, domain__name=domain).user
            except EmailAlias.DoesNotExist:
                return None
            else:
                tocheck_password = user.password

        if hashers.check_password(password, tocheck_password):
            return user
        else:
            return None

    def get_user(self, user_id: str) -> Optional[MNUser]:
        try:
            return MNUser.objects.get(uuid=user_id)
        except MNUser.DoesNotExist:
            return None
