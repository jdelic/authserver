# -* encoding: utf-8 *-
from collections import OrderedDict
from typing import Tuple

from django.contrib.auth import hashers
from django.utils.translation import ugettext_lazy as _
from mailauth.models import Domain, EmailAlias, MNUser

# noinspection PyUnresolvedReferences
from passlib.hash import sha256_crypt


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
        return sha256_crypt.verify(password, encoded)

    def encode(self, password: str, salt: str) -> str:
        """
        Creates an encoded database value

        The result is normally formatted as "algorithm$salt$hash" and
        must be fewer than 128 characters.
        """
        return sha256_crypt.encrypt(password, salt=salt, rounds=UnixCryptCompatibleSHA256Hasher.rounds)

    def safe_summary(self, encoded):
        """
        Returns a summary of safe values

        The result is a dictionary and will be used where the password field
        must be displayed to construct a safe representation of the password.
        """
        roundcount, salt, hash = self._split_encoded(encoded)
        return OrderedDict([
            (_('algorithm'), "sha256_crypt"),
            (_('iterations'), str(roundcount)),
            (_('salt'), hashers.mask_hash(salt)),
            (_('hash'), hashers.mask_hash(hash)),
        ])

    def must_update(self, encoded):
        return False

    def harden_runtime(self, password, encoded):
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
    def authenticate(self, email: str, password: str) -> MNUser:
        if "@" not in email or email.count("@") > 1:
            return None

        mailprefix, domain = email.split("@")

        if Domain.objects.filter(name=domain).count() == 0:
            return None

        try:
            user = EmailAlias.objects.get(mailprefix__istartswith=mailprefix, domain__name=domain).user
        except EmailAlias.DoesNotExist:
            return None

        if hashers.check_password(password, user.password):
            return user
        else:
            return None

    def get_user(self, user_id: str) -> MNUser:
        try:
            return MNUser.objects.get(uuid=user_id)
        except MNUser.DoesNotExist:
            return None
