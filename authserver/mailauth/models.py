# -* encoding: utf-8 *-
import logging
import uuid

from django.contrib.auth import models as auth_models, base_user
from django.db.backends.base.base import BaseDatabaseWrapper
from django.utils.translation import ugettext_lazy as _
from django.conf import settings
from django.db import models
from typing import Any

#
# The data model here is:
#     - the org owns D domains
#     - a user account has 1:N email aliases
#     - 1 email alias belongs to 1 domain
#     - a user will be able to authenticate to the app using any of his aliases and his password
#     - 'identifier' is meaningless for authentication
#


class Domain(models.Model):
    name = models.CharField(max_length=255, unique=True)


class EmailAlias(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, related_name="aliases")
    domain = models.ForeignKey(Domain, verbose_name="On domain")
    mailprefix = models.CharField("Mail prefix", max_length=255)

    class Meta:
        unique_together = (("mailprefix", "domain"),)


class MNUserManager(base_user.BaseUserManager):
    # serializes Manager into migrations. I set this here because it's set on the default UserManager
    use_in_migrations = True

    def _create_user(self, identifier: str, firstname: str, lastname: str, password: str,
                     **extrafields: Any) -> 'MNUser':
        if not identifier:
            raise ValueError("MNUserManager._create_user requires set identifier")

        user = MNUser(identifier=MNUser.normalize_username(identifier), firstname=firstname, lastname=lastname,
                      **extrafields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    # create_superuser MUST require a password
    # see https://docs.djangoproject.com/en/1.10/topics/auth/customizing/#extending-the-existing-user-model
    def create_superuser(self, identifier: str, firstname: str, lastname: str, password: str,
                         **extrafields: Any) -> 'MNUser':
        extrafields["is_superuser"] = True
        extrafields["is_staff"] = True
        return self._create_user(identifier, firstname, lastname, password, **extrafields)

    def create_user(self, identifier: str, firstname: str, lastname: str, password: str=None,
                    **extrafields: Any) -> 'MNUser':
        extrafields.setdefault("is_superuser", False)
        extrafields.setdefault("is_staff", False)
        return self._create_user(identifier, firstname, lastname, password, **extrafields)


class PretendHasherPasswordField(models.CharField):
    def get_prep_value(self, value: str) -> str:
        logging.debug("get_prep_value %s", value)
        from mailauth.auth import UnixCryptCompatibleSHA256Hasher
        if value.startswith(UnixCryptCompatibleSHA256Hasher.algorithm):
            return value[len(UnixCryptCompatibleSHA256Hasher.algorithm):]
        else:
            return value


class MNUser(base_user.AbstractBaseUser, auth_models.PermissionsMixin):
    identifier = models.CharField("User ID", max_length=255, unique=True, db_index=True)
    uuid = models.UUIDField("Shareable ID", default=uuid.uuid4, editable=False, primary_key=True)
    firstname = models.CharField("First name", max_length=255)
    lastname = models.CharField("Last name", max_length=255)
    sha256_password = PretendHasherPasswordField(_("password"), max_length=128)

    USERNAME_FIELD = 'identifier'
    # password and USERNAME_FIELD are autoadded to REQUIRED_FIELDS.
    REQUIRED_FIELDS = ['firstname', 'lastname']

    is_staff = models.BooleanField(
        _("staff status"),
        default=False,
        help_text=_("Designates whether the user can log into this admin site."),
    )

    is_active = models.BooleanField(
        _("active"),
        default=True,
        help_text=_(
            "Designates whether this user should be treated as active. "
            "Unselect this instead of deleting accounts."
        ),
    )

    objects = MNUserManager()

    @property
    def password(self) -> str:
        from mailauth.auth import UnixCryptCompatibleSHA256Hasher
        if self.sha256_password.startswith(UnixCryptCompatibleSHA256Hasher.algorithm):
            logging.debug("getter direct %s", self.sha256_password)
            return self.sha256_password
        else:
            logging.debug("getter %s%s", UnixCryptCompatibleSHA256Hasher.algorithm, self.sha256_password)
            return "%s%s" % (UnixCryptCompatibleSHA256Hasher.algorithm, self.sha256_password)

    @password.setter
    def password(self, value: str) -> None:
        logging.debug("setter %s", value)
        self.sha256_password = value

    def get_full_name(self) -> str:
        return "%s %s" % (self.firstname, self.lastname)

    def get_short_name(self) -> str:
        return self.identifier
