# -* encoding: utf-8 *-
import uuid

from django.contrib.auth import models as auth_models, base_user
from django.conf import settings
from django.contrib.postgres.fields.array import ArrayField
from django.core.exceptions import ValidationError
from django.db import models
from typing import Any

from oauth2_provider import models as oauth2_models

#
# The data model here is:
#     - the org owns D domains
#     - a user account has 1:N email aliases
#     - 1 email alias belongs to 1 domain
#     - a user will be able to authenticate to the app using any of his aliases and his password
#     - the user 'identifier' is meaningless for authentication
#


class PretendHasherPasswordField(models.CharField):
    """
    This just makes sure that no mention of sha256_passlib makes it into the database, even when
    Django sidesteps the Model instance which has a property below and instantiates the Field class
    directly.
    """
    def get_prep_value(self, value: str) -> str:
        # we might get a value previously modified by the password getter below. In that case we remove
        # the unwanted prefix.
        from mailauth.auth import UnixCryptCompatibleSHA256Hasher
        if value.startswith(UnixCryptCompatibleSHA256Hasher.algorithm):
            return value[len(UnixCryptCompatibleSHA256Hasher.algorithm):]
        else:
            return value

    def value_from_object(self, obj: Any) -> str:
        from mailauth.auth import UnixCryptCompatibleSHA256Hasher
        value = super().value_from_object(obj)
        if value.startswith(UnixCryptCompatibleSHA256Hasher.algorithm):
            return value
        else:
            return "%s%s" % (UnixCryptCompatibleSHA256Hasher.algorithm, value)


class Domain(models.Model):
    name = models.CharField(max_length=255, unique=True)
    dkimselector = models.CharField(verbose_name="DKIM DNS selector", max_length=255, null=False, blank=True,
                                    default="default")
    dkimkey = models.TextField(verbose_name="DKIM private key (PEM)", blank=True)
    redirect_to = models.CharField(verbose_name="Redirect all mail to domain", max_length=255, null=False, blank=True,
                                   default="")

    def __str__(self) -> str:
        return self.name


class MailingList(models.Model):
    name = models.CharField("Descriptive name", max_length=255)
    addresses = ArrayField(models.EmailField(max_length=255))
    new_mailfrom = models.EmailField(max_length=255, null=False, blank=True, default="")

    def __str__(self) -> str:
        return self.name


class EmailAlias(models.Model):
    class Meta:
        unique_together = (('mailprefix', 'domain'),)
        verbose_name_plural = "Email aliases"

    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="aliases",
                             null=True, blank=True)
    domain = models.ForeignKey(Domain, verbose_name="On domain")
    mailprefix = models.CharField("Mail prefix", max_length=255)
    forward_to = models.ForeignKey(MailingList, verbose_name="Forward to list", null=True, blank=True)

    def clean(self):
        if hasattr(self, 'forward_to') and self.forward_to is not None \
                and hasattr(self, 'user') and self.user is not None:
            raise ValidationError({'forward_to': "An email alias can't be associated with a user and be a mailing list "
                                                 "at the same time"})

        if not hasattr(self, 'forward_to') and not hasattr(self, 'user'):
            raise ValidationError({'user': "An email alias must either be a mailing list or be associated with an "
                                           "user."})

    def __str__(self) -> str:
        s = "%s@%s" % (self.mailprefix, self.domain,)
        if self.user is not None:
            s = "%s (Belongs to: %s)" % (s, self.user.identifier,)
        elif self.forward_to is not None:
            s = "%s (List: %s)" % (s, self.forward_to.name,)
        return s


class MNApplicationPermission(models.Model):
    class Meta:
        verbose_name = "application permissions"
        verbose_name_plural = "Application permissions"

    name = models.CharField("Human readable name", max_length=255, blank=True, null=False)
    scope_name = models.CharField("OAuth2 scope string", max_length=255, blank=False, null=True, unique=True)

    def __str__(self) -> str:
        return "%s (%s)" % (self.name, self.scope_name)


class MNGroup(models.Model):
    class Meta:
        verbose_name = "OAuth2/CAS Groups"
        verbose_name_plural = "OAuth2/CAS Groups"

    name = models.CharField("Group name", max_length=255)

    group_permissions = models.ManyToManyField(
        MNApplicationPermission,
        verbose_name="Application permissions",
        blank=True,
        help_text="Permissions for OAuth2/CAS applications",
        related_name='group_set',
        related_query_name='group',
    )

    def __str__(self) -> str:
        return self.name


class MNUserManager(base_user.BaseUserManager):
    # serializes Manager into migrations. I set this here because it's set on the default UserManager
    use_in_migrations = True

    def _create_user(self, identifier: str, fullname: str, password: str, **extrafields: Any) -> 'MNUser':
        if not identifier:
            raise ValueError("MNUserManager._create_user requires set identifier")

        user = MNUser(identifier=MNUser.normalize_username(identifier), fullname=fullname,
                      **extrafields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    # create_superuser MUST require a password
    # see https://docs.djangoproject.com/en/1.10/topics/auth/customizing/#extending-the-existing-user-model
    def create_superuser(self, identifier: str, fullname: str, password: str, **extrafields: Any) -> 'MNUser':
        extrafields["is_superuser"] = True
        extrafields["is_staff"] = True
        return self._create_user(identifier, fullname, password, **extrafields)

    def create_user(self, identifier: str, fullname: str, password: str=None, **extrafields: Any) -> 'MNUser':
        extrafields.setdefault("is_superuser", False)
        extrafields.setdefault("is_staff", False)
        return self._create_user(identifier, fullname, password, **extrafields)


class MNUser(base_user.AbstractBaseUser, auth_models.PermissionsMixin):
    class Meta:
        verbose_name_plural = "User accounts"

    uuid = models.UUIDField("Shareable ID", default=uuid.uuid4, editable=False, primary_key=True)
    identifier = models.CharField("User ID", max_length=255, unique=True, db_index=True)
    fullname = models.CharField("Full name", max_length=255)
    password = PretendHasherPasswordField("Password", max_length=128)
    delivery_mailbox = models.OneToOneField(EmailAlias, on_delete=models.PROTECT, null=True)

    pgp_key_id = models.CharField("PGP Key ID", max_length=64, blank=True, default="")
    yubikey_serial = models.CharField("Yubikey Serial", max_length=64, blank=True, default="")

    USERNAME_FIELD = 'identifier'
    # password and USERNAME_FIELD are autoadded to REQUIRED_FIELDS.
    REQUIRED_FIELDS = ['fullname', ]

    is_staff = models.BooleanField(
        "Staff status",
        default=False,
        help_text="Designates whether the user can log into this admin site.",
    )

    is_active = models.BooleanField(
        "Active",
        default=True,
        help_text="Designates whether this user should be treated as active. "
                  "Unselect this instead of deleting accounts.",
    )

    app_permissions = models.ManyToManyField(
        MNApplicationPermission,
        verbose_name="OAuth2/CAS Application permissions",
        blank=True,
        help_text="Permissions for networkapplications",
        related_name='user_set',
        related_query_name='user',
    )

    app_groups = models.ManyToManyField(
        MNGroup,
        verbose_name="OAuth2/CAS Groups",
        blank=True,
        related_name="user_set",
        related_query_name='user',
    )

    objects = MNUserManager()

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._masked_password = self.password  # type: str

        # hacky hacky this will breaky at some point in the future
        # but it's the solution that allows the most code reuse from django.contrib.auth
        # without having two password columns in the database table
        setattr(self.__class__, 'password',
                property(fget=MNUser._get_sha256_password, fset=MNUser._set_sha256_password))

    def _get_sha256_password(self) -> str:
        # pretend to return a Django crypt format password string
        from mailauth.auth import UnixCryptCompatibleSHA256Hasher
        if isinstance(self._masked_password, str):
            if self._masked_password.startswith(UnixCryptCompatibleSHA256Hasher.algorithm):
                return self._masked_password
            else:
                return "%s%s" % (UnixCryptCompatibleSHA256Hasher.algorithm, self._masked_password)
        return self._masked_password

    def _set_sha256_password(self, value: str) -> None:
        # pretend to be a standard CharField
        from mailauth.auth import UnixCryptCompatibleSHA256Hasher
        if isinstance(value, str):
            if value.startswith(UnixCryptCompatibleSHA256Hasher.algorithm):
                self._masked_password = value[len(UnixCryptCompatibleSHA256Hasher.algorithm):]
                return
        self._masked_password = value

    def get_full_name(self) -> str:
        return "%s %s" % (self.firstname, self.lastname)

    def get_short_name(self) -> str:
        return self.identifier


class MNApplication(oauth2_models.AbstractApplication):
    """
    Add permissions to applications. They are permissions that applications are *allowed to request
    as scopes*.
    """

    class Meta:
        verbose_name_plural = "OAuth2 Applications"

    required_permissions = models.ManyToManyField(
        MNApplicationPermission,
        verbose_name="required permissions",
        blank=True,
        help_text="Permissions required for this application",
        related_name='application_set',
        related_query_name='application',
    )

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
