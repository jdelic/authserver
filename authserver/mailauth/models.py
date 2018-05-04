# -* encoding: utf-8 *-
import uuid

from django.contrib.auth import models as auth_models, base_user
from django.conf import settings
from django.contrib.auth.hashers import make_password
from django.contrib.postgres.fields.array import ArrayField
from django.core.exceptions import ValidationError
from django.db import models
from typing import Any, Optional, Set, Iterable, Union, List

from django.db.models import Manager
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


class DomainManager(Manager):
    def find_parent_domain(self, fqdn: str, require_jwt_subdomains_set: bool=True) -> 'Domain':
        req_domain = None  # type: Optional[Domain]

        # results in ['sub.example.com', 'example.com', 'com']
        parts = fqdn.split(".")
        for domainstr in [".".join(parts[r:]) for r in range(0, len(parts))]:
            try:
                req_domain = self.get(name=domainstr)
            except Domain.DoesNotExist:
                continue
            else:
                if req_domain is None or req_domain.jwtkey == "":
                    req_domain = None
                    continue

                if req_domain.jwtkey is not None and req_domain.jwtkey != "":
                    if domainstr == fqdn or (req_domain.jwt_subdomains and require_jwt_subdomains_set):
                        break
                    elif not require_jwt_subdomains_set:
                        # we have a domain which has a jwtkey and we don't require jwt_subdomains to be True, so
                        # we return the current result
                        break
                    elif require_jwt_subdomains_set and not req_domain.jwt_subdomains:
                        # prevent the case where domainstr is the last str in parts, it matches, has a jwtkey but
                        # is not valid for subdomains. req_domain would be != None in that case and the loop would exit
                        req_domain = None
                        continue

        if req_domain is None:
            raise Domain.DoesNotExist()

        return req_domain


class Domain(models.Model):
    name = models.CharField(max_length=255, unique=True)
    dkimselector = models.CharField(verbose_name="DKIM DNS selector", max_length=255, null=False, blank=True,
                                    default="default")
    dkimkey = models.TextField(verbose_name="DKIM private key (PEM)", blank=True)
    jwtkey = models.TextField(verbose_name="JWT signing key (PEM)", blank=True)
    jwt_subdomains = models.BooleanField(verbose_name="Use JWT key to sign for subdomains", default=False)
    redirect_to = models.CharField(verbose_name="Redirect all mail to domain", max_length=255, null=False, blank=True,
                                   default="")

    objects = DomainManager()

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
    domain = models.ForeignKey(Domain, verbose_name="On domain", on_delete=models.CASCADE)
    mailprefix = models.CharField("Mail prefix", max_length=255)
    forward_to = models.ForeignKey(MailingList, verbose_name="Forward to list", on_delete=models.CASCADE, null=True,
                                   blank=True)

    def clean(self) -> None:
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

    name = models.CharField("Group name", max_length=255, unique=True)

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


class UnresolvableUserException(Exception):
    pass


class MNUserManager(base_user.BaseUserManager):
    # serializes Manager into migrations. I set this here because it's set on the default UserManager
    use_in_migrations = True

    def _create_user(self, identifier: str, fullname: str, password: Optional[str], **extrafields: Any) -> 'MNUser':
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

    def create_user(self, identifier: str, fullname: str, password: Optional[str]=None, **extrafields: Any) -> 'MNUser':
        extrafields.setdefault("is_superuser", False)
        extrafields.setdefault("is_staff", False)
        return self._create_user(identifier, fullname, password, **extrafields)

    def resolve_user(self, username: str) -> 'MNUser':
        """
        :param username: the username to find
        :raises UnresolvableUserException: When no user can be found
        :return: The user
        """
        if "@" not in username or username.count("@") > 1:
            try:
                service_user = MNServiceUser.objects.get(username=username)
            except (MNServiceUser.DoesNotExist, ValidationError):
                try:
                    user = MNUser.objects.get(identifier=username)
                except MNUser.DoesNotExist as e:
                    raise UnresolvableUserException() from e
            else:
                # It's a valid MNServiceUser
                user = service_user.user
        else:
            mailprefix, domain = username.split("@")

            try:
                Domain.objects.get(name=domain)
            except Domain.DoesNotExist as e:
                raise UnresolvableUserException() from e

            try:
                user = EmailAlias.objects.get(mailprefix__istartswith=mailprefix, domain__name=domain).user
            except EmailAlias.DoesNotExist as e:
                raise UnresolvableUserException() from e

        return user


class PasswordMaskMixin:
    def _get_sha256_password(self) -> str:
        # pretend to return a Django crypt format password string
        from mailauth.auth import UnixCryptCompatibleSHA256Hasher
        attr = super().__getattribute__('password')
        if isinstance(attr, str):
            if attr.startswith(UnixCryptCompatibleSHA256Hasher.algorithm):
                return attr
            else:
                return "%s%s" % (UnixCryptCompatibleSHA256Hasher.algorithm, attr)
        return attr

    def _set_sha256_password(self, value: Any) -> None:
        # pretend to be a standard CharField
        from mailauth.auth import UnixCryptCompatibleSHA256Hasher
        if isinstance(value, str):
            if value.startswith(UnixCryptCompatibleSHA256Hasher.algorithm):
                # call superclass __setattr__ to avoid infinite recursion
                super().__setattr__('password', value[len(UnixCryptCompatibleSHA256Hasher.algorithm):])
                return
        super().__setattr__('password', value)

    # hacky hacky this will breaky at some point in the future
    # but it's the solution that allows the most code reuse from django.contrib.auth
    # without having two password columns in the database table
    def __setattr__(self, key: str, value: Any) -> None:
        if key == "password":
            self._set_sha256_password(value)
        else:
            super().__setattr__(key, value)

    def __getattribute__(self, item: str) -> Any:
        if item == "password":
            return self._get_sha256_password()
        else:
            return super().__getattribute__(item)


class MNUser(base_user.AbstractBaseUser, PasswordMaskMixin, auth_models.PermissionsMixin):
    class Meta:
        verbose_name_plural = "User accounts"

    uuid = models.UUIDField("Shareable ID", default=uuid.uuid4, editable=False, primary_key=True)
    identifier = models.CharField("User ID", max_length=255, unique=True, db_index=True)
    password = PretendHasherPasswordField("Password", max_length=128)
    fullname = models.CharField("Full name", max_length=255)
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

    def get_full_name(self) -> str:
        return "%s %s" % (self.firstname, self.lastname)

    def get_short_name(self) -> str:
        return self.identifier

    def get_all_app_permissions(self) -> Set[MNApplicationPermission]:
        user_permissions = set(self.app_permissions.all())
        for group in self.app_groups.all():
            user_permissions.update(group.group_permissions.all())
        return user_permissions

    def get_all_app_permission_strings(self) -> List[str]:
        return [p.scope_name for p in self.get_all_app_permissions()]

    def has_app_permission(self, perm: str) -> bool:
        return perm in self.get_all_app_permissions()

    def has_app_permissions(self, perms: Iterable[str]) -> bool:
        return set(self.get_all_app_permission_strings()).issuperset(set(perms))


class MNServiceUser(PasswordMaskMixin, models.Model):
    """
    Service users are usernames and passwords that alias a valid user. This is useful when usernames
    and passwords must be shared with a service that doesn't support OAuth2/OpenID connect or requires
    the Resource Owner flow, but isn't always used from a trustworthy client.
    """
    class Meta:
        verbose_name = "Service User"
        verbose_name_plural = "Service Users"

    user = models.ForeignKey(MNUser, on_delete=models.CASCADE, null=False, blank=False)
    username = models.CharField("Username", default=uuid.uuid4, max_length=64)
    password = PretendHasherPasswordField("Password", max_length=128)
    description = models.CharField(max_length=255, blank=True, null=False, default='')

    def set_password(self, raw_password: str) -> None:
        self.password = make_password(raw_password)

    def clean(self) -> None:
        # use user_id instead of self.user to avoid an ObjectDoesNotExist exception when self.user is None
        if self.user_id is not None and self.user.delivery_mailbox is None:
            raise ValidationError("Service users can only be added for users with a delivery mailbox")

    def __str__(self) -> str:
        return "%s (%s)" % (self.username, self.user.identifier,)


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
