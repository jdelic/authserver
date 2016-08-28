# -* encoding: utf-8 *-
from django.contrib.auth import models as auth_models, base_user
from django.utils.translation import ugettext_lazy as _
from django.conf import settings
from django.db import models


class Domain(models.Model):
    name = models.CharField(max_length=255, unique=True)


class EmailAlias(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, related_name="aliases")
    domain = models.ForeignKey(Domain, verbose_name="On domain")
    mailprefix = models.CharField("Mail prefix", max_length=255)

    class Meta:
        unique_together = (("mailprefix", "domain"),)


class MNUser(base_user.AbstractBaseUser, auth_models.PermissionsMixin):
    identifier = models.CharField("User ID", max_length=255, unique=True)
    firstname = models.CharField("First name", max_length=255)
    lastname = models.CharField("Last name", max_length=255)

    USERNAME_FIELD = 'identifier'
    REQUIRED_FIELDS = ['firstname', 'lastname']  # password and USERNAME_FIELD are autoadded

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

    objects = MNUserManager

    def get_full_name(self) -> str:
        return "%s %s" % (self.firstname, self.lastname)

    def get_short_name(self) -> str:
        return self.identifier


class MNUserManager(base_user.BaseUserManager):
    # serializes Manager into migrations. I set this here because it's set on the default UserManager
    use_in_migrations = True

    def _create_user(self, identifier, firstname, lastname, password, **extrafields) -> MNUser:
        if not identifier:
            raise ValueError("MNUserManager._create_user requires set identifier")

        user = MNUser(identifier=MNUser.normalize_username(identifier), firstname=firstname, lastname=lastname,
                      **extrafields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    # create_superuser MUST require a password
    # see https://docs.djangoproject.com/en/1.10/topics/auth/customizing/#extending-the-existing-user-model
    def create_superuser(self, identifier, firstname, lastname, password, **extrafields) -> MNUser:
        extrafields["is_superuser"] = True
        extrafields["is_staff"] = True
        return self._create_user(identifier, firstname, lastname, password, **extrafields)

    def create_user(self, identifier, firstname, lastname, password=None, **extrafields) -> MNUser:
        extrafields.setdefault("is_superuser", False)
        extrafields.setdefault("is_staff", False)
        return self._create_user(identifier, firstname, lastname, password, **extrafields)
