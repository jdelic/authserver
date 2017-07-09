# -* encoding: utf-8 *-
from django.db import models

from oauth2_provider.generators import generate_client_id

from dockerauth.permissions import TokenPermissions
from mailauth.models import MNUser, MNGroup


def generate_jwt_secret_key() -> str:
    pass


class DockerPermissionBaseManager(models.Manager):
    def has_access(self, user: MNUser, scope: TokenPermissions) -> bool:
        user_permissions = set()


class DockerPermissionBase(models.Model):
    class Meta:
        abstract = True

    unauthenticated_pull = models.BooleanField("Allow unauthenticated pull",
                                               default=False, null=False)
    unauthenticated_push = models.BooleanField("Allow unauthenticated push",
                                               default=False, null=False)

    user_pull_access = models.ManyToManyField(
        MNUser,
        verbose_name="Users with pull access (read)",
        blank=True,
        related_name='%(class)s_pull_access',
    )

    user_push_access = models.ManyToManyField(
        MNUser,
        verbose_name="Users with push access (write)",
        blank=True,
        related_name='%(class)s_push_access',
    )

    group_pull_access = models.ManyToManyField(
        MNGroup,
        verbose_name="Groups with pull access (read)",
        blank=True,
        related_name='%(class)s_pull_access',
    )

    group_push_access = models.ManyToManyField(
        MNGroup,
        verbose_name="Groups with push access (write)",
        blank=True,
        related_name='%(class)s_push_access',
    )


class DockerRegistry(DockerPermissionBase):
    name = models.CharField(
        "Name", max_length=255, null=False, blank=False,
        help_text="Human readable name"
    )

    client_id = models.CharField(
        max_length=100, unique=True, default=generate_client_id, db_index=True
    )

    sign_key = models.TextField(
        verbose_name="JWT signature private key (RSA PEM)",
        default=generate_jwt_secret_key
    )

    objects = DockerPermissionBaseManager()


class DockerRepo(DockerPermissionBase):
    name = models.CharField(
        "Name", max_length=255, null=False, blank=False,
        help_text="Format should be 'orgname/appname'"
    )

    registry = models.ForeignKey(
        DockerRegistry,
        related_name="repos",
    )

    objects = DockerPermissionBaseManager()
