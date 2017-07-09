# -* encoding: utf-8 *-
from django.db import models

from oauth2_provider.generators import generate_client_id

from dockerauth.permissions import TokenPermissions
from mailauth.models import MNUser, MNGroup


def generate_jwt_secret_key() -> str:
    pass


def _permissions_fulfilled(pull: bool, push: bool, scope: TokenPermissions) -> bool:
    if scope.push and scope.pull:
        return push and pull
    elif scope.push:
        return push
    elif scope.pull:
        return pull
    return False  # if neither push nor pull is necessary, this makes no sense


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

    def has_access(self, user: MNUser, scope: TokenPermissions) -> bool:
        if _permissions_fulfilled(self.unauthenticated_pull, self.unauthenticated_push, scope):
            return True

        if _permissions_fulfilled(
                self.user_pull_access.filter(id=user.id).count() > 0,
                self.user_push_access.filter(id=user.id).count() > 0,
                scope):
            return True

        # is there a group that contains `user` that has pull/push access
        if _permissions_fulfilled(
                self.group_pull_access.filter(user_set__id=user.id).count() > 0,
                self.group_push_access.filter(user_set__id=user.id).count() > 0,
                scope):
            return True


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


class DockerRepo(DockerPermissionBase):
    name = models.CharField(
        "Name", max_length=255, null=False, blank=False,
        help_text="Format should be 'orgname/appname'"
    )

    registry = models.ForeignKey(
        DockerRegistry,
        related_name="repos",
    )

