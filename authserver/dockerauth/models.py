# -* encoding: utf-8 *-
import logging

from django.db import models

from oauth2_provider.generators import generate_client_id

from dockerauth.permissions import TokenPermissions
from mailauth.models import MNUser, MNGroup, Domain
from mailauth.utils import import_rsa_key


def _permissions_fulfilled(pull: bool, push: bool, scope: TokenPermissions) -> bool:
    _log.debug("permissions: scope: %s %s    user: %s %s", scope.pull, scope.push, pull, push)
    if scope.push and scope.pull:
        return push and pull
    elif scope.push:
        return push
    elif scope.pull:
        return pull
    elif scope.type == "login":  # pure login checks don't request permissions
        return True
    return False  # if neither push nor pull is necessary, this makes no sense


_log = logging.getLogger(__name__)


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
        _log.debug("checking access for user: %s (%s)", user.pk, user.get_username())
        _log.debug("checking for unauthenticated access")
        if _permissions_fulfilled(self.unauthenticated_pull, self.unauthenticated_push, scope):
            return True

        _log.debug("checking for user access")
        if _permissions_fulfilled(
                self.user_pull_access.filter(pk=user.pk).count() > 0,
                self.user_push_access.filter(pk=user.pk).count() > 0,
                scope):
            return True

        # is there a group that contains `user` that has pull/push access
        _log.debug("checking for group access")
        if _permissions_fulfilled(
                self.group_pull_access.filter(user=user).count() > 0,
                self.group_push_access.filter(user=user).count() > 0,
                scope):
            return True
        return False


class DockerRegistry(DockerPermissionBase):
    class Meta:
        verbose_name = "Docker Registry"
        verbose_name_plural = "Docker Registries"

    name = models.CharField(
        "Name", max_length=255, null=False, blank=False,
        help_text="Human readable name"
    )

    client_id = models.CharField(
        max_length=100, unique=True, default=generate_client_id, db_index=True
    )

    domain = models.ForeignKey(Domain, on_delete=models.PROTECT)

    def private_key_pem(self) -> str:
        return self.domain.jwtkey

    def public_key_pem(self) -> str:
        return import_rsa_key(self.domain.jwtkey).public_key

    def __str__(self) -> str:
        return "%s (%s)" % (self.name, self.domain.name)


class DockerRepo(DockerPermissionBase):
    class Meta:
        verbose_name = "Docker Repository"
        verbose_name_plural = "Docker Repositories"

    name = models.CharField(
        "Name", max_length=255, null=False, blank=False,
        help_text="Format should be 'orgname/appname'"
    )

    registry = models.ForeignKey(
        DockerRegistry,
        related_name="repos",
    )

    def __str__(self) -> str:
        return "%s:%s" % (self.registry.name, self.name,)
