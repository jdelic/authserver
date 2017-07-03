# -* encoding: utf-8 *-

from django.db import models


class DockerRepo(models.Model):
    name = models.CharField(
        "Name", max_length=255, null=False, blank=False,
        help_text="Format should be 'orgname/appname'"
    )
    unauthenticated_pull = models.BooleanField("Allow unauthenticated pull",
                                               default=False, null=False)
    unauthenticated_push = models.BooleanField("Allow unauthenticated push",
                                               default=False, null=False)
