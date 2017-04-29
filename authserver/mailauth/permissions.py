# -* encoding: utf-8 *-
from typing import List

from mailauth.models import MNApplication, MNUser, MNApplicationPermission


def find_missing_permissions(app: MNApplication, user: MNUser) -> List[MNApplicationPermission]:
    """
    returns a list of ``Permission`` objects that the user doesn't have, but that the
    app requires. Consequently, if this returns an empty list, the user is authorized
    to connect to the app.
    :param app: the application in question
    :param user: the user object of this request
    :return: a list of missing permissions or an empty list if the user has all necessary permissions
    """
    reqs = list(app.required_permissions.all())

    user_permissions = set([perm.scope_name for perm in list(user.app_permissions.all())])
    for group in user.app_groups.all():
        for perm in list(group.group_permissions.all()):
            user_permissions.add(perm.scope_name)

    missing_permissions = []
    for req in reqs:
        if req.scope_name not in user_permissions:
            missing_permissions.append(req)

    return missing_permissions
