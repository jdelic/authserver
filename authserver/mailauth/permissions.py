# -* encoding: utf-8 *-
import logging
from typing import Set

from mailauth.models import MNApplication, MNUser, MNApplicationPermission


_log = logging.getLogger(__name__)


def find_missing_permissions(app: MNApplication, user: MNUser) -> Set[MNApplicationPermission]:
    """
    returns a list of ``Permission`` objects that the user doesn't have, but that the
    app requires. Consequently, if this returns an empty list, the user is authorized
    to connect to the app.
    :param app: the application in question
    :param user: the user object of this request
    :return: a list of missing permissions or an empty list if the user has all necessary permissions
    """
    reqs = set(app.required_permissions.all())

    user_permissions = user.get_all_app_permissions()

    _log.debug("combined user permissions: %s; application permissions: %s" %
               (",".join([perm.scope_name for perm in user_permissions]), ",".join([req.scope_name for req in reqs])))

    missing_permissions = reqs - user_permissions.intersection(reqs)
    return missing_permissions
