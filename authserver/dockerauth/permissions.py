# -* encoding: utf-8 *-
import logging
from typing import NamedTuple, Any


_log = logging.getLogger(__name__)


_TokenPermissionsBase = NamedTuple('_TokenPermissionsBase', [
    ("type", str),
    ("path", str),
    ("pull", bool),
    ("push", bool),
])


class TokenPermissions(_TokenPermissionsBase):
    @staticmethod
    def parse_scope(scope: str) -> 'TokenPermissions':
        """
        :raises: ValueError when scope has the wrong type
        :param scope:
        :return: a repository permission object
        """
        _log.debug("Parsing Docker login scope str: %s", scope)
        typ, path, perms = scope.split(":", 2)

        if typ != "repository":
            raise ValueError("The requested permission scope is not of type repository - %s" % scope)

        for p in perms.split(","):
            if p not in ["pull", "push"]:
                raise ValueError("Client requested unknown permissions (not push or pull) - %s" % scope)

        return TokenPermissions(
            type=typ,
            path=path,
            pull="pull" in perms,
            push="push" in perms,
        )
