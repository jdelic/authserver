import logging
from datetime import datetime
from datetime import timedelta
from zoneinfo import ZoneInfo

from django.utils import timezone
from oauth2_provider.models import RefreshToken
from oauth2_provider.oauth2_validators import OAuth2Validator
from oauth2_provider.settings import oauth2_settings
from typing import Any, Dict, List, Union

from mailauth.models import MNApplication, MNUser
from mailauth.permissions import find_missing_permissions
from mailauth.utils import AuthenticatedHttpRequest


_log = logging.getLogger(__name__)


def check_pkce_required(client_id: str) -> bool:
    """
    Checks if PKCE is enforced for a client
    :param client_id:
    :return: True or False
    """
    try:
        client = MNApplication.objects.get(client_id=client_id)
    except MNApplication.DoesNotExist:
        return True

    return client.pkce_enforced


class ClientPermissionValidator(OAuth2Validator):
    oidc_claim_scope = OAuth2Validator.oidc_claim_scope
    oidc_claim_scope.update({
        "username": "profile",
        "groups": "profile",
    })

    def validate_refresh_token(self, refresh_token: str, client: MNApplication,
                               request: AuthenticatedHttpRequest, *args: Any, **kwargs: Any) -> bool:
        res = super().validate_refresh_token(refresh_token, client, request, *args, **kwargs)
        if res:
            # our base validated the refresh token, let's check if the client or user permissions
            # changed
            missing_permissions = find_missing_permissions(client, request.user)
            if missing_permissions:
                _log.warning(
                    "Rejecting refresh token for client %s (%s): missing permissions for user %s: %s",
                    client.name, client.client_id, request.user.identifier,
                    ",".join(sorted([p.permission_name for p in missing_permissions if p.permission_name])),
                )
                return False
            return True
        else:
            rt = RefreshToken.objects.filter(token=refresh_token).first()
            if not rt:
                _log.warning(
                    "Rejecting refresh token for client %s (%s): token not found (prefix=%s)",
                    client.name, client.client_id, refresh_token[:8],
                )
            elif rt.application_id != client.id:
                _log.warning(
                    "Rejecting refresh token for client %s (%s): token belongs to client_id=%s (prefix=%s)",
                    client.name, client.client_id, rt.application.client_id, refresh_token[:8],
                )
            elif rt.revoked is not None and rt.revoked <= timezone.now() - timedelta(
                seconds=oauth2_settings.REFRESH_TOKEN_GRACE_PERIOD_SECONDS
            ):
                _log.warning(
                    "Rejecting refresh token for client %s (%s): token revoked at %s (prefix=%s)",
                    client.name, client.client_id, rt.revoked.isoformat(), refresh_token[:8],
                )
            else:
                _log.warning(
                    "Rejecting refresh token for client %s (%s): failed base validator checks (prefix=%s)",
                    client.name, client.client_id, refresh_token[:8],
                )
            return False

    def get_additional_claims(self, request) -> Dict[str, Union[str, List]]:
        user = request.user
        _log.debug("Adding id_token claims (%s groups)", user.app_groups.count())
        return {
            "sub": str(user.uuid),
            "email": "%s@%s" % (user.delivery_mailbox.mailprefix, user.delivery_mailbox.domain.name),
            "username": "%s@%s" % (user.delivery_mailbox.mailprefix, user.delivery_mailbox.domain.name),
            "groups": [str(g.name) for g in user.app_groups.all()],
            "email_verified": True,
            "scopes": list(user.get_all_app_permission_strings()),
            "nbf": int(datetime.timestamp(datetime.now(tz=ZoneInfo("UTC")))) - 5,
            "exp": int(datetime.timestamp(datetime.now(tz=ZoneInfo("UTC")))) + 3600,
            "iss": request.client.domain.name,
            "aud": "net.maurus.authclient",
        }

    def get_userinfo_claims(self, request):
        cl = super().get_userinfo_claims(request)
        cl.update({
            "user_id": "%s@%s" % (request.user.delivery_mailbox.mailprefix, request.user.delivery_mailbox.domain.name),
        })
        _log.debug("Userinfo claims %s", cl)
        return cl
