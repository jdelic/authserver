# -* encoding: utf-8 *-
from datetime import datetime
from zoneinfo import ZoneInfo

from django.http.request import HttpRequest
from oauth2_provider.oauth2_validators import OAuth2Validator
from typing import Any, Dict

from mailauth.models import MNApplication, MNUser
from mailauth.permissions import find_missing_permissions
from mailauth.utils import AuthenticatedHttpRequest


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
        "username": "profile"
    })

    def validate_refresh_token(self, refresh_token: str, client: MNApplication,
                               request: AuthenticatedHttpRequest, *args: Any, **kwargs: Any) -> bool:
        res = super().validate_refresh_token(refresh_token, client, request, *args, **kwargs)
        if res:
            # our base validated the refresh token, let's check if the client or user permissions
            # changed
            missing_permissions = find_missing_permissions(client, request.user)
            return len(missing_permissions) == 0
        else:
            return False

    def get_additional_claims(self, request) -> Dict[str, str]:
        return {
            "sub": request.user.identifier,
            "username": "%s@%s" % (request.user.delivery_mailbox.mailprefix,
                                   request.user.delivery_mailbox.domain.name),
            "email": request.user.identifier,
            "email_verified": True,
            "permissions": list(request.user.get_all_app_permission_strings()),
            "nbf": int(datetime.timestamp(datetime.now(tz=ZoneInfo("UTC")))) - 5,
            "exp": int(datetime.timestamp(datetime.now(tz=ZoneInfo("UTC")))) + 3600,
            "iss": request.client.domain.name,
            "aud": "net.maurus.authclient",
        }