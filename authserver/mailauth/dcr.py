"""DCR (RFC 7591) support: initial-access-token permission and view."""
import hashlib
import json

from oauth2_provider.models import get_access_token_model
from oauth2_provider.utils import parse_bearer_token
from oauth2_provider.views.dynamic_client_registration import (
    DynamicClientRegistrationView,
    _error_response,
)

from mailauth.models import Domain, MNApplication

# Scope carried by operator-minted initial access tokens
# (see the `dcrtoken` management command).
INITIAL_ACCESS_TOKEN_SCOPE = "authserver:dcr-initial"


class InitialAccessTokenDCRPermission:
    """
    RFC 7591 initial access token check: the request must carry a Bearer
    token minted by `manage.py dcrtoken create`. Configured via
    OAUTH2_PROVIDER["DCR_REGISTRATION_PERMISSION_CLASSES"].
    """

    def has_permission(self, request) -> bool:
        raw_token = parse_bearer_token(request.META.get("HTTP_AUTHORIZATION", ""))
        if raw_token is None:
            return False
        checksum = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()
        access_token_model = get_access_token_model()
        try:
            token = access_token_model.objects.get(token_checksum=checksum)
        except access_token_model.DoesNotExist:
            return False
        return token.is_valid([INITIAL_ACCESS_TOKEN_SCOPE])


class MNDynamicClientRegistrationView(DynamicClientRegistrationView):
    """
    Wraps the upstream RFC 7591 view to bind the new application to the
    Domain that signs for the request host, mirroring how the rest of
    authserver resolves issuers. Rejects hosts without a signing domain
    BEFORE the upstream view creates anything.
    """

    def post(self, request, *args, **kwargs):
        hostname = request.get_host().split(":")[0]
        try:
            domain = Domain.objects.find_parent_domain(
                hostname, require_jwt_subdomains_set=True, require_jwt_key=True
            )
        except Domain.DoesNotExist:
            return _error_response(
                "invalid_client_metadata",
                "This host is not a valid registration domain",
            )

        response = super().post(request, *args, **kwargs)

        if response.status_code == 201:
            client_id = json.loads(response.content)["client_id"]
            MNApplication.objects.filter(client_id=client_id).update(domain=domain)
        return response
