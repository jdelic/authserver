"""Custom OAuthLib request/response glue for authserver."""
from typing import Any, Dict, Optional, Tuple

from django.http import HttpRequest

from oauth2_provider.oauth2_backends import OAuthLibCore, _add_iss_to_redirect
from oauth2_provider.settings import oauth2_settings


def add_iss_parameter(uri: str, request: HttpRequest) -> str:
    """
    Add the RFC 9207 `iss` authorization-response parameter to a redirect URI,
    using the issuer that authserver publishes for the requested host
    (https://<host>/o2), replacing any `iss` the URI already carries.
    """
    return _add_iss_to_redirect(uri, oauth2_settings.oidc_issuer(request))


class MNOAuthLibCore(OAuthLibCore):
    """
    Adds the RFC 9207 `iss` parameter to authorization responses (both the
    success redirect and the redirect produced when a user denies the request).
    Upstream's own emission, gated by COMPLIANT_BCP_RFC9700_AUTHZ_RESPONSE_ISS,
    derives the issuer from the root RFC 8414 metadata URL and so cannot
    produce authserver's per-host issuers.

    Authorization errors that django-oauth-toolkit turns into redirects inside
    the view never reach this method; ScopeValidationAuthView.error_response()
    adds `iss` to those.
    """

    def create_authorization_response(self, request: HttpRequest, scopes: str, credentials: Dict[str, Any],
                                      allow: bool) -> Tuple[Optional[str], Dict[str, str], Optional[str], int]:
        uri, headers, body, status = super().create_authorization_response(
            request, scopes, credentials, allow
        )
        if uri is not None:
            uri = add_iss_parameter(uri, request)
            headers["Location"] = uri
        return uri, headers, body, status
