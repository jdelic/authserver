"""Custom OAuthLib request/response glue for authserver."""
from oauth2_provider.oauth2_backends import OAuthLibCore, _add_iss_to_redirect
from oauth2_provider.settings import oauth2_settings


class MNOAuthLibCore(OAuthLibCore):
    """
    Adds the RFC 9207 `iss` parameter to successful authorization
    responses using the same per-request issuer that the OIDC discovery
    document advertises (https://<host>/o2). Upstream's implementation
    (gated by COMPLIANT_BCP_RFC9700_AUTHZ_RESPONSE_ISS, pinned False in
    settings) cannot derive path-component multi-tenant issuers.
    """

    def create_authorization_response(self, request, scopes, credentials, allow):
        uri, headers, body, status = super().create_authorization_response(
            request, scopes, credentials, allow
        )
        if uri is not None:
            issuer = oauth2_settings.oidc_issuer(request)
            uri = _add_iss_to_redirect(uri, issuer)
            headers["Location"] = uri
        return uri, headers, body, status
