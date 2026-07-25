"""DCR (RFC 7591/7592) support: initial-access-token permission and views."""
import hashlib
from typing import Any

from django.core.exceptions import ValidationError
from django.db import transaction
from django.http import HttpRequest, HttpResponse, JsonResponse
from django.utils.decorators import method_decorator

from django_ratelimit.decorators import ratelimit
from oauth2_provider.models import get_access_token_model, get_application_model
from oauth2_provider.settings import oauth2_settings
from oauth2_provider.utils import parse_bearer_token
from oauth2_provider.views.dynamic_client_registration import (
    DynamicClientRegistrationManagementView,
    DynamicClientRegistrationView,
    _application_to_response,
    _build_application_kwargs,
    _check_permissions,
    _error_response,
    _issue_registration_token,
    _parse_metadata,
    _validation_error_description,
)

from mailauth.models import Domain

# Scope carried by operator-minted initial access tokens
# (see the `dcrtoken` management command).
INITIAL_ACCESS_TOKEN_SCOPE = "authserver:dcr-initial"


class InitialAccessTokenDCRPermission:
    """
    RFC 7591 initial access token check: the request must carry a Bearer
    token minted by `manage.py dcrtoken create`. Configured via
    OAUTH2_PROVIDER["DCR_REGISTRATION_PERMISSION_CLASSES"].
    """

    def has_permission(self, request: HttpRequest) -> bool:
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


class RegistrationEndpointMixin:
    """
    The RFC 7591 and RFC 7592 endpoints both hand out client credentials, so
    they are TLS-only (RFC 7591 section 5), like the other credential-carrying
    APIs in mailauth.views.
    """

    def dispatch(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        # upstream's DCR_ENABLED gate answers first, so a disabled endpoint
        # still 404s instead of commenting on the transport
        if oauth2_settings.DCR_ENABLED and not request.is_secure():
            return _error_response("invalid_request", "This endpoint must be called securely")
        return super().dispatch(request, *args, **kwargs)  # type: ignore[misc]


@method_decorator(ratelimit(key='ip', rate='20/m', group='dcr-register', block=True), name='dispatch')
class MNDynamicClientRegistrationView(RegistrationEndpointMixin, DynamicClientRegistrationView):
    """
    RFC 7591 registration, binding the new application to the Domain that
    signs for the request host so every dynamically registered client can be
    issued ID tokens. Hosts without a signing domain are rejected before
    anything is created.

    ``post()`` is a copy of ``DynamicClientRegistrationView.post()``
    (django-oauth-toolkit 3.4.0) with the domain lookup added instead of a
    call to ``super()``: ``MNApplication.domain`` is ``null=True`` but not
    ``blank=True``, so the ``full_clean()`` inside upstream's ``post()``
    rejects an application that has no domain yet - the domain has to be on
    the instance before that runs. Keep in sync when upgrading
    django-oauth-toolkit.
    """

    def post(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        if not _check_permissions(request):
            return _error_response(
                "access_denied",
                "Authentication required to register a client",
                status=401,
            )

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

        data, err = _parse_metadata(request.body)
        if err:
            return err

        app_kwargs, err = _build_application_kwargs(data)
        if err:
            return err

        Application = get_application_model()
        user = request.user if request.user.is_authenticated else None
        application = Application(
            user=user,
            registration_source=Application.RegistrationSource.DCR,
            domain=domain,
            **app_kwargs,
        )

        # Capture the raw secret before save() hashes it
        raw_secret = application.client_secret if application.client_type == "confidential" else None

        try:
            application.full_clean()
        except ValidationError as exc:
            return _error_response("invalid_client_metadata", _validation_error_description(exc))

        with transaction.atomic():
            application.save()
            registration_token = _issue_registration_token(application, user)

        response_data = _application_to_response(application, registration_token, request)
        if raw_secret:
            response_data["client_secret"] = raw_secret

        return JsonResponse(response_data, status=201)


@method_decorator(ratelimit(key='ip', rate='60/m', group='dcr-manage', block=True), name='dispatch')
class MNDynamicClientRegistrationManagementView(RegistrationEndpointMixin,
                                                DynamicClientRegistrationManagementView):
    """
    RFC 7592 client configuration endpoint. Upstream's implementation is used
    as-is, it only gains the transport rules of RegistrationEndpointMixin.
    """
