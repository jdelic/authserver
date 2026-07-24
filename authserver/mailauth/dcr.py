"""DCR (RFC 7591) support: initial-access-token permission and view."""
import hashlib

from django.core.exceptions import ValidationError
from django.db import transaction
from django.http import JsonResponse

from oauth2_provider.models import get_access_token_model, get_application_model
from oauth2_provider.utils import parse_bearer_token
from oauth2_provider.views.dynamic_client_registration import (
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

    DEVIATION from implementation-plan.rst section 3.4a: the plan's reference
    implementation calls ``super().post(...)`` and assigns ``domain`` to the
    already-saved row afterwards (``MNApplication.objects.filter(client_id=
    ...).update(domain=domain)``), on the assumption that
    ``application.full_clean()`` (called inside upstream's ``post()``)
    tolerates ``domain=None``. In reality ``MNApplication.domain`` is
    ``null=True`` but not ``blank=True``, so ``full_clean()`` rejects a
    domain-less application with "domain: This field cannot be blank." -
    every registration would 400 before upstream's ``post()`` could ever
    save anything. Adding ``blank=True`` to the model was out of scope
    (task instructions excluded ``mailauth/models.py`` and migrations), so
    this inlines upstream's ``post()`` body instead, setting ``domain`` on
    the ``Application`` *before* ``full_clean()`` runs.
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

        if not _check_permissions(request):
            return _error_response(
                "access_denied",
                "Authentication required to register a client",
                status=401,
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
