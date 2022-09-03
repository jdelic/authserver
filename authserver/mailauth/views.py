# -* encoding: utf-8 *-
import json
import logging
from datetime import datetime
from typing import Any, Union, List, NamedTuple, Set, cast
from zoneinfo import ZoneInfo

from django.contrib.auth import authenticate
from django.http import HttpResponseBadRequest
from django.http.request import HttpRequest
from django.http.response import HttpResponse, HttpResponseBase, JsonResponse
from django.shortcuts import render
from django.utils.decorators import method_decorator
from django.views import View
from django.views.decorators.csrf import csrf_exempt
from oauth2_provider.forms import AllowForm
from oauth2_provider.models import get_application_model
from oauth2_provider.views import ProtectedResourceView
from oauth2_provider.views.base import AuthorizationView
from oauth2_provider.settings import oauth2_settings
from ratelimit.mixins import RatelimitMixin
from jwcrypto import jwk

from dockerauth.jwtutils import JWTViewHelperMixin
from mailauth.models import MNApplication, UnresolvableUserException, Domain
from mailauth.models import MNUser
from mailauth.permissions import find_missing_permissions
from mailauth.utils import AuthenticatedHttpRequest, import_rsa_key

_log = logging.getLogger(__name__)


class ScopeValidationAuthView(AuthorizationView):
    def __init__(self, **kwargs: Any) -> None:
        super().__init__(**kwargs)

    def form_valid(self, form: AllowForm) -> HttpResponse:
        """
        use the base class' form logic, but always behave like users didn't authorize the app
        if they doesn't have the permissions to do so.
        """
        app = get_application_model().objects.get(client_id=form.cleaned_data.get('client_id'))
        missing_permissions = find_missing_permissions(app, self.request.user)
        if missing_permissions:
            form.cleaned_data['allow'] = False

        return super().form_valid(form)

    def get(self, request: AuthenticatedHttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        _log.debug("ScopeValidationAuthView.get()")
        # super.get will initialize self.oauth2_data and now we can do additional validation
        resp = super().get(request, *args, **kwargs)

        if not (resp.status_code >= 200 and resp.status_code < 300):
            return resp

        app = self.oauth2_data['application']  # type: MNApplication

        missing_permissions = find_missing_permissions(app, request.user)

        _log.debug("missing_permissions: %s (%s)" %
                   (",".join([m.permission_name for m in missing_permissions if m.permission_name is not None]),
                    bool(missing_permissions)))

        if missing_permissions:
            return render(
                request,
                "oauth2_provider/unauthorized.html",
                context={
                    "required_permissions": list(app.required_permissions.all()),
                    "missing_permissions": missing_permissions,
                    "username": (
                        str(request.user.delivery_mailbox) if request.user.delivery_mailbox
                        else request.user.identifier
                    ),
                }
            )

        # we have all necessary permissions, so we return the original response
        return resp


class FakeUserInfoView(ProtectedResourceView):
    def __init__(self, **kwargs: Any) -> None:
        super().__init__(**kwargs)

    def get(self, request: AuthenticatedHttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        _log.debug("LimitedUserInfoView.get()")
        # TODO: validate bearer token like oauth2_provider

        if not hasattr(request, "resource_owner"):
            return HttpResponseBadRequest("Unauthenticated")

        if not request.is_secure():
            return HttpResponseBadRequest('{"error": "This endpoint must be called securely"}',
                                          content_type="application/json")

        try:
            req_domain = Domain.objects.find_parent_domain(request.get_host(), require_jwt_subdomains_set=True)
        except Domain.DoesNotExist:
            return HttpResponseBadRequest('{"error": "Not a valid authorization domain"}',
                                          content_type="application/json")

        user = request.resource_owner  # type: MNUser
        if user.delivery_mailbox is None:
            return HttpResponseBadRequest('{"error": "User has no primary email address"')

        return HttpResponse(
            json.dumps({
                "sub": str(user.uuid),
                "email": "%s@%s" % (user.delivery_mailbox.mailprefix, user.delivery_mailbox.domain.name),
                "user_id": "%s@%s" % (user.delivery_mailbox.mailprefix, user.delivery_mailbox.domain.name),
                "groups": [str(g.name) for g in user.app_groups.all()],
                "email_verified": True,
                "scopes": list(user.get_all_app_permission_strings()),
                "nbf": int(datetime.timestamp(datetime.now(tz=ZoneInfo("UTC")))) - 5,
                "exp": int(datetime.timestamp(datetime.now(tz=ZoneInfo("UTC")))) + 3600,
                "iss": req_domain.name,
            }),
            content_type="application/jwt", status=200
        )


_AuthRequest = NamedTuple(
    "_AuthRequest", [
        ("username", str),
        ("password", str),
        ("scopes", List[str]),
    ]
)


class InvalidAuthRequest(Exception):
    pass


class UserLoginAPIView(JWTViewHelperMixin, RatelimitMixin, View):
    ratelimit_key = 'ip'
    ratelimit_rate = '20/m'
    ratelimit_block = True

    def __init__(self, **kwargs: Any) -> None:
        super().__init__(**kwargs)

    def _parse_request(self, request: HttpRequest) -> _AuthRequest:
        scopes = []  # type: List[str]
        if request.content_type == "application/json":
            data = json.loads(request.body.decode('utf-8'))
            if "username" not in data:
                raise InvalidAuthRequest()
            username = data['username']
            password = data['password'] if "password" in data else None
            if "scopes" in data and isinstance(data["scopes"], list):
                scopes = data["scopes"]
        else:
            if "username" not in request.POST or "password" not in request.POST:
                raise InvalidAuthRequest()
            username = request.POST["username"]
            password = request.POST["password"]
            scopes = request.POST["scopes"].split(",")

        return _AuthRequest(
            username=username,
            password=password,
            scopes=list(set(scopes)),
        )

    @method_decorator(csrf_exempt)
    def dispatch(self, *args: Any, **kwargs: Any) -> HttpResponseBase:
        return super().dispatch(*args, **kwargs)

    def post(self, request: HttpRequest) -> HttpResponse:
        if not request.is_secure():
            return HttpResponseBadRequest('{"error": "This endpoint must be called securely"}',
                                          content_type="application/json")

        try:
            req_domain = Domain.objects.find_parent_domain(request.get_host(), require_jwt_subdomains_set=True)
        except Domain.DoesNotExist:
            return HttpResponseBadRequest('{"error": "Not a valid authorization domain"}',
                                          content_type="application/json")

        try:
            userdesc = self._parse_request(request)
        except json.JSONDecodeError:
            return HttpResponseBadRequest('{"error": "Invalid JSON"}', content_type="application/json")
        except InvalidAuthRequest:
            return HttpResponseBadRequest('{"error": "Missing parameters"}', content_type="application/json")

        if userdesc.password:
            user = cast(MNUser, authenticate(username=userdesc.username, password=userdesc.password))
            authenticated = True
        else:
            authenticated = False
            try:
                user = MNUser.objects.resolve_user(userdesc.username)
            except UnresolvableUserException:
                user = None

        if user is None:
            return HttpResponse(
                '{"authenticated": false, "authorized": false}', content_type="application/json", status=401,
            )
        elif user.delivery_mailbox is None:
            return HttpResponse(
                '{"authenticated": false, "authorized": false}', content_type="application/json", status=401,
            )
        elif userdesc.scopes and not user.has_app_permissions(userdesc.scopes):
            return HttpResponse(
                '{"authenticated": %s, "authorized": false, "requested": "[%s]"}' %
                ("true" if authenticated else "false", user.get_all_app_permission_strings()),
                content_type="application/json", status=401,
            )
        else:
            # user is possibly authenticated and authorized
            jwtstr = self._create_jwt(claim={
                "sub": userdesc.username,
                "canonical_username": "%s@%s" % (user.delivery_mailbox.mailprefix, user.delivery_mailbox.domain.name),
                "authenticated": authenticated,
                "authorized": user.has_app_permissions(userdesc.scopes or set()),
                "scopes": list(user.get_all_app_permission_strings()),
                "nbf": int(datetime.timestamp(datetime.now(tz=ZoneInfo("UTC")))) - 5,
                "exp": int(datetime.timestamp(datetime.now(tz=ZoneInfo("UTC")))) + 3600,
                "iss": req_domain.name,
                "aud": "net.maurus.authclient",
            }, key_pemstr=req_domain.jwtkey)

            return HttpResponse(
                jwtstr,
                content_type="application/jwt", status=200
            )


class JwksInfoView(View):
    def get(self, request: HttpRequest) -> HttpResponse:
        keys = []
        for dom in Domain.objects.all():
            if dom.jwtkey:
                key = jwk.JWK.from_pem(import_rsa_key(dom.jwtkey).public_key.encode('utf-8'))
                data = {
                    "alg": "RS256",
                    "use": "sig",
                    "kid": key.thumbprint(),
                    "domain": dom.name,
                }
                data.update(json.loads(key.export_public()))
                keys.append(data)

        response = JsonResponse({"keys": keys})
        response["Access-Control-Allow-Origin"] = "*"
        response["Cache-Control"] = (
                "Cache-Control: public, "
                + f"max-age={oauth2_settings.OIDC_JWKS_MAX_AGE_SECONDS}, "
                + f"stale-while-revalidate={oauth2_settings.OIDC_JWKS_MAX_AGE_SECONDS}, "
                + f"stale-if-error={oauth2_settings.OIDC_JWKS_MAX_AGE_SECONDS}"
        )
        return response
