# -* encoding: utf-8 *-

# Support for the Docker OAuth2 token authentication
# The Docker client submits username and password through basic authentication,
# but using a GET request. Using the actual OAuth2 spec would be *just* *too* *hard*.
#
# Much of this implementation is based around
#     https://umbrella.cisco.com/blog/blog/2016/02/23/implementing-oauth-for-registry-v2/

import datetime
import json
import logging
import base64
from typing import List, NamedTuple, Dict, Any, Union, Optional

import pytz
from django.conf import settings
from django.contrib.auth import authenticate
from django.http import QueryDict
from django.http.request import HttpRequest
from django.http.response import HttpResponse, HttpResponseNotFound, HttpResponseForbidden, HttpResponseBadRequest
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt
from django.views.generic.base import View

from dockerauth.jwtutils import JWTViewHelperMixin
from dockerauth.models import DockerRepo, DockerRegistry
from dockerauth.permissions import TokenPermissions
from mailauth.models import MNUser


_TokenRequest = NamedTuple('_TokenRequest', [
    ('service', str),
    ('offline_token', bool),
    ('client_id', Optional[str]),
    ('scope', Optional[str]),
])


_log = logging.getLogger(__name__)


def _tkr_parse(params: Union[Dict[str, str], QueryDict]) -> _TokenRequest:
    return _TokenRequest(
        service=params.get("service", "unknown"),
        offline_token=params.get("offline_token", "false") == "true",
        client_id=params.get("client_id", None),
        scope=params.get("scope", None)
    )


class DockerAuthView(JWTViewHelperMixin, View):
    def __init__(self, **kwargs: Any) -> None:
        super().__init__(**kwargs)

    def _make_access_token(self, request: HttpRequest, tokenreq: _TokenRequest,
                           rightnow: datetime.datetime, perms: TokenPermissions, for_user: MNUser) -> Dict[str, Any]:
        # TODO: figure out if we need to support more than one access scope
        # This implementation is based around this article, that, among other things,
        # describes the "kid" field required by Docker. The JWK implementation provided
        # by jwcrypto doesn't seem to work.
        # https://umbrella.cisco.com/blog/blog/2016/02/23/implementing-oauth-for-registry-v2/
        _x = []  # type: List[str]
        jwtobj = {
            'exp': int((rightnow + datetime.timedelta(minutes=2)).timestamp()),
            'nbf': int((rightnow - datetime.timedelta(seconds=1)).timestamp()),
            'iat': int(rightnow.timestamp()),
            'iss': request.get_host(),
            'aud': tokenreq.service,
            'sub': str(for_user.pk),
            'access': [{
                "type": perms.type,
                "name": perms.path,
                "actions": _x + (["push"] if perms.push else []) +
                                (["pull"] if perms.pull else []) +
                                (["login"] if perms.type == "login" else [])
            }]
        }  # type: Dict[str, Union[str, int, List[Dict[str, Union[str, List[str]]]]]]
        return jwtobj

    def _make_refresh_token(self, request: HttpRequest, tokenreq: _TokenRequest,
                            rightnow: datetime.datetime, for_user: MNUser) -> Dict[str, Any]:
        jwtobj = {
            'exp': int((rightnow + datetime.timedelta(hours=2)).timestamp()),
            'nbf': int((rightnow - datetime.timedelta(seconds=1)).timestamp()),
            'iat': int(rightnow.timestamp()),
            'iss': request.get_host(),
            'aud': tokenreq.service,
            'sub': str(for_user.pk),
            'malleable': True,
            'client_id': tokenreq.client_id,
        }
        return jwtobj

    def get(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        tr = _tkr_parse(request.GET)

        try:
            _log.debug("client: %s", str(tr))
            client = DockerRegistry.objects.get(client_id=tr.service)
        except DockerRegistry.DoesNotExist:
            return HttpResponseNotFound("No such registry/client (%s)" % str(tr))

        if tr.scope:
            tp = TokenPermissions.parse_scope(tr.scope)
        else:
            tp = TokenPermissions(
                type="login",
                path="",
                pull=False,
                push=False
            )

        try:
            drepo = DockerRepo.objects.get(name=tp.path, registry_id=client.id)
        except DockerRepo.DoesNotExist:
            if settings.DOCKERAUTH_ALLOW_UNCONFIGURED_REPOS:
                drepo = DockerRepo()
                drepo.name = tp.path
                drepo.registry = client
                drepo.unauthenticated_read = True
                drepo.unauthenticated_write = True
                drepo.save()
            elif tp.type == "login":
                drepo = DockerRepo()
                drepo.name = tp.path
                drepo.registry = client
                drepo.unauthenticated_read = False
                drepo.unauthenticated_write = False
            else:
                return HttpResponseNotFound("No such repo '%s'" % tp.path)

        if "HTTP_AUTHORIZATION" in request.META:
            basic, b64str = request.META["HTTP_AUTHORIZATION"].split(" ", 1)

            _log.debug("HTTP_AUTHORIZATION: %s %s", basic, b64str)

            if basic != "Basic":
                return HttpResponseForbidden("Unsupported auth type (must be Basic)")

            basic_auth = base64.b64decode(b64str).decode('utf-8')
            try:
                username, password = basic_auth.split(":", 1)
            except ValueError:
                return HttpResponseForbidden("Invalid basic auth string")

            rightnow = datetime.datetime.now(tz=pytz.UTC)
            user = authenticate(request, username=username, password=password)
            if user is None:
                return HttpResponseForbidden("Authentication failed")
            elif tp.type == "login":
                # create and return a refresh token
                response = HttpResponse(content=json.dumps({
                    "token": self._create_jwt(
                        self._make_access_token(request, tr, rightnow, tp, user), drepo.registry.private_key_pem()
                    ),
                    "refresh_token": self._create_jwt(
                        self._make_refresh_token(request, tr, rightnow, user), drepo.registry.private_key_pem()
                    ),
                }), status=200, content_type="application/json")
                return response
            elif drepo.registry.has_access(user, tp) or drepo.has_access(user, tp):
                response = HttpResponse(content=json.dumps({
                    "token": self._create_jwt(
                        self._make_access_token(request, tr, rightnow, tp, user), drepo.registry.private_key_pem()
                    ),
                }), status=200, content_type="application/json")
                return response
            else:
                return HttpResponseForbidden("Authentication failed")
        else:
            return HttpResponse("Unauthorized", status=401)

    def post(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        # POST received:
        # <QueryDict: {
        #       'client_id': ['docker'],
        #       'refresh_token': ['boink'],
        #       'service': ['registry.maurusnet.test'],
        #       'scope': ['repository:dev/destalinator:push,pull'],
        #       'grant_type': ['refresh_token']}>
        if "refresh_token" in request.POST and request.POST["grant_type"] == "refresh_token":
            tr = _tkr_parse(request.POST)

            if tr.scope:
                tp = TokenPermissions.parse_scope(tr.scope)
            else:
                return HttpResponseBadRequest("Can't issue access token without valid scope (scope=%s)", tr.scope)

            try:
                client = DockerRegistry.objects.get(client_id=tr.service)  # type: DockerRegistry
            except DockerRegistry.DoesNotExist:
                return HttpResponseNotFound("No such registry/client from refresh token(%s)" % str(tr))

            user = self._user_from_jwt(request.POST["refresh_token"], client.public_key_pem(),
                                       expected_issuer=request.get_host(),
                                       expected_audience=tr.service)
            if user:
                try:
                    drepo = DockerRepo.objects.get(name=tp.path, registry_id=client.id)
                except DockerRepo.DoesNotExist:
                    if settings.DOCKERAUTH_ALLOW_UNCONFIGURED_REPOS:
                        drepo = DockerRepo()
                        drepo.name = tp.path
                        drepo.registry = client
                        drepo.unauthenticated_read = True
                        drepo.unauthenticated_write = True
                    else:
                        return HttpResponseNotFound("No such repo '%s'" % tp.path)

                if drepo.registry.has_access(user, tp) or drepo.has_access(user, tp):
                    rightnow = datetime.datetime.now(tz=pytz.UTC)
                    return HttpResponse(content=json.dumps({
                        "access_token": self._create_jwt(
                            self._make_access_token(request, tr, rightnow, tp, user),
                            client.private_key_pem(),
                        ),
                        "scope": tr.scope,
                        "expires_in": 119,
                        "refresh_token": self._create_jwt(
                            self._make_refresh_token(request, tr, rightnow, user),
                            client.private_key_pem(),
                        )
                    }), status=200, content_type="application/json")
                else:
                    return HttpResponseForbidden("User %s doesn't have access to repo %s" % (user.pk, tp.path))
            else:
                return HttpResponse("Unauthorized", status=401)
        else:
            return HttpResponseBadRequest("POSTing to this endpoint requires a refresh_token")

    @method_decorator(csrf_exempt)
    def dispatch(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        return super().dispatch(request, *args, **kwargs)
