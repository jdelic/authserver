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

from typing import NamedTuple, Dict, Any

import pytz
import jwt
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from django.conf import settings
from django.contrib.auth import authenticate
from django.http.request import HttpRequest
from django.http.response import HttpResponse, HttpResponseNotFound, HttpResponseForbidden, HttpResponseNotAllowed
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt
from django.views.generic.base import View

from dockerauth.models import DockerRepo, DockerRegistry
from dockerauth.permissions import TokenPermissions


_TokenRequest = NamedTuple('_TokenRequest', [
    ('service', str),
    ('offline_token', bool),
    ('client_id', str),
    ('scope', str),
])


_log = logging.getLogger(__name__)


def _tkr_parse(params: Dict[str, str]) -> _TokenRequest:
    return _TokenRequest(
        service=params.get("service", None),
        offline_token=params.get("offline_token", "false") == "true",
        client_id=params.get("client_id", None),
        scope=params.get("scope", None)
    )


class DockerAuthView(View):
    def __init__(self, **kwargs: Any) -> None:
        super().__init__(**kwargs)

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

            user = authenticate(request, username=username, password=password)
            _log.debug("Registry access: %s", drepo.registry.has_access(user, tp))
            if user and drepo.registry.has_access(user, tp) or drepo.has_access(user, tp):
                ts = datetime.datetime.now(tz=pytz.UTC)
                # TODO: figure out if we need to support more than one access scope
                # This implementation is based around this article, that, among other things,
                # describes the "kid" field required by Docker. The JWK implementation provided
                # by jwcrypto doesn't seem to work.
                # https://umbrella.cisco.com/blog/blog/2016/02/23/implementing-oauth-for-registry-v2/
                jwtobj = {
                    'exp': int((ts + datetime.timedelta(hours=1)).timestamp()),
                    'nbf': int((ts - datetime.timedelta(seconds=1)).timestamp()),
                    'iat': int(ts.timestamp()),
                    'iss': request.get_host(),
                    'aud': tr.service,
                    'sub': str(user.pk),
                    'access': [{
                        "type": tp.type,
                        "name": tp.path,
                        "actions": [] + (["push"] if tp.push else []) +
                                        (["pull"] if tp.pull else []) +
                                        (["login"] if tp.type == "login" else [])
                    }]
                }

                _log.debug("Encoding JWT response: %s", jwtobj)

                fp = base64.b32encode(
                    SHA256.new(
                        data=RSA.import_key(drepo.registry.sign_key).publickey().exportKey(format="DER")
                    ).digest()[0:30]  # shorten to 240 bit presumably so no padding is necessary
                ).decode('utf-8')

                kid = ":".join([fp[i:i + 4] for i in range(0, len(fp), 4)])

                jwtstr = jwt.encode(
                    jwtobj,
                    headers={
                        "typ": "JWT",
                        "alg": "RS256",
                        "kid": kid,
                    },
                    key=drepo.registry.sign_key,
                    algorithm="RS256",
                ).decode('utf-8')

                _log.debug("JWT response: %s", jwtstr)

                response = HttpResponse(content=json.dumps({
                    "token": jwtstr,
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
        return HttpResponseForbidden("POST not supported")

    @method_decorator(csrf_exempt)
    def dispatch(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        return super().dispatch(request, *args, **kwargs)
