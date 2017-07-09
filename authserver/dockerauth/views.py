# -* encoding: utf-8 *-

# Support for the Docker OAuth2 token authentication
# The Docker client submits username and password through basic authentication,
# but using a GET request. Using the actual OAuth2 spec would be *just* *too* *hard*.
import datetime
import logging
import base64
import jwt

from typing import NamedTuple, Dict, Any

import pytz
from django.conf import settings
from django.contrib.auth import authenticate
from django.http.request import HttpRequest
from django.http.response import HttpResponse, HttpResponseNotFound, HttpResponseForbidden
from django.views.generic.base import View

from dockerauth.models import DockerRepo, DockerRegistry
from dockerauth.permissions import TokenPermissions
from mailauth.models import MNApplication

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
            client = DockerRegistry.objects.get(client_id=tr.client_id)
        except DockerRegistry.DoesNotExist:
            return HttpResponseNotFound("No such registry/client")

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
                drepo.unauthenticated_read = True
                drepo.unauthenticated_write = True
            elif tp.type == "login":
                drepo = DockerRepo()
                drepo.name = tp.path
                drepo.unauthenticated_read = False
                drepo.unauthenticated_write = False
            else:
                return HttpResponseNotFound("No such repo '%s'" % tp.path)

        if not tr.offline_token:
            return HttpResponseForbidden("authserver only supports authentication for docker 1.11 or higher")

        if "HTTP_AUTHORIZATION" in request.META:
            basic, b64str = request.META["HTTP_AUTHORIZATION"].split(" ", 1)

            if basic != "Basic":
                return HttpResponseForbidden("Unsupported auth type (must be Basic)")

            basic_auth = base64.b64decode(b64str).decode('utf-8')
            try:
                username, password = basic_auth.split(":", 1)
            except ValueError:
                return HttpResponseForbidden("Invalid basic auth string")

            user = authenticate(request, username=username, password=password)
            if user and (drepo.registry.has_access(user, tp) or drepo.has_access(user, tp)):
                ts = datetime.datetime.now(tz=pytz.UTC)
                jwtstr = jwt.encode({
                    'exp': ts + datetime.timedelta(hours=1),
                    'nbf': ts - datetime.timedelta(seconds=1),
                    'iat': ts,
                    'iss':
                })


                response = HttpResponse(content=jwtstr, status=200)
                return response
            else:
                return HttpResponseForbidden("Authentication failed")
        else:
            return HttpResponseForbidden("No authentication credentials provided")
