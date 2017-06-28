# -* encoding: utf-8 *-

# Support for the Docker OAuth2 token authentication
# The Docker client submits username and password through basic authentication,
# but using a GET request. Using the actual OAuth2 spec would be *just* *too* *hard*.
from typing import NamedTuple, Dict, Any

from django.http.request import HttpRequest
from django.http.response import HttpResponse, HttpResponseNotFound, HttpResponseForbidden
from django.views.generic.base import View

from mailauth.models import MNApplication

_TokenRequest = NamedTuple('_TokenRequest', [
    ('service', str),
    ('offline_token', str),
    ('client_id', str),
    ('scope', str),
])


def _tkr_parse(params: Dict[str, str]) -> _TokenRequest:
    return _TokenRequest(
        service=params.get("service", None),
        offline_token=params.get("offline_token", None),
        client_id=params.get("client_id", None),
        scope=params.get("scope", None)
    )


class DockerAuth(View):
    def get(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        tr = _tkr_parse(request.GET)

        try:
            client = MNApplication.objects.get(client_id=tr.client_id)
        except MNApplication.DoesNotExist:
            return HttpResponseNotFound()

        if client.authorization_grant_type != MNApplication.GRANT_PASSWORD:
            return HttpResponseForbidden("Client must be authorized for resource-owner password mode of operation")

        if "HTTP_AUTHORIZATION" in request.META:
            
