# -* encoding: utf-8 *-
import json
from typing import Any, Union

from Crypto.PublicKey import RSA
from Crypto.PublicKey.RSA import RsaKey
from django.http import HttpResponse, HttpResponseNotFound, HttpRequest, HttpResponseBadRequest
from django.utils.decorators import method_decorator
from django.views import View
from django.views.decorators.csrf import csrf_exempt
from ratelimit.mixins import RatelimitMixin

from dockerauth.models import DockerRegistry
from mailauth import utils


class InvalidKeyRequest(Exception):
    def __init__(self, response: HttpResponse, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.response = response


class JWTPublicKeyView(RatelimitMixin, View):
    ratelimit_key = 'ip'
    ratelimit_rate = '5/m'
    ratelimit_block = True

    def __init__(self, **kwargs: Any) -> None:
        super().__init__(**kwargs)

    @method_decorator(csrf_exempt)
    def dispatch(self, *args: Any, **kwargs: Any) -> HttpResponse:
        return super().dispatch(*args, **kwargs)

    def _get_domain_key(self, fqdn: str) -> RsaKey:
        req_domain = utils.find_parent_domain(fqdn)

        if req_domain is None:
            raise InvalidKeyRequest(HttpResponseNotFound('{"error": "Not a valid authorization domain"}',
                                                         content_type="application/json"))

        if req_domain.jwtkey is None or req_domain.jwtkey == "":
            raise InvalidKeyRequest(HttpResponseNotFound('{"error": "Domain is not JWT enabled"}',
                                                         content_type="application/json"))

        try:
            privkey = RSA.import_key(req_domain.jwtkey)  # type: ignore  # mypy doesn't see import_key for some reason
        except ValueError as e:
            raise InvalidKeyRequest(HttpResponseNotFound('{"error": "Domain is not JWT enabled"}',
                                                         content_type="application/json")) from e

        return privkey

    def _get_registry_key(self, fqdn: str) -> RsaKey:
        try:
            reg = DockerRegistry.objects.get(domain__name__iexact=fqdn)
        except DockerRegistry.DoesNotExist:
            raise InvalidKeyRequest(HttpResponseNotFound('{"error": "Not a valid authorization domain"}',
                                                         content_type="application/json"))

        if reg.domain.jwtkey:
            return reg.domain.jwtkey
        else:
            raise InvalidKeyRequest(HttpResponseNotFound('{"error": "Domain is not JWT enabled"}',
                                                         content_type="application/json"))

    def get(self, request: HttpRequest) -> HttpResponse:
        if not request.is_secure():
            return HttpResponseBadRequest('{"error": "This endpoint must be called securely"}',
                                          content_type="application/json")

        if "domain" in request.GET and request.GET["domain"]:
            domain = request.GET["domain"]
        else:
            domain = request.get_host()

        try:
            if request.GET.get("type", "d") == "d":
                privkey = self._get_domain_key(domain)
            elif request.GET.get("type", "d") == "r":
                privkey = self._get_registry_key(domain)
            else:
                return HttpResponseBadRequest('{"error": "Invalid type code (d and r are valid)"}',
                                              content_type="application/json")
        except InvalidKeyRequest as e:
            _log.debug(str(e))
            return e.response

        public_key = privkey.publickey().exportKey("PEM").decode('utf-8').replace("RSA PUBLIC KEY", "PUBLIC KEY")
        resp = {
            "public_key_pem": public_key.split("\n")
        }
        return HttpResponse(json.dumps(resp), content_type="application/json", status=200)
