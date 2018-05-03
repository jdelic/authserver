# -* encoding: utf-8 *-
import datetime
import json
import logging
from typing import Any, Tuple

import pytz
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509 import Certificate
from cryptography.x509 import NameOID
from django.conf import settings
from django.http import HttpResponse, HttpResponseNotFound, HttpRequest, HttpResponseBadRequest
from django.utils.decorators import method_decorator
from django.views import View
from django.views.decorators.csrf import csrf_exempt
from ratelimit.mixins import RatelimitMixin

from dockerauth.models import DockerRegistry
from mailauth.models import Domain
from mailauth.utils import Key, import_rsa_key

_log = logging.getLogger(__name__)


class InvalidKeyRequest(Exception):
    def __init__(self, response: HttpResponse, *args: Any, **kwargs: Any) -> None:
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

    def _get_domain_key(self, fqdn: str) -> Tuple[str, Key]:
        try:
            req_domain = Domain.objects.find_parent_domain(fqdn)
        except Domain.DoesNotExist:
            raise InvalidKeyRequest(HttpResponseNotFound('{"error": "Not a valid authorization domain"}',
                                                         content_type="application/json"))

        if not req_domain.jwtkey:
            raise InvalidKeyRequest(HttpResponseNotFound('{"error": "Domain is not JWT enabled"}',
                                                         content_type="application/json"))

        try:
            key = import_rsa_key(req_domain.jwtkey)  # type: ignore  # mypy doesn't see import_key for some reason
        except ValueError as e:
            raise InvalidKeyRequest(HttpResponseNotFound('{"error": "Domain is not JWT enabled"}',
                                                         content_type="application/json")) from e
        return req_domain.name, key

    def _get_registry_key(self, fqdn: str) -> Tuple[str, Key]:
        try:
            reg = DockerRegistry.objects.get(domain__name__iexact=fqdn)
        except DockerRegistry.DoesNotExist:
            raise InvalidKeyRequest(HttpResponseNotFound('{"error": "Not a valid authorization domain"}',
                                                         content_type="application/json"))

        if not reg.domain.jwtkey:
            raise InvalidKeyRequest(HttpResponseNotFound('{"error": "Domain is not JWT enabled"}',
                                                         content_type="application/json"))

        try:
            key = import_rsa_key(reg.domain.jwtkey)  # type: ignore  # mypy doesn't see import_key for some reason
        except ValueError as e:
            raise InvalidKeyRequest(HttpResponseNotFound('{"error": "Domain is not JWT enabled"}',
                                                         content_type="application/json")) from e
        return reg.client_id, key

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
                subj, key = self._get_domain_key(domain)
            elif request.GET.get("type", "d") == "r":
                subj, key = self._get_registry_key(domain)
            else:
                return HttpResponseBadRequest('{"error": "Invalid type code (d and r are valid)"}',
                                              content_type="application/json")
        except InvalidKeyRequest as e:
            _log.debug(str(e))
            return e.response

        if request.GET.get("format", "pubkey") == "pubkey":
            resp = {
                "public_key_pem": key.public_key.split("\n")
            }
        elif request.GET.get("format", "pubkey") == "cert":
            crt_subject = x509.Name([
                x509.NameAttribute(NameOID.COMMON_NAME, subj)
            ])
            cert = x509.CertificateBuilder()\
                .subject_name(crt_subject)\
                .issuer_name(crt_subject)\
                .public_key(key.key.public_key())\
                .serial_number(x509.random_serial_number())\
                .not_valid_before(datetime.datetime.now(tz=pytz.UTC))\
                .not_valid_after(
                    datetime.datetime.now(tz=pytz.UTC) + datetime.timedelta(days=settings.JWT_CERTIFICATE_DAYS_VALID)
                )\
                .add_extension(
                    x509.BasicConstraints(ca=False, path_length=None), critical=True
                )\
                .add_extension(
                    x509.KeyUsage(digital_signature=True, content_commitment=False, key_encipherment=True,
                                  data_encipherment=False, key_agreement=True, key_cert_sign=False, crl_sign=False,
                                  encipher_only=False, decipher_only=False),
                    critical=False
                )\
                .sign(key.key, algorithm=hashes.SHA256(), backend=default_backend())  # type: Certificate
            resp = {
                "cert": cert.public_bytes(encoding=serialization.Encoding.PEM).decode("utf-8").split("\n")
            }
        else:
            return HttpResponseBadRequest('{"error": "Invalid format (can be pubkey or cert)"}',
                                          content_type="application/json")

        return HttpResponse(json.dumps(resp), content_type="application/json", status=200)
