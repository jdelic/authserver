import base64
import hashlib
import json
import secrets
from urllib.parse import parse_qs, urlsplit

from django.test import TestCase
from django.urls import reverse
from oauth2_provider.settings import oauth2_settings

from mailauth import models
from mailauth.utils import generate_rsa_key


CLIENT_SECRET = "sekrit-test-client-secret"
REDIRECT_URI = "https://client.example.com/callback"
REDIRECT_URI_WITH_ISS = "https://client.example.com/callback?iss=https://evil.example"


class RFC9207AuthzResponseIssTests(TestCase):
    """
    RFC 9207 `iss` authorization-response parameter tests. Reuses the
    domain/user/app setup pattern from test_oauth2_oidc.py.
    """

    @classmethod
    def setUpTestData(cls) -> None:
        cls.key = generate_rsa_key()
        cls.domain = models.Domain.objects.create(name="example.com", jwtkey=cls.key.private_key)

        cls.user = models.MNUser.objects.create_user(
            identifier="testuser", fullname="Test User", password="secret"
        )
        cls.alias = models.EmailAlias.objects.create(
            user=cls.user, domain=cls.domain, mailprefix="testuser"
        )
        cls.user.delivery_mailbox = cls.alias
        cls.user.save()

        cls.app = models.MNApplication.objects.create(
            name="testclient",
            client_type=models.MNApplication.CLIENT_CONFIDENTIAL,
            authorization_grant_type=models.MNApplication.GRANT_AUTHORIZATION_CODE,
            redirect_uris=REDIRECT_URI,
            skip_authorization=True,
            domain=cls.domain,
            client_secret=CLIENT_SECRET,
            hash_client_secret=False,
        )

        cls.app_with_iss_redirect = models.MNApplication.objects.create(
            name="testclient-iss-redirect",
            client_type=models.MNApplication.CLIENT_CONFIDENTIAL,
            authorization_grant_type=models.MNApplication.GRANT_AUTHORIZATION_CODE,
            redirect_uris=REDIRECT_URI_WITH_ISS,
            skip_authorization=True,
            domain=cls.domain,
            client_secret=CLIENT_SECRET,
            hash_client_secret=False,
        )

    def _authorize(self, app, redirect_uri, code_verifier: str, state: "str | None" = None):
        code_challenge = (
            base64.urlsafe_b64encode(hashlib.sha256(code_verifier.encode("ascii")).digest())
            .rstrip(b"=")
            .decode("ascii")
        )
        self.client.force_login(self.user)
        params = {
            "response_type": "code",
            "client_id": app.client_id,
            "redirect_uri": redirect_uri,
            "scope": "openid profile email",
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
        }
        if state is not None:
            params["state"] = state
        return self.client.get(reverse("oauth2_provider:authorize"), params, secure=True)

    def _redeem_code(self, app, code: str, redirect_uri: str, code_verifier: str) -> dict:
        response = self.client.post(
            reverse("oauth2_provider:token"),
            {
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": redirect_uri,
                "client_id": app.client_id,
                "client_secret": CLIENT_SECRET,
                "code_verifier": code_verifier,
            },
            secure=True,
        )
        self.assertEqual(200, response.status_code, response.content)
        return json.loads(response.content)

    def test_authorize_redirect_contains_iss_query_parameter_once(self) -> None:
        code_verifier = secrets.token_urlsafe(48)
        response = self._authorize(self.app, REDIRECT_URI, code_verifier)

        self.assertEqual(302, response.status_code)
        self.assertTrue(response.url.startswith(REDIRECT_URI))
        query = parse_qs(urlsplit(response.url).query)
        self.assertEqual(["https://testserver/o2"], query["iss"])
        self.assertIn("code", query)

    def test_full_code_flow_completes_with_iss_present(self) -> None:
        code_verifier = secrets.token_urlsafe(48)
        state = "opaque-state-value"
        response = self._authorize(self.app, REDIRECT_URI, code_verifier, state=state)

        self.assertEqual(302, response.status_code)
        query = parse_qs(urlsplit(response.url).query)
        self.assertEqual(["https://testserver/o2"], query["iss"])
        self.assertEqual([state], query["state"])
        code = query["code"][0]

        token_data = self._redeem_code(self.app, code, REDIRECT_URI, code_verifier)
        self.assertIn("access_token", token_data)
        self.assertIn("id_token", token_data)

    def test_redirect_uri_with_preexisting_iss_param_is_overridden(self) -> None:
        code_verifier = secrets.token_urlsafe(48)
        response = self._authorize(self.app_with_iss_redirect, REDIRECT_URI_WITH_ISS, code_verifier)

        self.assertEqual(302, response.status_code)
        query = parse_qs(urlsplit(response.url).query)
        # only the server's value survives, exactly once
        self.assertEqual(["https://testserver/o2"], query["iss"])
        self.assertIn("code", query)

    def test_discovery_documents_advertise_iss_parameter_support(self) -> None:
        oidc_response = self.client.get("/o2/.well-known/openid-configuration", secure=True)
        self.assertEqual(200, oidc_response.status_code)
        oidc_data = json.loads(oidc_response.content)
        self.assertIs(True, oidc_data["authorization_response_iss_parameter_supported"])

        rfc8414_response = self.client.get(
            "/.well-known/oauth-authorization-server/o2", secure=True
        )
        self.assertEqual(200, rfc8414_response.status_code)
        rfc8414_data = json.loads(rfc8414_response.content)
        self.assertIs(True, rfc8414_data["authorization_response_iss_parameter_supported"])

    def test_upstream_iss_emission_gate_is_pinned_off(self) -> None:
        self.assertIs(False, oauth2_settings.COMPLIANT_BCP_RFC9700_AUTHZ_RESPONSE_ISS)
