import base64
import hashlib
import json
import secrets
from urllib.parse import parse_qs, urlsplit

from django.test import TestCase
from django.urls import reverse
from jwcrypto import jwk, jwt
from oauth2_provider.models import RefreshToken

from mailauth import models
from mailauth.utils import generate_rsa_key


CLIENT_SECRET = "sekrit-test-client-secret"
REDIRECT_URI = "https://client.example.com/callback"


class OIDCAuthorizationCodeFlowTests(TestCase):
    """
    End-to-end OAuth2/OpenID Connect tests against the real URL configuration:
    authorization code + PKCE, RS256 ID token signing with the Domain JWT key and
    refresh token handling (checksum-based lookup since django-oauth-toolkit 3.4.0).
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

    def _authorize_and_get_code(self, code_verifier: str) -> str:
        code_challenge = (
            base64.urlsafe_b64encode(hashlib.sha256(code_verifier.encode("ascii")).digest())
            .rstrip(b"=")
            .decode("ascii")
        )
        self.client.force_login(self.user)
        response = self.client.get(
            reverse("oauth2_provider:authorize"),
            {
                "response_type": "code",
                "client_id": self.app.client_id,
                "redirect_uri": REDIRECT_URI,
                "scope": "openid profile email",
                "code_challenge": code_challenge,
                "code_challenge_method": "S256",
            },
            secure=True,
        )
        self.assertEqual(302, response.status_code)
        self.assertTrue(response.url.startswith(REDIRECT_URI))
        query = parse_qs(urlsplit(response.url).query)
        self.assertIn("code", query)
        return query["code"][0]

    def _redeem_code(self, code: str, code_verifier: str) -> dict:
        response = self.client.post(
            reverse("oauth2_provider:token"),
            {
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": REDIRECT_URI,
                "client_id": self.app.client_id,
                "client_secret": CLIENT_SECRET,
                "code_verifier": code_verifier,
            },
            secure=True,
        )
        self.assertEqual(200, response.status_code, response.content)
        return json.loads(response.content)

    def test_full_flow_issues_rs256_id_token_signed_with_domain_key(self) -> None:
        code_verifier = secrets.token_urlsafe(48)
        code = self._authorize_and_get_code(code_verifier)
        token_data = self._redeem_code(code, code_verifier)

        self.assertIn("access_token", token_data)
        self.assertIn("refresh_token", token_data)
        self.assertIn("id_token", token_data)

        # the ID token must be verifiable with the public part of the domain's JWT key
        pubkey = jwk.JWK.from_pem(self.key.public_key.encode("utf-8"))
        verified = jwt.JWT(key=pubkey, jwt=token_data["id_token"])
        header = json.loads(verified.header)
        claims = json.loads(verified.claims)

        self.assertEqual("RS256", header["alg"])
        self.assertEqual(str(self.user.uuid), claims["sub"])
        self.assertEqual("testuser@example.com", claims["email"])
        self.assertEqual("testuser@example.com", claims["username"])

    def test_refresh_token_has_checksum_and_can_be_redeemed(self) -> None:
        code_verifier = secrets.token_urlsafe(48)
        code = self._authorize_and_get_code(code_verifier)
        token_data = self._redeem_code(code, code_verifier)

        # django-oauth-toolkit 3.4.0 looks refresh tokens up by SHA-256 checksum
        expected_checksum = hashlib.sha256(token_data["refresh_token"].encode("utf-8")).hexdigest()
        rt = RefreshToken.objects.get(token_checksum=expected_checksum)
        self.assertEqual(self.app.pk, rt.application_id)

        response = self.client.post(
            reverse("oauth2_provider:token"),
            {
                "grant_type": "refresh_token",
                "refresh_token": token_data["refresh_token"],
                "client_id": self.app.client_id,
                "client_secret": CLIENT_SECRET,
            },
            secure=True,
        )
        self.assertEqual(200, response.status_code, response.content)
        refreshed = json.loads(response.content)
        self.assertIn("access_token", refreshed)
        self.assertIn("refresh_token", refreshed)

    def test_refresh_token_rejected_when_client_permissions_change(self) -> None:
        code_verifier = secrets.token_urlsafe(48)
        code = self._authorize_and_get_code(code_verifier)
        token_data = self._redeem_code(code, code_verifier)

        permission = models.MNApplicationPermission.objects.create(
            name="Test Permission", permission_name="test.permission"
        )
        self.app.required_permissions.add(permission)

        response = self.client.post(
            reverse("oauth2_provider:token"),
            {
                "grant_type": "refresh_token",
                "refresh_token": token_data["refresh_token"],
                "client_id": self.app.client_id,
                "client_secret": CLIENT_SECRET,
            },
            secure=True,
        )
        self.assertEqual(400, response.status_code, response.content)

    def test_unknown_refresh_token_is_rejected(self) -> None:
        response = self.client.post(
            reverse("oauth2_provider:token"),
            {
                "grant_type": "refresh_token",
                "refresh_token": "this-token-does-not-exist",
                "client_id": self.app.client_id,
                "client_secret": CLIENT_SECRET,
            },
            secure=True,
        )
        self.assertEqual(400, response.status_code, response.content)

    def test_oauth_server_metadata_path_form_matches_oidc_issuer(self) -> None:
        oidc_response = self.client.get("/o2/.well-known/openid-configuration", secure=True)
        self.assertEqual(200, oidc_response.status_code)
        oidc_data = json.loads(oidc_response.content)

        rfc8414_response = self.client.get(
            "/.well-known/oauth-authorization-server/o2", secure=True
        )
        self.assertEqual(200, rfc8414_response.status_code)
        rfc8414_data = json.loads(rfc8414_response.content)

        self.assertEqual(oidc_data["issuer"], rfc8414_data["issuer"])
        self.assertEqual(
            oidc_data["authorization_endpoint"], rfc8414_data["authorization_endpoint"]
        )
        self.assertEqual(oidc_data["token_endpoint"], rfc8414_data["token_endpoint"])

    def test_oauth_server_metadata_root_form_is_served(self) -> None:
        response = self.client.get("/.well-known/oauth-authorization-server", secure=True)
        self.assertEqual(200, response.status_code)
        data = json.loads(response.content)
        self.assertIn("authorization_endpoint", data)
        self.assertIn("token_endpoint", data)
