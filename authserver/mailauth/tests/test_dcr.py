import base64
import hashlib
import json
import secrets
from datetime import timedelta
from urllib.parse import parse_qs, urlsplit

from django.test import TestCase, override_settings
from django.urls import reverse
from django.utils import timezone
from jwcrypto import jwk, jwt
from oauth2_provider.models import get_access_token_model

from mailauth import models
from mailauth.dcr import INITIAL_ACCESS_TOKEN_SCOPE
from mailauth.utils import generate_rsa_key

AccessToken = get_access_token_model()

REDIRECT_URI = "https://client.example.com/callback"


class DCRRegistrationTests(TestCase):
    """
    RFC 7591/7592 Dynamic Client Registration behind an operator-minted
    initial access token, mounted at /o2/register/ (see mailauth/dcr.py).
    """

    @classmethod
    def setUpTestData(cls) -> None:
        cls.key = generate_rsa_key()
        # named "testserver" because that's the Host header the Django test
        # client sends by default; find_parent_domain() resolves the domain
        # from the request Host.
        cls.domain = models.Domain.objects.create(name="testserver", jwtkey=cls.key.private_key)

        cls.user = models.MNUser.objects.create_user(
            identifier="testuser", fullname="Test User", password="secret"
        )
        cls.alias = models.EmailAlias.objects.create(
            user=cls.user, domain=cls.domain, mailprefix="testuser"
        )
        cls.user.delivery_mailbox = cls.alias
        cls.user.save()

    def setUp(self) -> None:
        self.raw_initial_token = secrets.token_urlsafe(32)
        self.initial_token = AccessToken.objects.create(
            application=None,
            user=None,
            token=self.raw_initial_token,
            scope=INITIAL_ACCESS_TOKEN_SCOPE,
            expires=timezone.now() + timedelta(days=1),
        )

    def _register(self, metadata: dict, *, token: str = None, **extra) -> "HttpResponse":  # noqa: F821
        headers = {}
        if token is not None:
            headers["HTTP_AUTHORIZATION"] = "Bearer %s" % token
        return self.client.post(
            reverse("oauth2_provider:dcr-register"),
            data=json.dumps(metadata),
            content_type="application/json",
            secure=True,
            **headers,
            **extra,
        )

    def _public_metadata(self, **overrides) -> dict:
        metadata = {
            "client_name": "Test DCR Client",
            "redirect_uris": [REDIRECT_URI],
            "grant_types": ["authorization_code"],
            "token_endpoint_auth_method": "none",
        }
        metadata.update(overrides)
        return metadata

    # 1. POST without token -> 401 with WWW-Authenticate header, no app created
    def test_register_without_token_is_rejected(self) -> None:
        response = self._register(self._public_metadata())
        self.assertEqual(401, response.status_code, response.content)
        self.assertIn("WWW-Authenticate", response)
        self.assertFalse(models.MNApplication.objects.exists())

    # 2. POST with expired/unknown token -> 401
    def test_register_with_unknown_token_is_rejected(self) -> None:
        response = self._register(self._public_metadata(), token="this-token-does-not-exist")
        self.assertEqual(401, response.status_code, response.content)
        self.assertFalse(models.MNApplication.objects.exists())

    def test_register_with_expired_token_is_rejected(self) -> None:
        raw_expired = secrets.token_urlsafe(32)
        AccessToken.objects.create(
            application=None,
            user=None,
            token=raw_expired,
            scope=INITIAL_ACCESS_TOKEN_SCOPE,
            expires=timezone.now() - timedelta(days=1),
        )
        response = self._register(self._public_metadata(), token=raw_expired)
        self.assertEqual(401, response.status_code, response.content)
        self.assertFalse(models.MNApplication.objects.exists())

    # 3. POST with valid token and metadata -> 201, public app with domain set
    def test_register_public_client_succeeds(self) -> None:
        response = self._register(self._public_metadata(), token=self.raw_initial_token)
        self.assertEqual(201, response.status_code, response.content)
        data = json.loads(response.content)

        app = models.MNApplication.objects.get(client_id=data["client_id"])
        self.assertEqual(models.MNApplication.RegistrationSource.DCR, app.registration_source)
        self.assertEqual(self.domain, app.domain)
        self.assertEqual("public", app.client_type)
        self.assertTrue(app.pkce_enforced)
        self.assertNotIn("client_secret", data)
        self.assertIn("registration_access_token", data)
        self.assertIn("registration_client_uri", data)

    # 4. Confidential registration returns client_secret in the response body
    def test_register_confidential_client_returns_secret(self) -> None:
        metadata = self._public_metadata(token_endpoint_auth_method="client_secret_basic")
        response = self._register(metadata, token=self.raw_initial_token)
        self.assertEqual(201, response.status_code, response.content)
        data = json.loads(response.content)

        app = models.MNApplication.objects.get(client_id=data["client_id"])
        self.assertEqual("confidential", app.client_type)
        self.assertIn("client_secret", data)
        self.assertTrue(data["client_secret"])

    # 5. POST on a Host with no signing domain -> 400, no app created
    @override_settings(ALLOWED_HOSTS=["testserver", "unknown.example"])
    def test_register_on_host_without_signing_domain_fails(self) -> None:
        response = self._register(
            self._public_metadata(), token=self.raw_initial_token, HTTP_HOST="unknown.example"
        )
        self.assertEqual(400, response.status_code, response.content)
        self.assertFalse(models.MNApplication.objects.exists())

    # 6. RFC 7592 management endpoint
    def test_management_endpoint_get_put_delete(self) -> None:
        response = self._register(self._public_metadata(), token=self.raw_initial_token)
        self.assertEqual(201, response.status_code, response.content)
        data = json.loads(response.content)
        client_id = data["client_id"]
        management_token = data["registration_access_token"]

        management_url = reverse(
            "oauth2_provider:dcr-register-management", kwargs={"client_id": client_id}
        )

        # the *initial* token must be rejected on the management endpoint
        rejected = self.client.get(
            management_url, HTTP_AUTHORIZATION="Bearer %s" % self.raw_initial_token, secure=True
        )
        self.assertEqual(401, rejected.status_code, rejected.content)

        # GET with the returned registration_access_token -> 200 metadata
        get_response = self.client.get(
            management_url, HTTP_AUTHORIZATION="Bearer %s" % management_token, secure=True
        )
        self.assertEqual(200, get_response.status_code, get_response.content)
        get_data = json.loads(get_response.content)
        self.assertEqual(client_id, get_data["client_id"])

        # PUT updates client_name
        put_metadata = self._public_metadata(client_name="Renamed DCR Client")
        put_response = self.client.put(
            management_url,
            data=json.dumps(put_metadata),
            content_type="application/json",
            HTTP_AUTHORIZATION="Bearer %s" % management_token,
            secure=True,
        )
        self.assertEqual(200, put_response.status_code, put_response.content)
        app = models.MNApplication.objects.get(client_id=client_id)
        self.assertEqual("Renamed DCR Client", app.name)

        # DCR_ROTATE_REGISTRATION_TOKEN_ON_UPDATE defaults to True: PUT
        # issued a new registration_access_token and invalidated the old one.
        put_data = json.loads(put_response.content)
        management_token = put_data["registration_access_token"]

        # DELETE removes the app
        delete_response = self.client.delete(
            management_url, HTTP_AUTHORIZATION="Bearer %s" % management_token, secure=True
        )
        self.assertEqual(204, delete_response.status_code, delete_response.content)
        self.assertFalse(models.MNApplication.objects.filter(client_id=client_id).exists())

    # 7. End-to-end: DCR-registered public client completes PKCE authorize + token flow
    def test_end_to_end_pkce_flow_for_dcr_registered_client(self) -> None:
        response = self._register(self._public_metadata(), token=self.raw_initial_token)
        self.assertEqual(201, response.status_code, response.content)
        data = json.loads(response.content)
        client_id = data["client_id"]

        code_verifier = secrets.token_urlsafe(48)
        code_challenge = (
            base64.urlsafe_b64encode(hashlib.sha256(code_verifier.encode("ascii")).digest())
            .rstrip(b"=")
            .decode("ascii")
        )

        self.client.force_login(self.user)

        # DCR apps keep skip_authorization=False (model default), so the
        # user must explicitly consent; POST directly to the authorize
        # endpoint with allow=True as the consent form would.
        authorize_response = self.client.post(
            reverse("oauth2_provider:authorize"),
            {
                "allow": True,
                "response_type": "code",
                "client_id": client_id,
                "redirect_uri": REDIRECT_URI,
                "scope": "openid profile email",
                "code_challenge": code_challenge,
                "code_challenge_method": "S256",
            },
            secure=True,
        )
        self.assertEqual(302, authorize_response.status_code, getattr(authorize_response, "content", b""))
        self.assertTrue(authorize_response.url.startswith(REDIRECT_URI))
        query = parse_qs(urlsplit(authorize_response.url).query)
        self.assertIn("code", query)
        code = query["code"][0]

        token_response = self.client.post(
            reverse("oauth2_provider:token"),
            {
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": REDIRECT_URI,
                "client_id": client_id,
                "code_verifier": code_verifier,
            },
            secure=True,
        )
        self.assertEqual(200, token_response.status_code, token_response.content)
        token_data = json.loads(token_response.content)
        self.assertIn("id_token", token_data)

        pubkey = jwk.JWK.from_pem(self.key.public_key.encode("utf-8"))
        verified = jwt.JWT(key=pubkey, jwt=token_data["id_token"])
        header = json.loads(verified.header)
        claims = json.loads(verified.claims)
        self.assertEqual("RS256", header["alg"])
        self.assertEqual(str(self.user.uuid), claims["sub"])


class DCRTokenManagementCommandTests(TestCase):
    """Tests for `manage.py dcrtoken create/list/revoke`."""

    def test_create_prints_token_once_and_stores_scope(self) -> None:
        from io import StringIO

        from django.core.management import call_command

        out = StringIO()
        err = StringIO()
        call_command("dcrtoken", "create", "--expires-days", "7", stdout=out, stderr=err)

        raw_token = out.getvalue().strip()
        self.assertTrue(raw_token)
        token = AccessToken.objects.get(scope=INITIAL_ACCESS_TOKEN_SCOPE)
        self.assertEqual(raw_token, token.token)
        self.assertIn("Store this token now", err.getvalue())

    def test_create_with_zero_expires_days_is_far_future(self) -> None:
        from django.core.management import call_command
        from io import StringIO

        out = StringIO()
        call_command("dcrtoken", "create", "--expires-days", "0", stdout=out)
        token = AccessToken.objects.get(scope=INITIAL_ACCESS_TOKEN_SCOPE)
        self.assertEqual(9999, token.expires.year)

    def test_list_shows_created_tokens(self) -> None:
        from django.core.management import call_command
        from io import StringIO

        create_out = StringIO()
        call_command("dcrtoken", "create", stdout=create_out)
        raw_token = create_out.getvalue().strip()

        list_out = StringIO()
        call_command("dcrtoken", "list", stdout=list_out)
        listing = list_out.getvalue()
        self.assertIn(raw_token[:8], listing)

    def test_list_with_no_tokens_writes_to_stderr(self) -> None:
        from django.core.management import call_command
        from io import StringIO

        out = StringIO()
        err = StringIO()
        call_command("dcrtoken", "list", stdout=out, stderr=err)
        self.assertEqual("", out.getvalue())
        self.assertIn("No initial access tokens found", err.getvalue())

    def test_revoke_by_id_deletes_token(self) -> None:
        from django.core.management import call_command
        from io import StringIO

        create_out = StringIO()
        call_command("dcrtoken", "create", stdout=create_out)
        token = AccessToken.objects.get(scope=INITIAL_ACCESS_TOKEN_SCOPE)

        revoke_err = StringIO()
        call_command("dcrtoken", "revoke", str(token.id), stderr=revoke_err)
        self.assertFalse(AccessToken.objects.filter(pk=token.pk).exists())
        self.assertIn(str(token.id), revoke_err.getvalue())

    def test_revoke_by_unique_prefix_deletes_token(self) -> None:
        from django.core.management import call_command
        from io import StringIO

        create_out = StringIO()
        call_command("dcrtoken", "create", stdout=create_out)
        raw_token = create_out.getvalue().strip()
        token = AccessToken.objects.get(scope=INITIAL_ACCESS_TOKEN_SCOPE)

        call_command("dcrtoken", "revoke", raw_token[:12])
        self.assertFalse(AccessToken.objects.filter(pk=token.pk).exists())

    def test_revoke_unknown_id_exits_nonzero(self) -> None:
        from django.core.management import call_command

        with self.assertRaises(SystemExit) as exit_ctx:
            call_command("dcrtoken", "revoke", "999999")
        self.assertNotEqual(0, exit_ctx.exception.code)

    def test_dcrtoken_does_not_grant_registration_management_access(self) -> None:
        """
        Sanity check for the design note in the plan: an initial access
        token cannot be used against the RFC 7592 management endpoint even
        if it somehow carried the DCR_REGISTRATION_SCOPE, because it has no
        application. Exercised end-to-end in DCRRegistrationTests; this just
        confirms the token has no application attached at creation time.
        """
        from django.core.management import call_command
        from io import StringIO

        out = StringIO()
        call_command("dcrtoken", "create", stdout=out)
        token = AccessToken.objects.get(scope=INITIAL_ACCESS_TOKEN_SCOPE)
        self.assertIsNone(token.application)
        self.assertIsNone(token.user)
