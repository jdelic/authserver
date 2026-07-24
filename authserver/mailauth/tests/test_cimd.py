import base64
import hashlib
import json
import secrets
from urllib.parse import parse_qs, urlsplit

from django.conf import settings
from django.core.cache import cache
from django.test import TestCase, override_settings
from django.urls import reverse
from jwcrypto import jwk, jwt

from mailauth import models
from mailauth.cimd import auto_permission_name
from mailauth.utils import generate_rsa_key

CLIENT_ID = "https://mcp.client.example/oauth-client"
CLIENT_REDIRECT_URI = "https://mcp.client.example/callback"


class StubFetcher:
    """Test double for CIMD_METADATA_FETCHER: never touches the network."""

    documents = {}  # client_id -> metadata dict, filled per-test

    def fetch(self, client_id):
        from oauth2_provider.cimd import CIMDError

        if client_id not in self.documents:
            raise CIMDError("not found")
        return self.documents[client_id], 300


def _oauth2_provider_settings(**overrides):
    """Rebuild the whole OAUTH2_PROVIDER dict (override_settings replaces it
    wholesale) with the StubFetcher wired in, plus any per-test overrides."""
    base = dict(settings.OAUTH2_PROVIDER)
    base["CIMD_METADATA_FETCHER"] = "mailauth.tests.test_cimd.StubFetcher"
    base.update(overrides)
    return base


class CIMDRegistrationTests(TestCase):
    """
    CIMD (Client ID Metadata Document) resolution, gated per-Domain via
    cimd_enabled / cimd_client_hosts / cimd_auto_permissions (mailauth/cimd.py),
    hooked into ClientPermissionValidator._load_application (mailauth/oauth2.py).
    """

    @classmethod
    def setUpTestData(cls) -> None:
        cls.key = generate_rsa_key()
        # named "testserver" because that's the Host header the Django test
        # client sends by default; _domain_for_oauthlib_request() resolves
        # the domain from the request Host.
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
        # Reset the CIMD failure backoff between tests (it lives in the
        # Django cache and would otherwise suppress resolution in a later
        # test for CIMD_FAILURE_BACKOFF_SECONDS).
        cache.clear()
        StubFetcher.documents = {
            CLIENT_ID: {
                "client_id": CLIENT_ID,
                "client_name": "Stub MCP client",
                "redirect_uris": [CLIENT_REDIRECT_URI],
                "grant_types": ["authorization_code"],
                "token_endpoint_auth_method": "none",
            }
        }
        self.client.force_login(self.user)

    def _authorize(self):
        # Explicit HTTP_HOST: the Django test client does not populate the
        # HTTP_HOST WSGI key unless told to (it otherwise only sets
        # SERVER_NAME). DomainCIMDPermission reads the raw HTTP_HOST key
        # from the oauthlib request (see the plan's warning: request.uri is
        # path-only), so a real client's Host header must be simulated here
        # to match production behavior.
        code_verifier = secrets.token_urlsafe(48)
        code_challenge = (
            base64.urlsafe_b64encode(hashlib.sha256(code_verifier.encode("ascii")).digest())
            .rstrip(b"=")
            .decode("ascii")
        )
        params = {
            "response_type": "code",
            "client_id": CLIENT_ID,
            "redirect_uri": CLIENT_REDIRECT_URI,
            "scope": "openid profile email",
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
        }
        response = self.client.get(
            reverse("oauth2_provider:authorize"), params, secure=True, HTTP_HOST="testserver"
        )
        return response, code_verifier

    def _authorize_with_consent(self, code_verifier: str):
        # CIMD applications keep skip_authorization=False (model default, same
        # as DCR apps), so a bare GET only ever renders the consent form (or,
        # if the app already has required_permissions, unauthorized.html) - it
        # never redirects. Completing the flow needs an explicit POST with
        # allow=True, mirroring the consent form's own submission, exactly
        # like DCRRegistrationTests's end-to-end test. This requires the
        # Application to already exist (a prior _authorize() GET call creates
        # it via the CIMD _load_application hook).
        code_challenge = (
            base64.urlsafe_b64encode(hashlib.sha256(code_verifier.encode("ascii")).digest())
            .rstrip(b"=")
            .decode("ascii")
        )
        return self.client.post(
            reverse("oauth2_provider:authorize"),
            {
                "allow": True,
                "response_type": "code",
                "client_id": CLIENT_ID,
                "redirect_uri": CLIENT_REDIRECT_URI,
                "scope": "openid profile email",
                "code_challenge": code_challenge,
                "code_challenge_method": "S256",
            },
            secure=True,
            HTTP_HOST="testserver",
        )

    def _complete_flow(self, code_verifier: str, code: str) -> dict:
        response = self.client.post(
            reverse("oauth2_provider:token"),
            {
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": CLIENT_REDIRECT_URI,
                "client_id": CLIENT_ID,
                "code_verifier": code_verifier,
            },
            secure=True,
            HTTP_HOST="testserver",
        )
        self.assertEqual(200, response.status_code, response.content)
        return json.loads(response.content)

    # 1. cimd_enabled=False -> error page (400 family), no app created
    @override_settings(OAUTH2_PROVIDER=_oauth2_provider_settings())
    def test_cimd_disabled_rejects_registration(self) -> None:
        self.domain.cimd_enabled = False
        self.domain.cimd_client_hosts = [".client.example"]
        self.domain.save()

        response, _ = self._authorize()
        self.assertGreaterEqual(response.status_code, 400)
        self.assertLess(response.status_code, 500)
        self.assertFalse(models.MNApplication.objects.filter(client_id=CLIENT_ID).exists())

    # 2. cimd_enabled=True but cimd_client_hosts=[] -> fail-closed allowlist
    @override_settings(OAUTH2_PROVIDER=_oauth2_provider_settings())
    def test_empty_allowlist_denies_all_clients(self) -> None:
        self.domain.cimd_enabled = True
        self.domain.cimd_client_hosts = []
        self.domain.save()

        response, _ = self._authorize()
        self.assertGreaterEqual(response.status_code, 400)
        self.assertLess(response.status_code, 500)
        self.assertFalse(models.MNApplication.objects.filter(client_id=CLIENT_ID).exists())

    # 3. cimd_client_hosts=["other.example"] (non-matching) -> same as (1)/(2)
    @override_settings(OAUTH2_PROVIDER=_oauth2_provider_settings())
    def test_non_matching_allowlist_denies_client(self) -> None:
        self.domain.cimd_enabled = True
        self.domain.cimd_client_hosts = ["other.example"]
        self.domain.save()

        response, _ = self._authorize()
        self.assertGreaterEqual(response.status_code, 400)
        self.assertLess(response.status_code, 500)
        self.assertFalse(models.MNApplication.objects.filter(client_id=CLIENT_ID).exists())

    # 4. matching allowlist -> app created, auto-permission created and
    #    attached, assigned to no user -> unauthorized.html rendering
    @override_settings(OAUTH2_PROVIDER=_oauth2_provider_settings())
    def test_matching_allowlist_creates_app_but_blocks_unauthorized_user(self) -> None:
        self.domain.cimd_enabled = True
        self.domain.cimd_client_hosts = [".client.example"]
        self.domain.save()

        response, _ = self._authorize()
        self.assertEqual(200, response.status_code, getattr(response, "content", b""))
        self.assertTemplateUsed(response, "oauth2_provider/unauthorized.html")

        app = models.MNApplication.objects.get(client_id=CLIENT_ID)
        self.assertEqual(models.MNApplication.RegistrationSource.CIMD, app.registration_source)
        self.assertEqual(self.domain, app.domain)

        permission_name = auto_permission_name(CLIENT_ID)
        permission = models.MNApplicationPermission.objects.get(permission_name=permission_name)
        self.assertIn(permission, app.required_permissions.all())
        self.assertFalse(permission.user_set.exists())

    # 5. Assign the permission to the test user -> authorize 302s with a
    #    code; complete the token exchange incl. RS256 ID-token verification.
    @override_settings(OAUTH2_PROVIDER=_oauth2_provider_settings())
    def test_assigning_permission_unblocks_authorize_and_token_flow(self) -> None:
        self.domain.cimd_enabled = True
        self.domain.cimd_client_hosts = [".client.example"]
        self.domain.save()

        # First hit creates the app + auto-permission (still blocked).
        blocked_response, _ = self._authorize()
        self.assertEqual(200, blocked_response.status_code)
        self.assertTemplateUsed(blocked_response, "oauth2_provider/unauthorized.html")

        permission_name = auto_permission_name(CLIENT_ID)
        permission = models.MNApplicationPermission.objects.get(permission_name=permission_name)
        self.user.app_permissions.add(permission)

        code_verifier = secrets.token_urlsafe(48)
        response = self._authorize_with_consent(code_verifier)
        self.assertEqual(302, response.status_code, getattr(response, "content", b""))
        self.assertTrue(response.url.startswith(CLIENT_REDIRECT_URI))
        query = parse_qs(urlsplit(response.url).query)
        self.assertIn("code", query)
        code = query["code"][0]

        token_data = self._complete_flow(code_verifier, code)
        self.assertIn("id_token", token_data)

        pubkey = jwk.JWK.from_pem(self.key.public_key.encode("utf-8"))
        verified = jwt.JWT(key=pubkey, jwt=token_data["id_token"])
        header = json.loads(verified.header)
        claims = json.loads(verified.claims)
        self.assertEqual("RS256", header["alg"])
        self.assertEqual(str(self.user.uuid), claims["sub"])

    # 6. cimd_auto_permissions=False -> app created with empty
    #    required_permissions and the flow works immediately.
    @override_settings(OAUTH2_PROVIDER=_oauth2_provider_settings())
    def test_auto_permissions_disabled_allows_immediate_use(self) -> None:
        self.domain.cimd_enabled = True
        self.domain.cimd_client_hosts = [".client.example"]
        self.domain.cimd_auto_permissions = False
        self.domain.save()

        # First hit creates the app (no permission required, so this already
        # renders the normal consent form rather than unauthorized.html).
        probe_response, _ = self._authorize()
        self.assertEqual(200, probe_response.status_code, getattr(probe_response, "content", b""))
        self.assertTemplateNotUsed(probe_response, "oauth2_provider/unauthorized.html")

        app = models.MNApplication.objects.get(client_id=CLIENT_ID)
        self.assertEqual(0, app.required_permissions.count())

        code_verifier = secrets.token_urlsafe(48)
        response = self._authorize_with_consent(code_verifier)
        self.assertEqual(302, response.status_code, getattr(response, "content", b""))
        query = parse_qs(urlsplit(response.url).query)
        self.assertIn("code", query)

        token_data = self._complete_flow(code_verifier, query["code"][0])
        self.assertIn("id_token", token_data)

    # 7. Wildcard ["*"] allows an arbitrary host.
    @override_settings(OAUTH2_PROVIDER=_oauth2_provider_settings())
    def test_wildcard_allowlist_allows_arbitrary_host(self) -> None:
        self.domain.cimd_enabled = True
        self.domain.cimd_client_hosts = ["*"]
        self.domain.cimd_auto_permissions = False
        self.domain.save()

        self._authorize()
        self.assertTrue(models.MNApplication.objects.filter(client_id=CLIENT_ID).exists())

        code_verifier = secrets.token_urlsafe(48)
        response = self._authorize_with_consent(code_verifier)
        self.assertEqual(302, response.status_code, getattr(response, "content", b""))
        query = parse_qs(urlsplit(response.url).query)
        self.assertIn("code", query)

    # 8. Idempotency: hit authorize twice; exactly one permission row, one
    #    M2M link.
    @override_settings(OAUTH2_PROVIDER=_oauth2_provider_settings())
    def test_repeated_authorize_is_idempotent(self) -> None:
        self.domain.cimd_enabled = True
        self.domain.cimd_client_hosts = [".client.example"]
        self.domain.save()

        self._authorize()
        self._authorize()

        permission_name = auto_permission_name(CLIENT_ID)
        self.assertEqual(
            1, models.MNApplicationPermission.objects.filter(permission_name=permission_name).count()
        )
        app = models.MNApplication.objects.get(client_id=CLIENT_ID)
        self.assertEqual(1, app.required_permissions.count())
        self.assertEqual(1, models.MNApplication.objects.filter(client_id=CLIENT_ID).count())
