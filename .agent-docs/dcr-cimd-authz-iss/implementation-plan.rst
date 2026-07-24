Implementation plan: DCR, CIMD and RFC 9207 ``iss`` for authserver
==================================================================

:Date: 2026-07-24
:Status: PLANNED — not implemented
:Depends on: the django-oauth-toolkit 3.4.0 upgrade
             (branch ``update/django-oauth-toolkit-3.4.0``, see
             ``.agent-docs/django-oauth-toolkit-3.4.0/findings.rst``)
:Decisions confirmed by Jonas: DCR domain is derived from the request Host;
             CIMD is gated per-``Domain`` with a **fail-closed** client-host
             allowlist (empty list = deny all, wildcard must be explicit).

This document is written so that an implementer with **no prior context** can
execute it. Read sections 1 and 2 before touching any code.


1. Required background about authserver
---------------------------------------

Facts you must know; all paths are relative to the repo root
(``~/authserver``), the Django project lives in ``authserver/``:

* **Swapped application model.** ``settings.OAUTH2_PROVIDER_APPLICATION_MODEL
  = 'mailauth.MNApplication'``. ``MNApplication``
  (``authserver/mailauth/models.py``) extends django-oauth-toolkit's (DOT)
  ``AbstractApplication`` with:

  - ``pkce_enforced`` (BooleanField, default **True**) — consumed by
    ``mailauth.oauth2.check_pkce_required``, wired via
    ``OAUTH2_PROVIDER['PKCE_REQUIRED']``.
  - ``required_permissions`` (M2M to ``MNApplicationPermission``) — the
    authorization gate: ``mailauth.permissions.find_missing_permissions(app,
    user)`` returns the required permissions the user does not have (via
    direct assignment or ``MNGroup`` membership). A non-empty result blocks
    the authorize flow (``ScopeValidationAuthView`` renders
    ``oauth2_provider/unauthorized.html``) and refresh-token grants
    (``ClientPermissionValidator.validate_refresh_token``). **An application
    with an empty ``required_permissions`` set is usable by every user.**
  - ``domain`` (FK to ``mailauth.Domain``, nullable) — provides the RSA key
    for OIDC ID-token signing through the ``jwk_key`` property (falls back to
    a parent domain with ``jwt_subdomains=True``). ``algorithm`` is a
    property hard-coded to RS256.

* **An application whose ``domain`` is NULL cannot sign ID tokens** —
  ``jwk_key`` returns ``None`` and token issuance crashes if the ``openid``
  scope is in play. Important: ``mailauth.scopes.MNAuthScopes
  .get_default_scopes()`` returns **all** scopes including ``openid`` when a
  client requests no explicit scope, so a domain-less application is a
  landmine, not a degraded-but-working client. Every application created by
  DCR or CIMD must therefore get a domain assigned (both features below
  guarantee this).

* **Multi-tenant issuers.** OAuth2/OIDC endpoints are mounted under ``o2/``
  in ``authserver/authserver/urls.py`` inside an include with app namespace
  ``'oauth2_provider'`` (the tuple ``oauth2_patterns``). The issuer is
  ``https://<request-host>/o2`` — DOT derives it per-request
  (``oauth2_settings.oidc_issuer(request)``). Which authserver ``Domain`` a
  host belongs to is resolved with
  ``Domain.objects.find_parent_domain(fqdn, require_jwt_subdomains_set=True,
  require_jwt_key=True)`` (raises ``Domain.DoesNotExist``); see
  ``WebFingerView`` and ``UserLoginAPIView`` in
  ``authserver/mailauth/views.py`` for the canonical usage pattern,
  including stripping ``:port`` from ``request.get_host()``.

* **Custom validator.** ``OAUTH2_PROVIDER['OAUTH2_VALIDATOR_CLASS'] =
  'mailauth.oauth2.ClientPermissionValidator'``
  (``authserver/mailauth/oauth2.py``).

* **Tests** live in ``authserver/mailauth/tests/``; run with::

    envdir <envdir> django-admin test authserver.tests mailauth.tests

  where the envdir sets ``DJANGO_SETTINGS_MODULE=authserver.settings``,
  ``DATABASE_NAME/USER/PASSWORD=authtest``, ``DATABASE_PARENTROLE=authtest``,
  ``SECRET_KEY``. The ``authtest`` role has CREATEDB. See
  ``mailauth/tests/test_oauth2_oidc.py`` for an existing end-to-end OIDC flow
  test with reusable setup code (domain with RSA key, user with delivery
  mailbox, application, PKCE authorize + token exchange).

* **Branching:** fork feature branches off ``develop`` (after the
  ``update/django-oauth-toolkit-3.4.0`` branch is merged; if it is not
  merged yet, stack on top of it). Commit as author
  ``claude <claude@maurus.net>`` if implemented by an agent.


2. Reference: DOT 3.4.0 source files
------------------------------------

Consult these inside the installed package (``site-packages/oauth2_provider``):

===========================================  ==================================================
File                                         Relevance
===========================================  ==================================================
``views/dynamic_client_registration.py``     RFC 7591 POST view, RFC 7592 management view,
                                             ``_issue_registration_token``, response building
``dcr.py``                                   DCR permission classes + ``enforce_csrf`` helper
``cimd.py``                                  CIMD resolver (``resolve_cimd_application``,
                                             ``refresh_if_stale``, ``_fetch_validate_upsert``),
                                             permission classes, ``SafeMetadataFetcher``
``oauth2_validators.py``                     ``OAuth2Validator._load_application`` — the ONLY
                                             place CIMD resolution is triggered
``oauth2_backends.py``                       ``OAuthLibCore.create_authorization_response``,
                                             ``_add_iss_to_redirect`` (RFC 9207)
``settings.py``                              all ``DCR_*``, ``CIMD_*``, ``COMPLIANT_*`` defaults
``urls.py``                                  upstream URL names the views ``reverse()``
===========================================  ==================================================

Upstream behaviors you must NOT re-implement (they already exist): SSRF
hardening of the CIMD fetch, CIMD failure backoff + concurrency cap, the
"manually provisioned app cannot be taken over by a CIMD document" guard, the
RFC 7592 rule that management tokens only work for ``registration_source ==
"dcr"`` applications, secret hashing on save.


3. Feature 1: Dynamic Client Registration (RFC 7591/7592)
---------------------------------------------------------

3.1 Goal
~~~~~~~~

A client that possesses a pre-shared **initial access token** (RFC 7591 §1.2
term) can self-register by POSTing its metadata to
``https://<host>/o2/register/``. The token is minted by an operator through a
management command. The new application automatically gets the ``Domain``
that signs for ``<host>``; registration on a host without a signing domain is
rejected. Registered clients manage themselves via RFC 7592 using the
per-application ``registration_access_token`` that DOT issues automatically.

3.2 Upstream mechanics you build on (verified facts)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

* Both DCR views return 404 unless ``OAUTH2_PROVIDER['DCR_ENABLED']`` is
  True; the URLs additionally do not exist until we mount them (authserver
  assembles its URL patterns manually).
* On POST, ``_check_permissions`` instantiates every class in
  ``DCR_REGISTRATION_PERMISSION_CLASSES`` and requires **all** to pass;
  an empty tuple denies everything. The default class
  (``IsAuthenticatedDCRPermission``) requires ``request.user`` to be
  authenticated — a bare ``Authorization: Bearer`` header does **not**
  authenticate ``request.user`` in authserver (no OAuth middleware on this
  path), so a custom permission class is required for token-based
  registration.
* The view creates the application with
  ``registration_source=RegistrationSource.DCR``, ``user=None`` for
  anonymous requests, and metadata-derived fields (``redirect_uris``,
  ``name``, ``authorization_grant_type`` — exactly one grant type,
  ``client_type`` from ``token_endpoint_auth_method``). It calls
  ``application.full_clean()`` — fine for ``MNApplication`` (the RS256
  branch of ``clean()`` only requires ``OIDC_RSA_PRIVATE_KEY`` to be truthy,
  which authserver's ``'<unused>'`` placeholder satisfies).
* After saving it creates the RFC 7592 management token:
  an ``AccessToken`` row with ``scope=DCR_REGISTRATION_SCOPE``
  (default ``"oauth2_provider:registration"``), bound to the new
  application. The management view later looks that token up **by SHA-256
  ``token_checksum``**, checks ``token.is_valid([DCR_REGISTRATION_SCOPE])``,
  requires ``token.application.client_id == <path client_id>`` and
  ``registration_source == "dcr"``.
* The registration response contains ``registration_client_uri`` built with
  ``reverse("oauth2_provider:dcr-register-management", ...)`` — that URL
  name **must** be mounted or registration responses crash with
  ``NoReverseMatch``.
* ``AccessToken.token_checksum`` is filled automatically by
  ``TokenChecksumField.pre_save`` whenever a row is saved with a plaintext
  ``token`` value — including rows created manually via the ORM (this is how
  the management command below can mint tokens).

3.3 Design (confirmed with Jonas)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

* Initial access tokens are plain ``AccessToken`` rows: ``application=None``,
  ``user=None``, ``scope="authserver:dcr-initial"``, expiry configurable at
  mint time. No new model, no migration.
* The scope string is deliberately different from
  ``DCR_REGISTRATION_SCOPE`` so the two token kinds cannot be confused.
  (Even with the same scope the management endpoint would reject an initial
  token — ``application`` is NULL so the client_id match fails — but a
  distinct scope keeps intent obvious.)
* The Domain comes from the request Host. Registration on a host that has no
  signing domain **fails** with 400 — this guarantees every DCR application
  can sign ID tokens (see section 1).
* ``required_permissions`` stays empty for DCR apps: possession of the
  initial token is the admission control. (If per-app lockdown is wanted
  later, reuse the CIMD auto-permission helper from Feature 2.)
* ``skip_authorization`` stays False (users see the consent screen);
  ``pkce_enforced`` defaults to True (model default) so public DCR clients
  must use PKCE — correct for MCP clients.

3.4 Implementation steps
~~~~~~~~~~~~~~~~~~~~~~~~

**(a) New module ``authserver/mailauth/dcr.py``:**

.. code-block:: python

    """DCR (RFC 7591) support: initial-access-token permission and view."""
    import hashlib
    import json

    from oauth2_provider.models import get_access_token_model
    from oauth2_provider.utils import parse_bearer_token
    from oauth2_provider.views.dynamic_client_registration import (
        DynamicClientRegistrationView,
        _error_response,
    )

    from mailauth.models import Domain, MNApplication

    # Scope carried by operator-minted initial access tokens
    # (see the `dcrtoken` management command).
    INITIAL_ACCESS_TOKEN_SCOPE = "authserver:dcr-initial"


    class InitialAccessTokenDCRPermission:
        """
        RFC 7591 initial access token check: the request must carry a Bearer
        token minted by `manage.py dcrtoken create`. Configured via
        OAUTH2_PROVIDER["DCR_REGISTRATION_PERMISSION_CLASSES"].
        """

        def has_permission(self, request) -> bool:
            raw_token = parse_bearer_token(request.META.get("HTTP_AUTHORIZATION", ""))
            if raw_token is None:
                return False
            checksum = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()
            access_token_model = get_access_token_model()
            try:
                token = access_token_model.objects.get(token_checksum=checksum)
            except access_token_model.DoesNotExist:
                return False
            return token.is_valid([INITIAL_ACCESS_TOKEN_SCOPE])


    class MNDynamicClientRegistrationView(DynamicClientRegistrationView):
        """
        Wraps the upstream RFC 7591 view to bind the new application to the
        Domain that signs for the request host, mirroring how the rest of
        authserver resolves issuers. Rejects hosts without a signing domain
        BEFORE the upstream view creates anything.
        """

        def post(self, request, *args, **kwargs):
            hostname = request.get_host().split(":")[0]
            try:
                domain = Domain.objects.find_parent_domain(
                    hostname, require_jwt_subdomains_set=True, require_jwt_key=True
                )
            except Domain.DoesNotExist:
                return _error_response(
                    "invalid_client_metadata",
                    "This host is not a valid registration domain",
                )

            response = super().post(request, *args, **kwargs)

            if response.status_code == 201:
                client_id = json.loads(response.content)["client_id"]
                MNApplication.objects.filter(client_id=client_id).update(domain=domain)
            return response

  Notes for the implementer:

  - ``_error_response`` is imported from the upstream module to keep the
    RFC 7591 error shape; if importing the underscore name is considered too
    fragile, inline an equivalent ``JsonResponse({"error":
    "invalid_client_metadata", "error_description": ...}, status=400)``.
  - ``.update(domain=domain)`` avoids re-running ``full_clean``/secret
    hashing on the already-saved row.

**(b) New management command
``authserver/mailauth/management/commands/dcrtoken.py``:**

Model it on the existing subcommand-style commands (see
``mailauth/management/commands/oauth2.py`` for the subparser pattern).
Subcommands:

* ``create`` — options: ``--expires-days N`` (default 30; ``0`` = no expiry,
  implemented as year-9999 like upstream's ``_issue_registration_token``).
  Behavior: mint ``secrets.token_urlsafe(32)``, create
  ``AccessToken(application=None, user=None, token=<raw>,
  scope=INITIAL_ACCESS_TOKEN_SCOPE, expires=<computed>)`` and print the raw
  token to stdout exactly once with a "store this now" warning.
* ``list`` — print id, ``token[:8]…`` prefix, expiry, created timestamp of
  all AccessToken rows with ``scope=INITIAL_ACCESS_TOKEN_SCOPE``.
* ``revoke <id-or-prefix>`` — delete the matching row (refuse ambiguous
  prefixes).

Import ``INITIAL_ACCESS_TOKEN_SCOPE`` from ``mailauth.dcr`` — do not
duplicate the string.

**(c) Settings (``authserver/authserver/settings.py``), add to the
``OAUTH2_PROVIDER`` dict:**

.. code-block:: python

    'DCR_ENABLED': True,
    # registration requires an operator-minted initial access token,
    # see mailauth/dcr.py and the `dcrtoken` management command
    'DCR_REGISTRATION_PERMISSION_CLASSES': (
        'mailauth.dcr.InitialAccessTokenDCRPermission',
    ),

(String import paths work: the setting is in DOT's ``IMPORT_STRINGS``.)

**(d) URLs (``authserver/authserver/urls.py``), add to ``oauth2_patterns``
— names must be exactly these:**

.. code-block:: python

    from mailauth.dcr import MNDynamicClientRegistrationView
    # inside oauth2_patterns:
    path('register/', MNDynamicClientRegistrationView.as_view(), name='dcr-register'),
    path('register/<str:client_id>/',
         oauth2_views.DynamicClientRegistrationManagementView.as_view(),
         name='dcr-register-management'),

**(e) Tests — new ``authserver/mailauth/tests/test_dcr.py``** (reuse the
setUp pattern from ``test_oauth2_oidc.py``: a ``Domain`` with
``generate_rsa_key().private_key`` as ``jwtkey``). Cases:

1. POST without token → 401 with ``WWW-Authenticate`` header, no app created.
2. POST with expired/unknown token → 401.
3. POST with valid token and metadata ``{"client_name": ..,
   "redirect_uris": [..], "grant_types": ["authorization_code"],
   "token_endpoint_auth_method": "none"}`` → 201; assert the created
   ``MNApplication`` has ``registration_source == "dcr"``,
   ``domain`` set to the test domain, ``client_type == "public"``,
   ``pkce_enforced`` True.
4. Confidential registration (``token_endpoint_auth_method``
   ``client_secret_basic``) returns ``client_secret`` in the response body.
5. POST on a Host with no signing domain (use
   ``self.client.post(..., HTTP_HOST="unknown.example")`` — remember
   ``ALLOWED_HOSTS`` is ``['*']`` only under DEBUG; in tests Django allows
   ``testserver`` — use ``@override_settings(ALLOWED_HOSTS=[...])`` if
   needed) → 400, no app created.
6. RFC 7592: GET with the returned ``registration_access_token`` → 200
   metadata; PUT updates ``client_name``; DELETE removes the app. The
   *initial* token must be rejected on the management endpoint (401).
7. End-to-end: a DCR-registered public client completes the PKCE
   authorize + token flow and the ID token verifies against the domain key
   (copy the helpers from ``test_oauth2_oidc.py``).

3.5 Acceptance criteria
~~~~~~~~~~~~~~~~~~~~~~~

* All new tests plus the whole existing suite pass.
* ``manage.py dcrtoken create/list/revoke`` works against a live DB.
* With ``DCR_ENABLED`` flipped to False in settings the endpoints return 404
  (upstream behavior; nothing else may break).
* No change in behavior for manually provisioned applications.


4. Feature 2: CIMD (Client ID Metadata Documents)
-------------------------------------------------

4.1 Goal
~~~~~~~~

A client whose ``client_id`` is an ``https://`` URL can be resolved
automatically: authserver fetches the URL, and the JSON document found there
becomes the client's registration. Gating (confirmed with Jonas):

* per-``Domain`` opt-in: new flag ``cimd_enabled`` (default False);
* per-``Domain`` **fail-closed** client-host allowlist
  ``cimd_client_hosts``: a list of patterns the *client_id URL's host* must
  match. An **empty list denies all clients** even when ``cimd_enabled`` is
  True; allowing everything requires an explicit ``"*"`` entry.
* per-``Domain`` flag ``cimd_auto_permissions`` (default True): every newly
  registered CIMD application gets a dedicated, freshly created
  ``MNApplicationPermission`` attached to its ``required_permissions``.
  The permission is assigned to **nobody**, so no user can complete the
  authorize flow until an admin assigns it to users or groups (that page —
  ``unauthorized.html`` — is exactly what users see until then). Approving a
  CIMD client == assigning its permission.

4.2 Upstream mechanics you build on (verified facts)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

* CIMD has **no endpoints**. The hook is inside
  ``OAuth2Validator._load_application`` (``oauth2_validators.py`` ~line
  355): for an unknown ``client_id`` that starts with ``https://`` it calls
  ``cimd.resolve_cimd_application(client_id, request)``; for a known CIMD
  application it calls ``cimd.refresh_if_stale(application, request)``.
  Everything happens during normal authorize/token requests.
* ``resolve_cimd_application`` returns ``None`` (→ "unknown client") when
  CIMD is disabled, a permission class refuses, the URL is in failure
  backoff, the in-flight cap is hit, or the fetch/validation fails.
* Permission classes come from
  ``CIMD_REGISTRATION_PERMISSION_CLASSES``; each is called as
  ``cls().has_permission(request, client_id)`` — **all** must pass, empty
  tuple fails closed. ``request`` here is the **oauthlib** request, NOT a
  Django ``HttpRequest``.

  .. warning::
     ``request.uri`` on the oauthlib request is only the escaped **path**
     (DOT's ``_get_escaped_full_path``) — it has no scheme/host. The request
     host must be read from ``request.headers["HTTP_HOST"]`` (the headers
     dict is a copy of Django's ``request.META``; strip a ``:port`` suffix).
     Getting this wrong makes every permission check fail silently.

* ``_fetch_validate_upsert`` (creation/refresh) sets ``user=None``,
  ``client_type="public"``, ``registration_source="cimd"``,
  ``cimd_expires_at``, and the metadata fields (``redirect_uris``, ``name``,
  ``authorization_grant_type``). It does **not** touch ``domain`` or any
  M2M — authserver-added state survives metadata refreshes.
* There is **no post-creation hook upstream.** The clean authserver-side
  interception point is overriding ``_load_application`` in
  ``ClientPermissionValidator`` (already our validator class).
* The failure backoff uses Django's cache framework. authserver defines no
  ``CACHES`` setting → per-process LocMem cache. Acceptable (backoff is
  best-effort by design); note it in the commit message.

4.3 Implementation steps
~~~~~~~~~~~~~~~~~~~~~~~~

**(a) Model changes (``authserver/mailauth/models.py``, class ``Domain``):**

.. code-block:: python

    cimd_enabled = models.BooleanField(
        verbose_name="Allow CIMD client registration",
        default=False,
        help_text="Allow OAuth2 clients to self-register on this domain using "
                  "Client ID Metadata Documents (their client_id is an https URL "
                  "that authserver fetches). Which client hosts are acceptable is "
                  "controlled by the CIMD client host allowlist below.")

    cimd_client_hosts = ArrayField(
        models.CharField(max_length=255),
        verbose_name="CIMD client host allowlist",
        default=list, blank=True,
        help_text="Hosts that CIMD client_id URLs may use, in Django "
                  "ALLOWED_HOSTS syntax: 'client.example.com' (exact), "
                  "'.example.com' (domain and all subdomains), '*' (any host - "
                  "must be set explicitly). An EMPTY list blocks all CIMD "
                  "clients even when CIMD is enabled.")

    cimd_auto_permissions = models.BooleanField(
        verbose_name="Auto-generate permissions for CIMD applications",
        default=True,
        help_text="When a CIMD application registers on this domain, create a "
                  "dedicated application permission, require it on the "
                  "application, and assign it to nobody - so no user can "
                  "authorize against the client until an admin grants the "
                  "permission.")

Then ``manage.py makemigrations mailauth`` → migration ``0030_...``
(three ``AddField`` on ``domain``; no data migration needed).
``ArrayField`` is already imported in ``models.py``. The Domain admin form
(``DomainForm``) uses ``ALL_FIELDS`` so the fields appear automatically; no
admin change needed.

**(b) New module ``authserver/mailauth/cimd.py``:**

.. code-block:: python

    """CIMD (Client ID Metadata Document) policy for authserver.

    Gating and post-registration normalization are per mailauth.Domain:
    see Domain.cimd_enabled / cimd_client_hosts / cimd_auto_permissions.
    """
    import hashlib
    import logging
    from urllib.parse import urlparse

    from django.http.request import validate_host

    from mailauth.models import Domain, MNApplication, MNApplicationPermission

    _log = logging.getLogger(__name__)


    def _domain_for_oauthlib_request(request):
        """Resolve the mailauth.Domain serving an oauthlib request.

        request.headers is a copy of Django's META, so the Host header is
        HTTP_HOST. request.uri holds only the path - do NOT parse it for a
        hostname. Returns None when no signing domain matches.
        """
        host = (request.headers.get("HTTP_HOST") or "").split(":")[0]
        if not host:
            return None
        try:
            return Domain.objects.find_parent_domain(
                host, require_jwt_subdomains_set=True, require_jwt_key=True
            )
        except Domain.DoesNotExist:
            return None


    class DomainCIMDPermission:
        """CIMD gate: the request's Domain must have cimd_enabled and the
        client_id URL's host must match the domain's fail-closed allowlist
        (empty allowlist = deny; '*' must be explicit)."""

        def has_permission(self, request, client_id) -> bool:
            domain = _domain_for_oauthlib_request(request)
            if domain is None or not domain.cimd_enabled:
                return False
            client_host = urlparse(client_id).hostname
            if not client_host or not domain.cimd_client_hosts:
                return False
            return validate_host(client_host, domain.cimd_client_hosts)


    def auto_permission_name(client_id: str) -> str:
        """Deterministic, unique, <=255 char permission identifier for a CIMD
        client. Includes the client host for readability and a hash of the
        full URL for uniqueness."""
        digest = hashlib.sha256(client_id.encode("utf-8")).hexdigest()[:16]
        host = urlparse(client_id).hostname or "unknown"
        return "cimd:%s:%s" % (host[:200], digest)


    def ensure_cimd_application_defaults(application: MNApplication, request) -> None:
        """Idempotent post-registration normalization, called on every
        _load_application hit for a CIMD app: attach the Domain and (if the
        domain wants it) the auto-generated lockdown permission."""
        domain = None
        if application.domain_id is None:
            domain = _domain_for_oauthlib_request(request)
            if domain is None:
                # Permission checks should make this unreachable; never
                # break the OAuth flow from here.
                _log.warning("CIMD app %s has no resolvable domain", application.client_id)
            else:
                application.domain = domain
                application.save(update_fields=["domain"])

        if domain is None and application.domain_id is not None:
            domain = application.domain
        if domain is None or not domain.cimd_auto_permissions:
            return

        permission_name = auto_permission_name(application.client_id)
        permission, _created = MNApplicationPermission.objects.get_or_create(
            permission_name=permission_name,
            defaults={"name": "CIMD client: %s" % application.client_id[:200]},
        )
        if not application.required_permissions.filter(pk=permission.pk).exists():
            application.required_permissions.add(permission)

**(c) Hook into the validator (``authserver/mailauth/oauth2.py``), add to
``ClientPermissionValidator``:**

.. code-block:: python

    def _load_application(self, client_id, request):
        application = super()._load_application(client_id, request)
        if (
            application is not None
            and application.registration_source == application.RegistrationSource.CIMD
        ):
            from mailauth.cimd import ensure_cimd_application_defaults
            ensure_cimd_application_defaults(application, request)
        return application

(Idempotent by construction; runs on every authorize/token request that
loads a CIMD client, which also self-heals rows if flags change later.)

**(d) Settings:**

.. code-block:: python

    'CIMD_ENABLED': True,
    # policy lives on the Domain model (cimd_enabled/cimd_client_hosts),
    # see mailauth/cimd.py
    'CIMD_REGISTRATION_PERMISSION_CLASSES': ('mailauth.cimd.DomainCIMDPermission',),

Do **not** set ``CIMD_ALLOWED_HOSTS`` — that global belongs to the upstream
``HostAllowlistCIMDPermission`` which we replace with the per-domain policy.

**(e) Tests — new ``authserver/mailauth/tests/test_cimd.py``.**

Never fetch the network: override the fetcher. Define a stub in the test
module::

    class StubFetcher:
        documents = {}   # client_id -> metadata dict, filled per-test

        def fetch(self, client_id):
            from oauth2_provider.cimd import CIMDError
            if client_id not in self.documents:
                raise CIMDError("not found")
            return self.documents[client_id], 300

and activate with
``@override_settings(OAUTH2_PROVIDER={... 'CIMD_METADATA_FETCHER':
'mailauth.tests.test_cimd.StubFetcher', ...})`` — when overriding
``OAUTH2_PROVIDER`` you must repeat the whole dict from settings (DOT's
settings object rebuilds itself on the ``setting_changed`` signal). A valid
metadata document must contain ``client_id`` equal to the URL (upstream
verifies this), e.g.::

    CLIENT_ID = "https://mcp.client.example/oauth-client"
    StubFetcher.documents[CLIENT_ID] = {
        "client_id": CLIENT_ID,
        "client_name": "Stub MCP client",
        "redirect_uris": ["https://mcp.client.example/callback"],
        "grant_types": ["authorization_code"],
        "token_endpoint_auth_method": "none",
    }

Also clear the failure-backoff between tests
(``from django.core.cache import cache; cache.clear()`` in ``setUp``),
otherwise a failed resolution in one test suppresses resolution in the next
for ``CIMD_FAILURE_BACKOFF_SECONDS``.

Cases (drive everything through ``self.client.get('/o2/authorize/', {...
'client_id': CLIENT_ID ...}, secure=True)`` with a logged-in user, PKCE
params as in ``test_oauth2_oidc.py``):

1. ``cimd_enabled=False`` → error page ("Invalid client_id" / 400 family
   response from the authorize view), **no** ``MNApplication`` row created.
2. ``cimd_enabled=True`` but ``cimd_client_hosts=[]`` → same as (1):
   fail-closed allowlist.
3. ``cimd_client_hosts=["other.example"]`` (non-matching) → same as (1).
4. ``cimd_client_hosts=[".client.example"]`` → application created with
   ``registration_source="cimd"``, ``domain`` set, auto-permission created
   with ``auto_permission_name(CLIENT_ID)``, attached to
   ``required_permissions``, assigned to no user; the authorize response is
   the ``unauthorized.html`` rendering (user lacks the permission).
5. Assign the permission to the test user (``user.app_permissions.add``) →
   authorize now 302s with a code; complete the token exchange incl. RS256
   ID-token verification (client is public + PKCE — no client_secret).
6. ``cimd_auto_permissions=False`` on the domain → app created with empty
   ``required_permissions`` and the flow works immediately.
7. Wildcard ``["*"]`` allows an arbitrary host.
8. Idempotency: hit authorize twice; exactly one permission row, one M2M
   link.

4.4 Acceptance criteria
~~~~~~~~~~~~~~~~~~~~~~~

* All new tests plus the whole existing suite pass.
* A Domain with ``cimd_enabled=False`` (the default, i.e. every existing
  domain after migration) behaves exactly as before the change.
* The Django admin shows the three new Domain fields.
* No CIMD application can complete an authorize flow before an admin
  assigns its auto-generated permission (when ``cimd_auto_permissions``).


5. Feature 3: RFC 9207 ``iss`` authorization-response parameter
---------------------------------------------------------------

5.1 Where ``iss`` exists in the codebase today (inventory)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

This is why grepping for ``iss`` finds little — four distinct things share
the name:

1. **ID-token ``iss`` claim** — set by DOT's ``finalize_id_token`` to
   ``oidc_issuer(request)`` = ``https://<host>/o2``. Note: the ``"iss":
   request.client.domain.name`` entry in
   ``ClientPermissionValidator.get_additional_claims`` is **overwritten** by
   DOT for ID tokens (DOT applies its required claims after the additional
   ones); it only surfaces in the **userinfo endpoint** output. Not touched
   by this plan.
2. **``checkpassword`` / ``UserLoginAPIView`` JWT** ``iss`` =
   ``Domain.name`` — a custom, non-OIDC API. Not touched.
3. **dockerauth JWTs** — unrelated. Not touched.
4. **RFC 9207 authorization-response ``iss`` query/fragment parameter** —
   does not exist anywhere in authserver today. This plan adds it.

5.2 What the DOT 4.0 default flip would do if we change nothing
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Upstream plans to flip ``COMPLIANT_BCP_RFC9700_AUTHZ_RESPONSE_ISS`` to True
in 4.0. The single upstream call site is
``OAuthLibCore.create_authorization_response``
(``oauth2_provider/oauth2_backends.py``, the block guarded by the gate): it
appends ``iss = oauth2_settings.oauth2_authorization_server_issuer(request)``
to the redirect. That helper resolves, in order:

1. ``OIDC_ISS_ENDPOINT`` — authserver leaves it empty (it is a static
   value; our issuers are per-Host).
2. ``reverse("oauth2_provider:oauth-server-metadata")`` — **fails** in
   authserver: the RFC 8414 routes added in the 3.4.0 upgrade live at the
   URL-root *outside* the ``oauth2_provider`` namespace (deliberately, so
   the namespace's endpoint reversal used by the discovery documents keeps
   working). And even where it resolves, upstream derives the issuer from
   the *root* metadata URL, which strips the ``/o2`` path.
3. Fallback: ``request.build_absolute_uri("/").rstrip("/")`` →
   ``https://<host>``.

Result with the flipped default: every authorization redirect gains
``iss=https://<host>`` — the **wrong** issuer (ours is
``https://<host>/o2``).

Compatibility matrix of that unmodified behavior:

* Clients that do not implement RFC 9207 (all current downstream clients):
  **unaffected** — RFC 6749 §4.1.2/§8.2 obliges clients to ignore
  unrecognized response parameters. The parameter is additive.
* Clients that do implement RFC 9207: they compare the received ``iss``
  against the issuer from their configuration/discovery
  (``https://<host>/o2``) → mismatch → they **abort the flow** (it looks
  like a mix-up attack). This is the breakage to prevent.

5.3 Planned change
~~~~~~~~~~~~~~~~~~

Strategy (confirmed with Jonas): pin the upstream gate **explicitly off**
and emit the parameter ourselves with the issuer authserver actually uses.

**(a) Settings — add to ``OAUTH2_PROVIDER``:**

.. code-block:: python

    # RFC 9207: we emit the `iss` authorization-response parameter ourselves
    # (see mailauth/oauth2_backends.py) because upstream's issuer derivation
    # cannot produce our per-host 'https://<host>/o2' issuers. Pinned False so
    # the django-oauth-toolkit 4.0 default flip cannot turn on the upstream
    # emission (which would produce a mismatching 'https://<host>' issuer and
    # break RFC 9207-validating clients). Do not remove without reading
    # .agent-docs/dcr-cimd-authz-iss/implementation-plan.rst section 5.
    'COMPLIANT_BCP_RFC9700_AUTHZ_RESPONSE_ISS': False,

**(b) New module ``authserver/mailauth/oauth2_backends.py``:**

.. code-block:: python

    """Custom OAuthLib request/response glue for authserver."""
    from oauth2_provider.oauth2_backends import OAuthLibCore, _add_iss_to_redirect
    from oauth2_provider.settings import oauth2_settings


    class MNOAuthLibCore(OAuthLibCore):
        """
        Adds the RFC 9207 `iss` parameter to successful authorization
        responses using the same per-request issuer that the OIDC discovery
        document advertises (https://<host>/o2). Upstream's implementation
        (gated by COMPLIANT_BCP_RFC9700_AUTHZ_RESPONSE_ISS, pinned False in
        settings) cannot derive path-component multi-tenant issuers.
        """

        def create_authorization_response(self, request, scopes, credentials, allow):
            uri, headers, body, status = super().create_authorization_response(
                request, scopes, credentials, allow
            )
            if uri is not None:
                issuer = oauth2_settings.oidc_issuer(request)
                uri = _add_iss_to_redirect(uri, issuer)
                headers["Location"] = uri
            return uri, headers, body, status

  Facts making this correct:

  - ``request`` here is the Django ``HttpRequest`` (the authorize view
    passes ``self.request``); ``oidc_issuer()`` accepts it and derives
    ``https://<host>/o2`` from the ``oidc-connect-discovery-info`` route —
    byte-identical to the ``issuer`` in both discovery documents.
  - ``_add_iss_to_redirect`` handles both response modes: it appends to the
    **fragment** for implicit/hybrid responses and to the **query**
    otherwise, and strips any pre-existing ``iss`` from both components
    first (RFC 9207 requires a single unambiguous value). If importing the
    underscore helper is unpalatable, copy its 15 lines into this module
    with an attribution comment.
  - Exceptions raised before ``super()`` returns (denied consent, fatal
    client errors) propagate unchanged — those paths return no redirect URI
    from this method.

**(c) Settings — activate the backend:**

.. code-block:: python

    'OAUTH2_BACKEND_CLASS': 'mailauth.oauth2_backends.MNOAuthLibCore',

**(d) Advertise support in both discovery documents.** Upstream only sets
``authorization_response_iss_parameter_supported`` when its gate is on, so
wrap the two views (in ``authserver/mailauth/views.py``):

.. code-block:: python

    class IssAdvertisingDiscoveryMixin:
        def get(self, request, *args, **kwargs):
            response = super().get(request, *args, **kwargs)
            if response.status_code == 200:
                data = json.loads(response.content)
                data["authorization_response_iss_parameter_supported"] = True
                new_response = JsonResponse(data)
                new_response["Access-Control-Allow-Origin"] = "*"
                return new_response
            return response


    class MNConnectDiscoveryInfoView(IssAdvertisingDiscoveryMixin, oidc_views.ConnectDiscoveryInfoView):
        pass


    class MNOAuthServerMetadataView(IssAdvertisingDiscoveryMixin, oauth2_views.OAuthServerMetadataView):
        pass

and swap these classes into ``authserver/authserver/urls.py`` in place of
the upstream ``ConnectDiscoveryInfoView`` and ``OAuthServerMetadataView``
(three mounts: ``o2/.well-known/openid-configuration`` plus the two
root-level ``oauth-authorization-server`` routes).

**(e) Deliberately out of scope (document in the commit):** RFC 9207 §2
also wants ``iss`` on *error* redirects. Upstream does not implement that
either (verified: ``_add_iss_to_redirect`` has exactly one call site, in the
success path). Error redirects flow through
``AuthorizationView.error_response`` / ``OAuth2ResponseRedirect``; adding
``iss`` there is a follow-up that should be done when/if upstream does it,
to avoid diverging.

5.4 What the planned change achieves
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

* Successful authorization redirects carry
  ``iss=https://<host>/o2`` (URL-encoded), matching the ``issuer`` of both
  discovery documents for that host.
* Legacy clients: behavior is byte-identical except for one additional
  parameter they must ignore per RFC 6749. **No configuration change needed
  downstream.**
* RFC 9207-capable clients: the mix-up defense works, and the
  ``..._supported`` metadata flag tells them to expect/require the
  parameter.
* The DOT 4.0 default flip becomes a **no-op** for authserver (gate pinned
  False; our backend owns the emission). Conversely: if someone later
  removes ``MNOAuthLibCore`` they must re-evaluate the gate — hence the
  settings comment in (a).

5.5 Tests — new ``authserver/mailauth/tests/test_authz_response_iss.py``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Reuse the ``test_oauth2_oidc.py`` setup. Cases:

1. Authorize redirect contains ``iss=https%3A%2F%2Ftestserver%2Fo2``
   exactly once, in the **query** for ``response_type=code``
   (``parse_qs(urlsplit(response.url).query)["iss"] ==
   ["https://testserver/o2"]``).
2. The full code flow still completes after the parameter is appended
   (state and code parameters intact).
3. A redirect URI that itself contains an ``iss`` query parameter is
   registered for the app → the response contains only the server's value.
4. Both discovery documents contain
   ``"authorization_response_iss_parameter_supported": true``.
5. Guard test: assert
   ``oauth2_settings.COMPLIANT_BCP_RFC9700_AUTHZ_RESPONSE_ISS is False`` —
   this test fails loudly if a future DOT upgrade or settings edit turns
   the upstream emission on alongside ours (which would still yield a
   single, correct ``iss`` thanks to the strip-then-append helper, but
   means duplicated intent that should be resolved consciously).

5.6 Acceptance criteria
~~~~~~~~~~~~~~~~~~~~~~~

* All new tests plus the whole existing suite pass (in particular the
  existing ``test_oauth2_oidc.py`` flow tests, which prove legacy-client
  compatibility since they ignore the new parameter).
* ``check --deploy`` still shows W005 (that warning keys off the gate being
  False; it is expected and documented — our emission satisfies the intent).


6. Rollout order and branch strategy
------------------------------------

All three features are independent of each other; none may land before the
3.4.0 upgrade branch. Suggested order (smallest blast radius first):

1. **Feature 3 (iss)** — no schema change, two small modules, immediate
   value, provable compatibility.
2. **Feature 1 (DCR)** — no schema change; adds endpoints that are
   token-gated.
3. **Feature 2 (CIMD)** — one migration, the validator hook, and the most
   policy surface.

One branch per feature (``feature/authz-response-iss``, ``feature/dcr``,
``feature/cimd``) forked off ``develop``, or a single stacked branch if
Jonas prefers one review. Each lands with its tests; run the full suite
(``authserver.tests mailauth.tests``) before pushing. Update
``.agent-docs/dcr-cimd-authz-iss/`` with a DONE note per feature when
merged (pattern: ``.agent-docs/management-extensions/DONE.rst``).
