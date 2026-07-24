django-oauth-toolkit 3.3.0 → 3.4.0 upgrade
==========================================

:Date: 2026-07-24
:Branch: ``update/django-oauth-toolkit-3.4.0``
:Release notes: https://github.com/django-oauth/django-oauth-toolkit/releases/tag/3.4.0

Summary
-------

django-oauth-toolkit (DOT) 3.4.0 is a large feature release centered on making DOT a
usable authorization server for the Model Context Protocol (MCP): RFC 8414 authorization
server metadata, RFC 9728 protected resource metadata, RFC 7591/7592 Dynamic Client
Registration (DCR), Client ID Metadata Documents (CIMD), RFC 8707 resource indicators,
and a set of RFC 9700 (OAuth 2.0 Security BCP) compliance gates. It also reworks how
refresh tokens are stored/looked up and how HS256 ID-token signing works.

The upgrade was verified by diffing the installed 3.3.0 and 3.4.0 packages (not just the
release notes). authserver needed four changes, listed under `Changes made`_.

Impact analysis
---------------

Swapped application model (``mailauth.MNApplication``)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

``AbstractApplication`` changed in 3.4.0:

- ``client_id`` widened from ``max_length=100`` to ``max_length=255`` (so a CIMD URL can
  be a client_id),
- new field ``registration_source`` (CharField, choices ``manual``/``dcr``/``cimd``,
  default ``manual``),
- new field ``cimd_expires_at`` (nullable DateTimeField),
- ``client_secret`` help text changed.

DOT's own migrations (``0017``/``0019``/``0020``) explicitly *skip* swapped-out
application models, so ``mailauth`` has to mirror them. This is done by the new
generated migration ``mailauth/migrations/0029_mnapplication_cimd_expires_at_and_more.py``.
Nothing else about the swap changed; ``OAUTH2_PROVIDER_APPLICATION_MODEL`` keeps working
as before.

Refresh tokens: checksum-based lookup
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

``AbstractRefreshToken`` gained a ``token_checksum`` field (SHA-256 of the token), the
``token`` column became a ``TextField``, and the uniqueness constraint moved from
``(token, revoked)`` to ``(token_checksum, revoked)``. The base
``OAuth2Validator.validate_refresh_token`` now looks tokens up by checksum, preferring
the unrevoked row and falling back to the most recently revoked one.

authserver does **not** swap the token models, so DOT's migrations ``0015``–``0018``
apply as-is (including a data migration backfilling checksums for existing rows — this
runs automatically on ``manage.py migrate`` during deployment).

``mailauth.oauth2.ClientPermissionValidator.validate_refresh_token`` contained a
diagnostic fallback that queried ``RefreshToken.objects.filter(token=...)``. That would
keep working while tokens are stored in plaintext, but is no longer how rows are keyed
(several rows may share a token value now, and the token column is blank when the RFC
9700 hashed-at-rest storage gate is ever enabled). It was updated to mirror the base
class' checksum lookup.

HS256 signing changes: **not applicable**
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

3.4.0 fixes HS256 ID-token signing (previously tokens were signed with the *hashed*
client secret, which relying parties could never verify). ``Application.clean()`` and
``jwk_key`` now raise for HS256 apps whose secret is hashed or empty;
``hash_client_secret=False`` is required for HS256.

authserver is unaffected: ``MNApplication.algorithm`` is a property hard-coded to
``RS256_ALGORITHM`` (the field was removed in mailauth migration ``0018``), and
``MNApplication.jwk_key`` is overridden to sign with the per-``Domain`` JWT key. No
HS256 application can exist. The new HS256 branches in ``clean()``/``jwk_key`` are
unreachable, and the RS256 branch of ``clean()`` only checks that
``OIDC_RSA_PRIVATE_KEY`` is truthy — the ``'<unused>'`` placeholder in ``settings.py``
still satisfies it (the actual key comes from the ``Domain`` model via the ``jwk_key``
override, same as before).

The upstream advice "recreate secrets with plaintext storage" therefore does **not**
apply to this deployment.

Admin
~~~~~

``MNApplicationAdmin`` inherits from DOT's ``ApplicationAdmin``, which changed in
3.4.0:

- uses the new ``ApplicationForm`` (adds live help text for ``hash_client_secret``;
  its HS256 wiring skips gracefully because MNApplication has no ``algorithm`` form
  field),
- ``list_display``/``list_filter`` now include ``registration_source`` and
  ``registration_source``/``cimd_expires_at`` are readonly — this requires migration
  ``0029`` (present) and otherwise works unchanged,
- the token/grant admins now mask credentials in list views, disallow manual creation,
  and search by client/user identifiers instead of by raw token — a security
  improvement inherited automatically.

Authorization endpoint (``ScopeValidationAuthView``)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

``AuthorizationView`` changes are additive: ``prompt`` is now parsed as a
space-delimited set, ``prompt=create`` support exists but returns HTTP 400 unless
``OIDC_RP_INITIATED_REGISTRATION_ENABLED`` is turned on (default off), and RFC 8707
``resource`` parameters are validated and threaded through the flow. ``AllowForm``
gained a hidden ``resource`` field; the ``authorize.html`` override renders hidden
fields generically, so no template change is needed. The 3.4.0 fix for the
unauthenticated open redirect with ``prompt=none`` is inherited automatically.

URLs / new well-known endpoints
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

authserver assembles its ``oauth2_provider`` URL namespace manually in
``authserver/urls.py``, so none of the new 3.4.0 routes appeared automatically. What
was added:

- **RFC 8414 authorization server metadata** (``OAuthServerMetadataView``), mounted at
  the server root as the RFC requires:

  - ``/.well-known/oauth-authorization-server/o2`` — the *path-component form*. This is
    the authoritative document for our issuer ``https://<host>/o2`` (the issuer OIDC
    discovery advertises); the view derives the issuer from the URL suffix, and MCP
    clients resolve issuers with path components through exactly this form.
  - ``/.well-known/oauth-authorization-server`` — the plain root form (issuer
    ``https://<host>``) for clients that do not implement issuer-path handling.

  The view builds its endpoint list by reversing names in the ``oauth2_provider``
  namespace; ``authorize``, ``token``, ``revoke-token`` and ``jwks-info`` are all
  mounted, so the document is complete. ``introspect`` is not mounted and is correctly
  omitted. Verified in ``mailauth/tests/test_oauth2_oidc.py`` that the path-component
  document agrees with ``/o2/.well-known/openid-configuration``.

Deliberately **not** mounted:

- *RFC 9728 protected resource metadata* — authserver is the authorization server, not
  an OAuth2-protected resource; resource servers (e.g. an MCP server using authserver)
  publish their own document.
- *DCR endpoints* (``/register/``) and *CIMD* — both features are default-disabled in
  settings (``DCR_ENABLED``/``CIMD_ENABLED`` False) and unwanted here: applications are
  provisioned manually/via management commands, and ``required_permissions`` gating
  assumes curated clients. Not mounting them is defense in depth.

RFC 9700 compliance gates
~~~~~~~~~~~~~~~~~~~~~~~~~

All new ``COMPLIANT_BCP_RFC9700_*`` settings default to ``False`` = 3.3.0 behavior.
``manage.py check --deploy`` now emits warnings W001–W008 (implicit grant enabled,
password grant enabled, PKCE ``plain`` accepted, tokens in query string, no ``iss``
response parameter, plaintext token storage, no refresh-token reuse protection, http
redirect URIs allowed). These are informational; nothing changes at runtime.

Upstream plans to flip all defaults to ``True`` in DOT 4.0. See `Recommended
follow-ups`_.

Other verified-unaffected areas
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

- ``MNAuthScopes`` (``SCOPES_BACKEND_CLASS``): ``BaseScopes`` interface unchanged; now
  additionally feeds ``scopes_supported`` in the RFC 8414 document.
- ``check_pkce_required`` callable for ``PKCE_REQUIRED``: unchanged, still honored (a
  callable also suppresses the W010 config check).
- Device grant model changes (``scope`` → TextField etc.): device flow is not used and
  its endpoints are not mounted; migrations apply cleanly anyway.
- ``get_additional_claims``/``get_userinfo_claims``: interface unchanged.
  ``finalize_id_token`` now normalizes naive ``last_login`` values for ``auth_time`` —
  no impact (``USE_TZ = True``).
- Management commands (``oauth2``, ``dockerauth`` etc.): client creation verified
  working. Note: ``oauth2 list --search-client-name`` crashes with an
  ``AttributeError`` — a **pre-existing** typo (``objects.file`` instead of
  ``objects.filter`` in ``_list()``), unrelated to this upgrade.
- Templates: only ``authorize.html``/``unauthorized.html``/``base.html`` are
  overridden; upstream template changes (application form JS) don't affect them.
- ``oauthlib`` requirement is ``>=3.3.0`` — already satisfied (3.3.1 resolves).

Changes made
------------

1. ``requirements.txt`` — ``django-oauth-toolkit==3.4.0``.
2. ``authserver/mailauth/migrations/0029_mnapplication_cimd_expires_at_and_more.py`` —
   new fields ``registration_source``/``cimd_expires_at``, ``client_id`` widened to
   255 chars, ``client_secret`` help text (mirrors DOT's skipped-for-swapped-models
   migrations 0019/0020).
3. ``authserver/mailauth/oauth2.py`` — refresh-token rejection diagnostics now look up
   rows by SHA-256 ``token_checksum`` (mirrors the 3.4.0 base validator).
4. ``authserver/authserver/urls.py`` — RFC 8414 metadata endpoints mounted at the
   server root (plain + path-component form).
5. ``authserver/mailauth/tests/test_oauth2_oidc.py`` — new end-to-end tests:
   authorization-code + PKCE flow, RS256 ID-token signature verification against the
   ``Domain`` JWT key, refresh-token redemption + checksum storage, refresh rejection on
   permission revocation, RFC 8414/OIDC discovery consistency.

Validation performed
--------------------

- ``manage.py migrate`` against the ``authtest`` PostgreSQL database: all
  ``oauth2_provider`` 0015–0020 and ``mailauth`` 0029 migrations apply cleanly.
- ``manage.py check``: no issues. ``check --deploy``: only the expected new RFC 9700
  warnings (see above).
- Full test suite (``authserver.tests`` + ``mailauth.tests``): 45 tests pass
  (39 pre-existing + 6 new).
- Smoke tests: discovery documents served and consistent; ``oauth2 create`` management
  command creates clients with the new model fields.

Note: the ``authtest`` role has no ``CREATEDB`` privilege, so the suite was run with a
settings wrapper that sets ``DATABASES["default"]["TEST"]["NAME"] = "authtest"`` plus
``--keepdb``. CI (GitHub Actions) is unaffected — its role has ``CREATEDB``.

Recommended follow-ups (not done here)
--------------------------------------

- **Before DOT 4.0**: decide on the RFC 9700 gates. Reasonable early adoptions for this
  deployment: ``COMPLIANT_BCP_RFC9700_PKCE_METHOD`` (reject PKCE ``plain``; all known
  clients use S256) and ``COMPLIANT_BCP_RFC9700_ACCESS_TOKEN_TRANSPORT`` (reject tokens
  in query strings). ``REFRESH_TOKEN_REUSE_PROTECTION = True`` (W007) is worth
  considering but changes client-visible rotation semantics — test with real clients
  first. ``COMPLIANT_BCP_RFC9700_AUTHZ_RESPONSE_ISS`` requires care: with per-host
  issuers, the derived ``iss`` value would be ``https://<host>`` and not match the
  advertised issuer ``https://<host>/o2`` (DOT derives it from the root metadata URL);
  don't enable it without setting ``OIDC_ISS_ENDPOINT`` or accepting the mismatch.
- Optionally set ``OAUTH2_GRANT_TYPES_SUPPORTED``/``OAUTH2_RESPONSE_TYPES_SUPPORTED``
  so the RFC 8414 document stops advertising the device-code grant (endpoint not
  mounted).
- Fix the pre-existing ``oauth2 list --search-client-name`` typo
  (``objects.file`` → ``objects.filter``; both search branches also use the invalid
  ``__ilike`` lookup — should be ``__icontains``).
- Bump ``types-oauthlib`` when a 3.4.x stub release appears.
