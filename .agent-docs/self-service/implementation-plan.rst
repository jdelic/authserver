Self-Service Frontend Implementation Plan
=========================================

Context
-------

The current project exposes browser-facing authentication only through:

* Django admin
* a small PureCSS-based login template
* OAuth2 authorization templates

The root URL currently returns plain text via ``authserver.base_views.nothing``.
There is no self-service dashboard for regular users.

Relevant existing model and auth behavior:

* ``EmailAlias`` belongs either to ``MNUser`` or ``MailingList``.
* ``EmailAlias.blacklisted`` already provides the "block alias" primitive.
* ``MNServiceUser`` already exists and authenticates as its backing
  ``MNUser``.
* ``MNUserAuthenticationBackend`` allows:

  * staff users to log in with ``MNUser.identifier``
  * regular users to log in with an email alias
  * service users to log in with the service username

* ``spapi`` currently only resolves credentials by delivery email address.

Goals
-----

Implement a mobile-friendly, server-rendered self-service frontend using Django
templates and standard views. No SPA and no API layer are needed.

Required browser behavior:

1. ``/`` shows the login page for anonymous users.
2. ``/`` shows the dashboard for authenticated non-admin users.
3. Authenticated admin users are redirected to Django admin.
4. The dashboard allows users to manage:

   * their email aliases
   * mailing-list behavior for aliases
   * their service users

5. The existing PureCSS layout is replaced with a Tailwind-based layout.
6. ``spapi`` is evaluated and extended for service-user support if the calling
   contract can be preserved safely.

Proposed Work Breakdown
-----------------------

Phase 1: Routing and Authentication Entry Points
++++++++++++++++++++++++++++++++++++++++++++++++

1. Replace ``base_views.nothing`` at ``/`` with a dedicated entry view:

   * anonymous: render login page
   * authenticated + ``is_staff``: redirect to ``/admin/``
   * authenticated + not staff: redirect/render dashboard

2. Replace the current login view wiring with a small custom subclass of
   ``django.contrib.auth.views.LoginView`` so we can:

   * redirect staff users to Django admin after login
   * redirect non-staff users to the dashboard
   * use a custom template/form presentation

3. Keep logout on standard Django auth views.

Phase 2: Shared Tailwind Layout
+++++++++++++++++++++++++++++++

1. Replace the current PureCSS ``registration/base.html`` layout with a new
   shared Tailwind-based base template.
2. Rework these existing browser templates to use the new layout:

   * ``registration/login.html``
   * ``oauth2_provider/base.html``
   * ``oauth2_provider/authorize.html``
   * ``oauth2_provider/unauthorized.html``

3. Add a dashboard template namespace, for example:

   * ``authserver/authserver/templates/selfservice/base.html``
   * ``authserver/authserver/templates/selfservice/dashboard.html``
   * partials/forms as needed

4. Ensure all pages are usable on mobile portrait widths without horizontal
   scrolling.

Phase 3: Self-Service Dashboard
+++++++++++++++++++++++++++++++

1. Add a dashboard view that loads:

   * user summary
   * the user's ``EmailAlias`` rows
   * the user's ``MNServiceUser`` rows

2. Present alias and service-user actions as standard Django forms and POST
   endpoints, not JavaScript APIs.
3. Use Django messages for success/error feedback.

Phase 4: Email Alias Workflows
++++++++++++++++++++++++++++++

1. Add alias list and action handling for the logged-in user only.
2. Implement alias workflows:

   * create alias
   * delete alias
   * block alias
   * unblock alias
   * convert alias to mailing list / manage mailing-list settings

3. Enforce model invariants server-side:

   * an alias cannot belong to both a user and a mailing list
   * an alias must belong to one of them

4. Mutating alias endpoints should be POST-only and CSRF-protected.

Phase 5: Mailing List Workflows
+++++++++++++++++++++++++++++++

1. Build a form flow for "set up alias as mailing list" around existing
   ``MailingList.addresses`` and ``MailingList.new_mailfrom`` fields.
2. Decide whether the first pass supports:

   * converting a user alias into a mailing-list alias
   * editing mailing-list recipients after conversion
   * converting the alias back to a user alias

3. Validate email addresses with Django form validation before save.

Phase 6: Service User Workflows
+++++++++++++++++++++++++++++++

1. Add service-user create and delete flows scoped to ``request.user``.
2. Creation should show the generated password exactly once after save.
3. The initial implementation can omit edit/rotate if not requested, but the
   create flow should be structured so password rotation can be added later.

Phase 7: Stored Procedure API Evaluation
++++++++++++++++++++++++++++++++++++++++

1. Review existing consumers of ``authserver_get_credentials(varchar)``.
2. Extend service-user support in the safest compatible way:

   * preferred: broaden credential lookup to also resolve service usernames
   * fallback: add a new function instead of changing existing semantics

3. Preserve current alias-based behavior for Dovecot/OpenSMTPD consumers.
4. Update command checks/tests if function signatures change.

Phase 8: Test Coverage
++++++++++++++++++++++

1. Extend ``authserver/authserver/tests/test_views.py`` for:

   * ``/`` anonymous login rendering
   * ``/`` redirect for staff users
   * ``/`` dashboard for logged-in regular users

2. Add view/form tests for:

   * alias creation, blocking, deletion
   * mailing-list setup validation
   * service-user creation/deletion
   * authorization boundaries between users

3. Add ``spapi`` tests or command-level assertions for service-user support if
   that work is implemented.

Likely Code Changes
-------------------

Primary areas expected to change:

* ``authserver/authserver/urls.py``
* ``authserver/authserver/base_views.py``
* ``authserver/authserver/views.py`` or a new self-service view module
* ``authserver/mailauth/forms.py`` or a new self-service form module
* ``authserver/authserver/templates/registration/*.html``
* ``authserver/authserver/templates/oauth2_provider/*.html``
* new ``authserver/authserver/templates/selfservice/*.html``
* ``authserver/mailauth/management/commands/spapi.py``
* relevant tests under ``authserver/authserver/tests`` and possibly
  ``authserver/mailauth/tests``

Design Constraints and Risks
----------------------------

* The login UI cannot remain email-only if staff identifier login must keep
  working; the current template uses ``type="email"``.
* ``MNServiceUser`` passwords are write-only. The UI can create or rotate them,
  but it cannot reveal existing passwords.
* ``EmailAlias`` has no explicit "owned domain" relation. Alias creation rules
  need a product decision.
* Converting a user alias into a mailing list changes delivery semantics and
  should be treated as a deliberate action.
* ``spapi`` currently assumes a mailbox-oriented lookup contract. Service-user
  support is possible, but only if downstream consumers accept non-email
  usernames or the function remains backward compatible.

Recommended Delivery Order
--------------------------

1. Root/login/dashboard routing
2. Shared Tailwind layout
3. Read-only dashboard data
4. Alias CRUD/block flows
5. Mailing-list setup flow
6. Service-user create/delete flow
7. ``spapi`` extension
8. Tests and cleanup
