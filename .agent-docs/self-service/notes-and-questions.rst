Self-Service Frontend Notes and Open Questions
==============================================

Implementation Notes
--------------------

Current browser behavior
++++++++++++++++++++++++

* ``/`` currently returns ``nothing to see here``.
* The current login form only accepts ``type="email"``, which blocks browser
  entry of staff identifiers and service-user usernames even though the backend
  authenticator supports them.

**Operator note:** Staff identifiers should be allowed. Service users MUST NOT
be accepted as logins into the self-service portal.

Existing auth behavior that matters
+++++++++++++++++++++++++++++++++++

* "Admin flag" most likely maps to Django ``is_staff`` because that is what
  grants admin-site access and what the auth backend already special-cases for
  identifier login.
* Service-user login currently authenticates as the backing ``MNUser``.
  That means a service-user credential could reach the self-service dashboard
  unless the new browser login flow explicitly rejects it.

**Operator note:** see above.

Alias and mailing-list model constraints
++++++++++++++++++++++++++++++++++++++++

* ``EmailAlias.blacklisted`` is already the correct implementation for
  blocking an alias.
* ``EmailAlias`` cannot point to both a user and a mailing list.
* A "mailing list alias" in the current schema is not a secondary feature on a
  user alias. It is a different target type.
* ``MailingList.addresses`` already supports arbitrary recipient addresses.

**Operator notes:** While mailing lists are just email aliases on the backend,
it's fine to separate them in the dashboard as two separate entities to make
it easier to understand for the user.

Service-user behavior
+++++++++++++++++++++

* ``MNServiceUser`` usernames are currently free-form up to 64 characters.
  The admin form defaults to UUID4 usernames.
* Password plaintext is not stored, so the dashboard can only show the
  generated password at creation or explicit rotation time.

**Operator note:** Service users can only be created and deleted, never edited.

SPAPI notes
+++++++++++

* ``authserver_get_credentials(varchar)`` currently expects an email address
  and returns ``(username, password, primary_alias)`` for a real user mailbox.
* Browser login already supports service users through Django auth, so the
  ``spapi`` work is only needed for database clients such as Dovecot/OpenSMTPD.
* Compatibility risk is in downstream expectations, not in the Python auth
  backend.

**Operator note:** Just to be specific: it returns the password hash, not the
password.

Decisions Needed From You
-------------------------

1. Admin criterion
++++++++++++++++++

Please confirm whether "admin flag" means:

* ``is_staff`` (recommended, matches Django admin), or
* ``is_superuser`` only.

**Operator note:** `is_staff` is good.

2. Tailwind asset strategy
++++++++++++++++++++++++++

Please choose one of these:

* vendored/compiled Tailwind CSS committed into ``static`` and served locally
* Tailwind Play CDN for the first pass

I recommend a local static asset for production, but that may require adding a
build step or committing the compiled CSS artifact.

**Operator note:** You can use `npx` on this machine to run tailwindcss/cli.
You must add the necessary downloads to the CI pipielines in `.github` (GitHub
Actions) for linting and `.ci` (Concourse-CI) for building. It might be worth
it to switch the whole project to `pyproject.toml` from `setup.py` so as to
integrate tailwind's CLI more seamlessly?

3. Alias creation scope
+++++++++++++++++++++++

When a user creates a new alias, which domains should they be allowed to use?

Options to choose between:

* any domain where they already own at least one alias
* only the domain of their primary delivery mailbox
* an explicit allowlist you want me to derive some other way

The current schema has no direct per-user domain ownership model.

**Operator note:** Any registered domain is fair game for v1.


4. Mailing-list conversion semantics
++++++++++++++++++++++++++++++++++++

When a user turns an alias into a mailing list, should the first pass:

* replace the user-owned alias with a mailing-list alias on the same address
* allow converting it back later
* permit external recipient addresses

The current model supports external addresses and replacement on the same
address, but the product behavior should be explicit.

**Operator note:** There should be a button "convert to mailing list" and on
mailing lists there should be a button "convert to user alias".


5. Self-service login policy for service users
++++++++++++++++++++++++++++++++++++++++++++++

Should service-user credentials be allowed to log into the self-service web UI?

Current backend behavior says yes because they authenticate as the backing
user. My default recommendation is:

* allow staff identifier login
* allow regular-user mailbox login
* reject service-user logins in the browser UI unless you explicitly want them

**Operator note:** Service users should never be able to log into the Admin
site for the self-service site. They are only allowed through SPAPI, checkpassword,
and OAuth2/OpenIDC flows.


6. Service-user username policy
+++++++++++++++++++++++++++++++

For dashboard-created service users, should usernames be:

* autogenerated UUIDs
* autogenerated human-readable names
* user-specified

I can implement any of the three, but the UX and collision rules differ.

**Operator note:** Prefill a UUID, but allow editing.

7. Service-user password lifecycle
++++++++++++++++++++++++++++++++++

The requirement only asks for create/delete. Please confirm whether the first
pass should also include password rotation.

I can keep it out initially and still structure the views/templates so it can
be added cleanly later.

**Operator note:** No password rotation anywhere for v1.


8. SPAPI compatibility target
+++++++++++++++++++++++++++++

For stored-procedure auth support of service users, which behavior do you want?

* extend ``authserver_get_credentials`` to accept service usernames too
* add a new stored procedure for service-user credential lookup

My recommendation is additive if you want zero ambiguity for existing mail
consumers.

**Operator note:** The SPAPI can't be extended with new stored procedures given
how it is used from Dovecot and OpenSMTPD. So existing code must be extended.


