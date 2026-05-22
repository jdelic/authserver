EmailAgentAuthToken Reference
=============================

Purpose
-------

``EmailAgentAuthToken`` is a one-time credential for external email agents that
need to hand off outbound mail through authserver-integrated components such as
an OpenSMTPD filter.

Token lifecycle
---------------

Creation
++++++++

Tokens can be created in two places:

* the self-service dashboard's "Email Agent Tokens" tab
* Django admin via ``EmailAgentAuthToken``

Issued tokens currently have these properties:

* token value: 32 lowercase hexadecimal characters
* ``token_hint``: the first 12 characters of the token
* ``creator``: the owning ``MNUser``
* ``created_at``: issuance timestamp
* ``burned``: ``False`` initially
* ``used_at``: ``NULL`` initially

The full active token is visible in the self-service dashboard for easy
copy/paste until it is burned.

Validation and burn-on-use
++++++++++++++++++++++++++

Validation is single-use:

* the submitted plaintext token is SHA-256 hashed and looked up by
  ``token_digest``
* the matching row is locked with ``SELECT ... FOR UPDATE``
* if the token does not exist, is empty, or is already burned, validation fails
* on success, the token is burned atomically and ``used_at`` is set

Manual burn
+++++++++++

Users can burn their own tokens from the self-service dashboard.
Admins can burn tokens from Django admin, including bulk actions.

Operational rule
++++++++++++++++

Once a token has been successfully validated or manually burned, it must be
treated as permanently invalid. Reuse is expected to return ``401`` with
``{"valid": false}``.

HTTP API reference
------------------

Endpoint
++++++++

``POST /email-agent-auth-tokens/validate/``

URL name in Django: ``email-agent-auth-token-validate``

Security and transport requirements
+++++++++++++++++++++++++++++++++++

* HTTPS is required. Non-secure requests return ``400`` with:

  .. code-block:: json

     {"error": "This endpoint must be called securely"}

* CSRF protection is exempted because this endpoint is for machine-to-machine
  callers.
* Requests are rate limited by source IP to ``60/m`` for ``POST``.

Accepted request formats
++++++++++++++++++++++++

JSON request:

.. code-block:: http

   POST /email-agent-auth-tokens/validate/
   Content-Type: application/json

   {"token": "9f4c0e7626bc1f4098e31c39c51f0b0d"}

Form-encoded request:

.. code-block:: http

   POST /email-agent-auth-tokens/validate/
   Content-Type: application/x-www-form-urlencoded

   token=9f4c0e7626bc1f4098e31c39c51f0b0d

The server strips surrounding whitespace from the submitted token before
validation.

Successful response
+++++++++++++++++++

Status: ``200 OK``

.. code-block:: json

   {
     "valid": true,
     "burned": true,
     "creator": {
       "identifier": "alice",
       "uuid": "927ced5e-0460-4345-bb60-d3e9462f3922",
       "primary_email": "alice@example.com"
     },
     "token_hint": "9f4c0e7626bc",
     "used_at": "2026-05-21T22:35:00+00:00"
   }

Response fields
+++++++++++++++

``valid``
  ``true`` when the token was accepted.

``burned``
  Always ``true`` on success because the endpoint consumes the token.

``creator.identifier``
  The authserver user identifier for the token owner.

``creator.uuid``
  Stable UUID for the token owner.

``creator.primary_email``
  Delivery mailbox address for the owner if one exists, otherwise ``null``.

``token_hint``
  First 12 characters of the token, useful for logs and UI correlation without
  depending on the full token string.

``used_at``
  ISO-8601 timestamp of successful validation/burn.

Failure responses
+++++++++++++++++

Invalid, unknown, reused, or already-burned token:

* status: ``401 Unauthorized``
* body:

  .. code-block:: json

     {"valid": false}

Malformed JSON:

* status: ``400 Bad Request``
* body:

  .. code-block:: json

     {"error": "Invalid JSON"}

Missing or non-string ``token`` parameter:

* status: ``400 Bad Request``
* body:

  .. code-block:: json

     {"error": "Missing or invalid parameters"}

OpenSMTPD filter integration notes
----------------------------------

Recommended usage pattern
+++++++++++++++++++++++++

1. Obtain a token out-of-band from the dashboard or admin.
2. Submit that token exactly once to
   ``/email-agent-auth-tokens/validate/`` over HTTPS.
3. If the response is ``200``, trust the returned ``creator`` metadata for the
   current handoff and discard the token immediately.
4. If the response is ``401``, treat the token as unusable and require a new
   token to be issued.
5. Do not retry a token after a successful validation response; success means it
   has already been burned.

Minimal JSON example
++++++++++++++++++++

.. code-block:: shell

   curl -X POST \
     -H 'Content-Type: application/json' \
     --data '{"token":"9f4c0e7626bc1f4098e31c39c51f0b0d"}' \
     https://auth.example.com/email-agent-auth-tokens/validate/

Implementation pointers
+++++++++++++++++++++++

Relevant code for maintainers:

* model issuance and burn logic:
  ``authserver/mailauth/models.py`` ``EmailAgentAuthTokenManager``
* validation HTTP view:
  ``authserver/mailauth/views.py`` ``EmailAgentAuthTokenValidationAPIView``
* self-service token UI:
  ``authserver/authserver/selfservice_views.py`` and
  ``authserver/authserver/templates/selfservice/dashboard.html``
