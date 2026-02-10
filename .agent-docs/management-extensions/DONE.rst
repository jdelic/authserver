Management Extensions Progress
==============================

Status
------

Implemented on branch ``codex/management-extensions``.

Planning Documents
------------------

Committed and finalized:

* ``.agent-docs/management-extensions/implementation-plan.rst``
* ``.agent-docs/management-extensions/commands-and-subcommands.rst``

Implemented Command Work
------------------------

New command modules:

* ``authserver/mailauth/management/commands/emailalias.py``
  - Subcommands: ``list``, ``show``, ``create``, ``edit``, ``remove``,
    ``blacklist``, ``unblacklist``
  - Added selector support and ``-y/--yes`` confirmation bypass for mutating
    actions.

* ``authserver/mailauth/management/commands/mailinglist.py``
  - Subcommands: ``create``, ``list``, ``show``, ``edit``, ``remove``,
    ``add-address``, ``remove-address``, ``set-addresses``
  - Batch input support for addresses (including ``-`` stdin mode).

* ``authserver/mailauth/management/commands/user.py``
  - Subcommands: ``create``, ``list``, ``show``, ``edit``, ``activate``,
    ``deactivate``, ``set-delivery-mailbox``, ``remove``
  - Fixed runtime bug in activate/deactivate flow caused by an option-name
    collision.

* ``authserver/mailauth/management/commands/serviceuser.py``
  - Subcommands: ``create``, ``list``, ``show``, ``edit``, ``remove``

Shared helper module:

* ``authserver/mailauth/management/commands/_mgmt_helpers.py``
  - Common parsing/resolution/confirmation helpers.

Consistency Updates in Existing Commands
----------------------------------------

Standardized destructive confirmation style toward ``-y/--yes``:

* ``authserver/mailauth/management/commands/domain.py``
* ``authserver/dockerauth/management/commands/dockerauth.py``

Tests and CI
------------

Added tests:

* ``authserver/mailauth/tests/test_management_commands.py``

Updated CI flow:

* ``.github/workflows/django.yaml``
  - Expanded to run CRUD smoke operations (existing and new command families)
    on a fresh migrated database.
  - Updated smoke cleanup sequence to avoid protected-delete cycles on primary
    delivery-mailbox aliases.
  - Includes ``mailauth.tests`` in test invocation.

Validation Performed
--------------------

Local static/compile validation:

* ``python3 -m compileall`` run successfully on changed command/test modules.

Live dev-environment validation (sudo + /usr/local/authserver):

* Installed branch editable via
  ``sudo /usr/local/authserver/bin/pip install -e .``.
* Ran end-to-end smoke commands via
  ``sudo /usr/local/authserver/bin/envdir /etc/appconfig/authserver/env/ /usr/local/authserver/bin/django-admin ...``
  covering create/list/edit/remove paths and blacklist flows.
* Confirmed fixed ``user activate/deactivate`` behavior in live execution.

Known Environment Constraints Observed
--------------------------------------

* Running ``django-admin test`` in the provided dev environment failed because
  the configured DB role could not create test databases
  (``permission denied to create database``).
* Deleting aliases referenced by ``MNUser.delivery_mailbox`` is blocked by the
  existing ``PROTECT`` relationship; smoke cleanup was adjusted accordingly.

Commit Groups Delivered
-----------------------

* ``3ae6984`` Add emailalias management command with CRUD and blacklist flows
* ``9862d49`` Add mailinglist, user, and serviceuser management commands
* ``7e95584`` Standardize destructive confirmations on -y/--yes
* ``36d7a6e`` Add management command tests and CI CRUD smoke run
* ``3423f5f`` Fix user activate/deactivate option collision and adjust CI smoke cleanup
