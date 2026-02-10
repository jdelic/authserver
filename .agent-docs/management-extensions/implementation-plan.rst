Management Extensions Implementation Plan
========================================

Context
-------

This repository already provides multiple Django management command namespaces
(``oauth2``, ``permissions``, ``group``, ``domain``, ``spapi``, ``dockerauth``)
with subcommand-based CLIs. Core mailauth administration still has gaps:

* ``EmailAlias`` management is missing.
* ``MailingList`` management is missing.
* ``MNUser``/``MNServiceUser`` operational management is limited.

Goal
----

Add/extend top-level management command namespaces for core identity and mail
routing administration:

* ``django-admin emailalias ...``
* ``django-admin mailinglist ...``
* ``django-admin user ...``
* ``django-admin serviceuser ...``

The command families must support practical administration workflows while
respecting existing model constraints and command style.

Model Constraints to Preserve
-----------------------------

``EmailAlias``
++++++++++++++

* ``(mailprefix, domain)`` is unique.
* An alias must point to exactly one target type:

  * ``user`` (``MNUser``), or
  * ``forward_to`` (``MailingList``)

* Setting both ``user`` and ``forward_to`` is invalid.
* Setting neither is invalid.
* ``blacklisted`` affects SMTP resolution behavior in ``spapi`` functions.

``MNUser`` / ``MNServiceUser``
++++++++++++++++++++++++++++++

* ``MNUser.identifier`` is unique.
* ``MNUser.delivery_mailbox`` is a critical relationship used by auth/spapi.
* ``MNServiceUser`` must resolve unambiguously to a backing ``MNUser``.

``MailingList``
+++++++++++++++

* Address membership should support operator-friendly batch input workflows.
* Relationship consistency with ``EmailAlias.forward_to`` must be preserved.

CLI Design Decisions (Confirmed)
--------------------------------

* New command namespaces are preferred where functionality does not exist.
* Domain resolution should be case-insensitive everywhere.
* Matching-friendly operations can return multiple results.
* Destructive or broad updates should confirm by default.
* ``--force`` bypasses confirmation.
* ``list``/``show`` style output supports ``table`` and ``json``.
* Blacklisting workflows are first-class in ``emailalias``.
* Commonly reused options should expose consistent short forms.

Option Normalization Standard
-----------------------------

For selector/parameter options shared across command families, use consistent
long and short forms whenever the option exists in a command:

* ``--user`` / ``-u``
* ``--domain`` / ``-d``
* ``--mailing-list`` / ``-m``
* ``--format`` / ``-f``
* ``--force`` / ``-F``
* ``--yes`` / ``-y`` (if a command uses yes/no confirmation semantics)
* ``--contains`` / ``-c``
* ``--output`` / ``-o`` (where output path/file is supported)

If an option name exists in multiple namespaces, it should retain the same
meaning and short flag mapping.

Implementation Phases
---------------------

Phase 1: Command Skeletons and Shared Resolvers
+++++++++++++++++++++++++++++++++++++++++++++++

1. Add command modules:

   * ``authserver/mailauth/management/commands/emailalias.py``
   * ``authserver/mailauth/management/commands/mailinglist.py``
   * ``authserver/mailauth/management/commands/user.py``
   * ``authserver/mailauth/management/commands/serviceuser.py``

2. Add shared resolver helpers (in-module or shared utility) for:

   * domain (case-insensitive),
   * user (identifier or resolvable mailbox),
   * service user,
   * mailing list (id or name),
   * alias parser (``local@domain`` and explicit parts).

3. Apply consistent parser construction and help text style from existing
   commands.

Phase 2: Read Operations
++++++++++++++++++++++++

1. Implement ``list`` and ``show`` across namespaces with:

   * ``--format``/``-f`` ``table|json``,
   * filter selectors with normalized short flags,
   * deterministic output columns and JSON payload fields.

2. Include ids and key relation fields in outputs so operators can safely chain
   mutations.

Phase 3: Create and Update Operations
+++++++++++++++++++++++++++++++++++++

1. ``emailalias``:

   * create/edit/remove,
   * blacklist/unblacklist convenience,
   * target exclusivity enforcement.

2. ``mailinglist``:

   * create/list/show/edit/remove,
   * address membership add/remove/set operations,
   * batch address input via repeated args and stdin list mode.

3. ``user``:

   * create/list/show/edit/remove,
   * activation toggles,
   * delivery mailbox management with validation.

4. ``serviceuser``:

   * create/list/show/remove,
   * password/update helpers as needed for operations.

Phase 4: Destructive/Bulk Safety and UX
+++++++++++++++++++++++++++++++++++++++

1. Mutating commands that affect multiple rows:

   * print matched records,
   * prompt for confirmation by default,
   * allow bypass with ``--force``/``-F`` or ``--yes``/``-y`` as applicable.

2. Ensure empty/ambiguous selectors return non-zero and actionable stderr.

Phase 5: Validation and Transactions
++++++++++++++++++++++++++++++++++++

1. Enforce model ``clean()`` and uniqueness behavior before commit.
2. Use transactions for multi-step updates to avoid partial state.
3. Keep stderr/stdout conventions aligned with existing command modules.

Phase 6: Test Coverage
++++++++++++++++++++++

1. Add command tests for each namespace.
2. Cover:

   * case-insensitive domain/user resolution,
   * short/long option parity,
   * multi-match confirmation flow,
   * ``--force`` bypass behavior,
   * JSON/table outputs,
   * batch input handling,
   * relationship and uniqueness constraints.

3. Run project tests relevant to modified command modules.

Compatibility and Rollout Notes
-------------------------------

* No schema changes are required for introducing command families.
* Commands should remain scriptable for configuration management workflows.
* Consistent flags and output reduce operator mistakes and training overhead.

Open Implementation Questions (for coding phase)
------------------------------------------------

* Final boundary between ``user`` and ``serviceuser`` command responsibilities
  for password-related operations.
* Whether some multi-object ``edit`` operations should require explicit
  ``--force`` even when only one row is currently matched by selector.
