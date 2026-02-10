Management Extensions: EmailAlias Implementation Plan
======================================================

Context
-------

This repository already provides multiple Django management command namespaces
(``oauth2``, ``permissions``, ``group``, ``domain``, ``spapi``, ``dockerauth``)
with subcommand-based CLIs. ``mailauth.models.EmailAlias`` is a key model for
mail routing and authentication behavior, but it does not currently have an
administrative command namespace.

Goal
----

Add a new top-level command namespace:

* ``django-admin emailalias ...``

The command family must support practical administration workflows for
``EmailAlias`` records, with behavior aligned to existing command style while
respecting model constraints.

Model Constraints to Preserve
-----------------------------

From ``mailauth.models.EmailAlias``:

* ``(mailprefix, domain)`` is unique.
* An alias must point to exactly one target type:

  * ``user`` (``MNUser``), or
  * ``forward_to`` (``MailingList``)

* Setting both ``user`` and ``forward_to`` is invalid.
* Setting neither is invalid.
* ``blacklisted`` toggles SMTP resolution behavior in ``spapi`` logic.

Design Decisions (Confirmed)
----------------------------

* New command namespace (not nested under another command): ``emailalias``.
* Case-insensitive domain resolution everywhere.
* Matching-friendly operations should support multiple matches, with safer
  defaults that ask for confirmation for destructive changes.
* ``--force`` style bypass for confirmations on destructive/bulk operations.
* ``list``/``show`` style output should support both table and JSON formats.
* Blacklisting should be available in v1 workflows.
* Batch operations are appropriate where input naturally supports it.

Implementation Phases
---------------------

Phase 1: Command Skeleton and Shared Resolvers
++++++++++++++++++++++++++++++++++++++++++++++

1. Create ``authserver/mailauth/management/commands/emailalias.py``.
2. Add subparser wiring and consistent help text patterns.
3. Add resolver helpers for:

   * domain (case-insensitive by name),
   * user (identifier or resolvable mailbox),
   * mailing list (id or name),
   * alias selector parsing.

4. Add table formatting utility use via existing
   ``mailauth.management.commands._common.table_left_format_str``.

Phase 2: Read Operations
++++++++++++++++++++++++

1. Implement ``list`` with filters and output modes:

   * table (default),
   * json.

2. Implement matching behavior that can return multiple aliases.
3. Include fields needed for operations review:

   * alias address,
   * target type/value,
   * blacklisted state,
   * primary key.

Phase 3: Create and Update Operations
+++++++++++++++++++++++++++++++++++++

1. Implement ``create`` with explicit target arguments and validation:

   * ``--user`` or ``--mailing-list`` (mutually exclusive),
   * ``--blacklisted`` optional,
   * domain/name parsing from full email alias input.

2. Implement ``edit`` for selected aliases:

   * switch target (user vs mailing list) with exclusivity,
   * set/unset blacklist,
   * optional mailprefix/domain move when non-conflicting.

3. Enforce uniqueness conflicts and model validation errors with clear stderr
   messages and non-zero exits.

Phase 4: Destructive and Policy Workflows
+++++++++++++++++++++++++++++++++++++++++

1. Implement ``remove`` with match query support.
2. Default behavior:

   * display matching aliases,
   * request confirmation before delete when one or more matches are found.

3. ``--force`` bypasses prompt.
4. Add explicit ``blacklist`` and ``unblacklist`` convenience subcommands for
   common operational workflows.

Phase 5: Batch-Friendly Inputs
++++++++++++++++++++++++++++++

1. For workflows where batching is useful, support:

   * repeated command arguments, and/or
   * reading newline-delimited values from stdin (``-`` convention) where
     practical and explicit.

2. Keep object creation semantics explicit so operators must provide enough
   information for each alias target relation.

Phase 6: Validation and Test Coverage
+++++++++++++++++++++++++++++++++++++

1. Add command tests under an appropriate tests module (likely in
   ``authserver/mailauth/tests`` if present, otherwise create one).
2. Cover:

   * case-insensitive domain resolution,
   * user/list target exclusivity,
   * uniqueness collision handling,
   * confirmation and ``--force`` behavior,
   * json/table outputs,
   * blacklist toggling.

3. Run available test suite for changed scope.

Error Handling and Exit Semantics
---------------------------------

Follow existing command conventions:

* write actionable operator messages to stderr,
* return non-zero exit on validation/DB errors,
* avoid partial writes by using transactions for multi-step mutations.

Compatibility and Rollout Notes
-------------------------------

* No schema changes are required for command introduction.
* Command behavior should remain scriptable for configuration management users.
* Default-safe deletion/update confirmation protects against over-broad matching.

Open Implementation Questions (to resolve during coding)
--------------------------------------------------------

* Final selector grammar for targeting aliases:

  * explicit ``mailprefix + domain`` flags,
  * full address argument (``local@domain``),
  * optional fuzzy filter mode for bulk operations.

* How broad ``edit`` should be in v1 for multi-match queries vs requiring
  explicit single-match selectors for certain field changes.
