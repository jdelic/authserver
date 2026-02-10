EmailAlias Command Surface
==========================

Namespace
---------

* ``django-admin emailalias <subcommand> [options]``

Core Principles
---------------

* Domain matching is case-insensitive.
* Mutating operations support match review and confirmation.
* ``--force`` bypasses confirmation where applicable.
* Output-capable commands support ``--format table|json``.

Subcommands to Implement
------------------------

list
++++

Purpose:

* List aliases with optional filtering.

Primary options:

* ``--format {table,json}``
* ``--domain <fqdn>`` (case-insensitive exact)
* ``--contains <substring>`` (address/mailprefix search)
* ``--user <identifier|email>``
* ``--mailing-list <id|name>``
* ``--blacklisted``
* ``--not-blacklisted``

Behavior:

* Returns all matching aliases.
* Table output includes alias, target type, target id/name, blacklisted, pk.

show
++++

Purpose:

* Show one or more aliases matching explicit selectors.

Primary options:

* ``--format {table,json}``
* selector arguments (address and/or filter-based)

Behavior:

* Similar to ``list`` but optimized for explicit lookup and detailed fields.

create
++++++

Purpose:

* Create alias entries.

Primary arguments/options:

* positional alias address (``local@domain``) or explicit
  ``--mailprefix`` + ``--domain``.
* exactly one target:

  * ``--user <identifier|primary delivery email>``, or
  * ``--mailing-list <id|name>``

* optional ``--blacklisted``.

Behavior:

* Validates uniqueness and target exclusivity.
* Emits created object summary.

edit
++++

Purpose:

* Modify alias fields/target.

Primary options:

* selector arguments to find candidate aliases.
* mutations:

  * ``--user <...>``
  * ``--mailing-list <...>``
  * ``--set-blacklisted``
  * ``--unset-blacklisted``
  * optional rename/move via ``--mailprefix`` and/or ``--domain``.

* ``--force`` for applying to multiple matches without prompt.

Behavior:

* Shows matched rows and prompts before multi-object edits unless ``--force``.
* Enforces model constraints and uniqueness.

remove
++++++

Purpose:

* Delete aliases.

Primary options:

* selector arguments.
* ``--force``.

Behavior:

* Shows all matches.
* Prompts for confirmation by default.
* Deletes all confirmed matches (or exits if aborted).

blacklist
+++++++++

Purpose:

* Convenience workflow to create/update aliases for blocked delivery.

Primary options:

* ``--user <identifier|primary delivery email>`` (as requested workflow)
* alias address selector (for existing alias or create-if-missing mode)
* ``--create-if-missing`` (or equivalent explicit behavior flag)
* ``--force`` for multi-match actions.

Behavior:

* Sets ``blacklisted=True``.
* Preserves/validates alias target relation.
* If creating, requires enough data to satisfy model constraint.

unblacklist
+++++++++++

Purpose:

* Clear blacklist flag for matching aliases.

Primary options:

* selector arguments.
* ``--force``.

Behavior:

* Sets ``blacklisted=False`` after optional confirmation.

Batch-Friendly Extensions (v1 where applicable)
------------------------------------------------

For commands where repeated values are operationally useful:

* accept repeated flags (for example multiple selectors), and/or
* accept stdin list input for selectors via ``-`` sentinel.

Candidates:

* ``remove`` multi-selector deletes,
* ``blacklist``/``unblacklist`` repeated alias addresses,
* future ``mailinglist`` command family for adding many destination addresses.

Suggested Selector Conventions
------------------------------

Preferred explicit selector forms:

* positional ``alias`` as ``local@domain``.
* ``--mailprefix`` + ``--domain``.
* filter selectors for bulk:

  * ``--contains``
  * ``--domain``
  * ``--user``
  * ``--mailing-list``

Safety Rules
------------

* Any destructive operation with potentially multiple matches prompts unless
  ``--force``.
* Any mutation targeting multiple aliases should print affected aliases before
  applying changes.
* Ambiguous/empty target resolution exits non-zero with actionable error text.
