Management Extension Command Surface
===================================

Namespaces
----------

* ``django-admin emailalias <subcommand> [options]``
* ``django-admin mailinglist <subcommand> [options]``
* ``django-admin user <subcommand> [options]``
* ``django-admin serviceuser <subcommand> [options]``

Cross-Command Option Convention
-------------------------------

When these options exist in a command, provide both long and short forms:

* ``--user`` / ``-u``
* ``--domain`` / ``-d``
* ``--mailing-list`` / ``-m``
* ``--format`` / ``-f``
* ``--force`` / ``-F``
* ``--yes`` / ``-y``
* ``--contains`` / ``-c``
* ``--output`` / ``-o``

Core Principles
---------------

* Domain matching is case-insensitive.
* Mutating operations support match review and confirmation.
* ``--force`` bypasses confirmation where applicable.
* Output-capable commands support ``--format table|json``.
* Shared selectors keep the same semantics across namespaces.

``emailalias`` Subcommands
--------------------------

list
++++

* filters: ``--domain/-d``, ``--contains/-c``, ``--user/-u``,
  ``--mailing-list/-m``, blacklist filters
* output: ``--format/-f``

show
++++

* explicit selector lookup with detailed fields
* output: ``--format/-f``

create
++++++

* alias selector: positional ``local@domain`` or
  ``--mailprefix`` + ``--domain/-d``
* target (exactly one): ``--user/-u`` or ``--mailing-list/-m``
* optional: blacklist on create

edit
++++

* selector filters and target reassignment
* blacklist toggles
* optional mailprefix/domain move
* multi-match safety with confirmation or ``--force/-F``

remove
++++++

* selector filters
* shows all matches and confirms by default
* bypass with ``--force/-F`` or ``--yes/-y``

blacklist
+++++++++

* convenience operation for setting ``blacklisted=True``
* supports requested workflow:
  ``django-admin emailalias blacklist --user/-u <identifier|primary delivery email> <alias>``
* optional create-if-missing semantics

unblacklist
+++++++++++

* convenience operation for setting ``blacklisted=False``
* selector filters + confirmation/force behavior

``mailinglist`` Subcommands
---------------------------

create
++++++

* create mailing list with name and optional initial addresses

list
++++

* list mailing lists with filters and ``--format/-f``

show
++++

* show mailing list details including addresses

edit
++++

* rename list and/or update metadata

remove
++++++

* remove one/more lists with confirmation defaults and ``--force/-F``

add-address
+++++++++++

* add one or more addresses to a list
* batch input support:

  * repeated arguments
  * stdin list mode via ``-``

remove-address
++++++++++++++

* remove one or more addresses from a list
* supports batch input

set-addresses
+++++++++++++

* replace list addresses atomically from args/stdin

``user`` Subcommands
--------------------

create
++++++

* create ``MNUser`` with required fields and optional password input mode

list
++++

* list users with filters and ``--format/-f``

show
++++

* show user details and key relationships (delivery mailbox, status)

edit
++++

* update fullname/identifier and other mutable fields

activate / deactivate
+++++++++++++++++++++

* toggle ``is_active``

set-delivery-mailbox
++++++++++++++++++++

* set/replace delivery mailbox alias with integrity checks

remove
++++++

* remove/decommission user with confirmation defaults

``serviceuser`` Subcommands
---------------------------

create
++++++

* create ``MNServiceUser`` linked to ``--user/-u`` target

list
++++

* list service users with filters and ``--format/-f``

show
++++

* show service user details and linked user

edit
++++

* update mutable service user properties (for example username/password flow)

remove
++++++

* remove service user with confirmation defaults

Batch and Selector Rules
------------------------

* Prefer explicit selectors for single-object edits.
* Allow filter selectors for review and bulk operations.
* Any multi-match destructive/mutating action must display affected objects
  and require confirmation unless forced.

Safety Rules
------------

* Destructive operations with possible multiple matches prompt unless forced.
* Mutations on multiple rows print affected rows first.
* Ambiguous/empty target resolution exits non-zero with actionable stderr.
