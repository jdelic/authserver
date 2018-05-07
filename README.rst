maurus.networks Authentication server
=====================================

This is a Python Django based server application that provides single sign-on
services for my own setup. It has OAuth2 endpoints and for applications
that don't support any of these: a SQL stored procedure database abstraction.

As a second application it provides *dkimsigner*, a daemon that speaks SMTP and
receives mail, then forwards it to another SMTP port after signing it with a
DKIM key from its database.

The third included application is *mailforwarder*. As OpenSMTPD 6.x does not
offer a stable filter API and `my OpenSMTPD setup`_ already `relies on
<opensmtpd_spapi_>`__ the "stored procedure API", *mailforwarder* provides
a daemon speaking SMTP that resolves domains and email-addresses in
*authserver's* database and can then forward email to one-or-more other
email addresses. Basically a ``.forward`` or ``.qmail`` implementation based on
authserver's database schema as a Python daemon.

It also provides Django ``manage.py`` commands for registering OAuth2
applications, users, domains and  Docker registries. Those are useful for
creating configuration entries through configuration management systems.

It also includes an implementation of the
`Docker Token Authentication protocol <dockerauth_>`__ and can therefore be
used to secure Docker registries for push and pull with SSO credentials. The
included ``manage.py`` command: ``manage.py dockerauth registry add ...``
allows script based setup.

Finally, it includes a ``checkpassword`` compatible client application that can
be used to integrate Apache2 ``mod_authnz_external`` or DJB checkpassword
compatible clients with authserver.

Users can use the admin interface to create "service users" which are specific
aliases for user accounts that can be used with applications that don't support
OAuth2 so users don't have to share their passwords with the service
(equivalent to the same feature on Google Gmail).

Planned features
----------------
* OAuth2 applications can use a SSL client certificate to authenticate for a
  non-standard HTTP API to register as an OAuth2 client and get their OAuth2
  credentials, cutting down on manual configuration.

* OpenID Connect support

* Service-specific username and passwords for systems that don't support
  OAuth2/OIDC

* CAS support through ``mama-cas``

* add Google Authenticator support via ``django-otp``


Installation
------------
There is no widely available Docker container available yet, but you can install
from this repository:

.. code-block:: shell

    $ virtualenv -p python3 authserver
    $ authserver/bin/pip install net.maurus.authserver


Or for Debian 9.0 Stretch:

.. code-block:: shell

    $ echo "deb http://repo.maurus.net/release/stretch mn-release main" >> /etc/apt/sources.list.d/maurusnet.list
    $ apt update
    $ apt install authserver authclient


APPCONFIG FOLDER
----------------
This application uses `12factor <12factor_>`__ and in its systemd configuration
loads its configuration from a `appconfig folder <appconfig_>`__.

Canonical reserved configuration folders for this app:

* **/etc/appconfig/authserver**
* **/etc/appconfig/dkimsigner**
* **/etc/appconfig/mailforwarder**

Run ``django-admin.py`` like this:

.. code-block:: shell

    bin/envdir /etc/appconfig/authserver/env bin/django-admin.py [command]
        --settings=authserver.settings


12factor Environment configuration
----------------------------------

Managed configuration
+++++++++++++++++++++
These environment variables must be placed in the appconfig folder manually (or
through configuration management). You can just leave ``VAULT_*`` empty and set
``DATABASE_URL`` if you're not planning on using Vault.

====================  ========================================================
Variable              Description
====================  ========================================================
VAULT_CA              Pinned CA to use to validate that we're talking to the
                      right Vault.
VAULT_DATABASE_PATH   The key path to read from Vault to get database
                      credentials for a full access role.
DATABASE_PARENTROLE   The role that authserver should "sudo" into (via
                      ``SET ROLE``) after connecting to the database, i.e. the
                      primary access role (only used with Vault).
DATABASE_NAME         The name of the database to connect to (only used with
                      Vault).
DATABASE_URL          When client SSL certificates or usernames and passwords
                      are used to connect to the database instead of Vault,
                      then this URL (parsed by dj-database-url) is used to
                      connect (only used without Vault).
====================  ========================================================


Smartstack services
-------------------
This application relies on the following smartstack services being available
on localhost:

==== =========== ================
Port Service     SSL Hostname
==== =========== ================
5432 PostgreSQL  postgresql.local
8200 Vault       vault.local
==== =========== ================


Smartstack registration and loadbalancing
-----------------------------------------


Building
========

Build script
------------
This application is meant to be built using `GoPythonGo <gopythongo_>`__.

.. code-block:: shell

    export REPO=maurusnet
    export APTLY_DISTRIBUTION=mn-nightly
    export APTLY_PUBLISH_ENDPOINT=s3:maurusnet:nightly/stretch
    export GNUPGHOME=/etc/gpg-managed-keyring/
    export VAULTWRAPPER_READ_PATH=secret/gpg/packaging_passphrase
    /opt/gopythongo/bin/gopythongo -v /usr/local/authserver /path/to/source


Access methods
==============

There are multiple ways to authenticate user accounts against this program.
Offered APIs include OAuth2, CAS and a "if nothing else works" abstraction
layer for direct user database access based on stored procedures.

Stored Procedure API
--------------------
Since some applications (like OpenSMTPD and Dovecot) which are used by
`my saltshaker <jdelics_saltshaker_>`__  need lowest common denominator
authentication, authserver includes a pgplsql stored procedure API tailored to
OpenSMTPD to validate user accounts.

==  ===================================  =====================================
N   Function Name                        Description
==  ===================================  =====================================
1   ``authserver_get_credentials(        Gets a username password pair for the
    varchar)``                           provided email address together with
                                         the primary delivery email address.
                                         (Users can log in with every email
                                         alias and their account password.)
2   ``authserver_check_domain(           Checks whether the passed domain is a
    varchar)``                           valid delivery domain.
3   ``authserver_resolve_alias(varchar,  Resolves email addresses to known
    boolean)``                           ``MNUser`` or ``MailingList``
                                         instances. Resolving a primary
                                         delivery address will return the
                                         "magic" value "virtmail" pointing to
                                         the system user normally handling
                                         email delivery if the boolean
                                         parameter is ``true``. If the boolean
                                         parameter is ``false`` it will return
                                         the primary delivery address again. If
                                         the resolved address is a
                                         ``MailingList`` it will return the
                                         input unchanged.
4   ``authserver_iterate_users()``       Returns a list of all valid delivery
                                         mailboxes.
==  ===================================  =====================================

Access to the stored procedure API is managed by the ``django-admin.py spapi``
command which allows you to ``grant`` access to database users, ``install`` the
stored procedures on the database and ``check`` whether the stored procedures
have been installed or if a specific database user has ``execute`` access to
the stored procedures. For more information, please run:

.. code-block::shell

    /usr/local/authserver/bin/envdir /etc/appconfig/authserver/env/ \
        /usr/local/authserver/bin/django-admin.py spapi --help


OAuth2
------
authserver delivers OAuth2 support over the following endpoints:

* ``/o2/authorize/``
* ``/o2/token/``
* ``/o2/revoke_token/``

You can create client applications and authorization scopes via the Django
admin interface or ``manage.py oauth2|permissions`` and assign scopes to users
and groups respectively. The authorization view will list the scopes for the
user to approve unless automatic authorization is turned on for the OAuth2
client.


Docker Auth
-----------
authserver supports Docker-compatible JWTs using the "resource owner" OAuth2
flow via ``docker login`` at ``https://your.authserver.domain/docker/token/``.
You can generally just use ``docker login https://your.authserver.domain/`` and
create Docker registry instances and access rights to namespaces on that
registry via the Django admin interface or the ``manage.py dockerauth``
command.


Propietary endpoints and mod_authnz_external
--------------------------------------------
The ``checkpassword.py`` command-line script, also shipped in the
``authclient`` Debian package is compatible with djb checkpassword and Apache2
mod_authnz_external. It uses two proprietary API endpoints:

* ``/checkpassword/`` which takes a username and optionally a list of
  scopes and password (for something akin to the "resource owner" OAuth2 flow)
  and issues a JWT that has the user's assigned scopes and validates the
  password (if transmitted).

* ``/getkey/`` exports a RSA public key for a domain registered with authserver
  to allow a client to validate an issued JWT.

You should prefer OAuth2 where possible as this solution will bring the client
into possession of the user's password. However, if you trust the client this
is an alternative solution. Obviously it's also an easy way to integrate legacy
systems.

``checkpassword.py`` can operate in 5 modes:

* ``-m init`` uses the getkey API to load a RSA public key for the authserver's
  domain and output it to stdout or into a file.
* ``-m check`` behaves like ``init`` but makes no changes, it's useful to check
  whether a domain has a JWT key to export or that key is readable to
  checkpassword on the file system.
* ``-m authext`` and ``-m checkpassword`` read username and password from stdin
  (either in the way specified by mod_authnz_external or djb checkpassword) and
  send them to the server to be validated. The program then either exits with
  exit code ``0`` (success), ``1`` if the auth domain is invalid, ``2`` if
  there are API connection problems and ``3`` for anything else.
* ``-m authextgroup`` validates a list of scopes for a username. This does
  **not** validate the user's password. This is useful for
  mod_authnz_external's ``GroupExternal`` configuration, but you must
  additionally authenticate the user.

The API endpoints respond with a JSON Web Token (JWT) with the following
claims:

.. code-block:: json

    {
        "sub": "the provided username"
        "canonical_username": "the user's delivery_mailbox name"
        "authenticated": true or false depending on the status of the password check
        "authorized": true or false depending on whether the user has all submitted scopes,
        "scopes": ["a list of", "all the scopes", "assigned to this user"],
        "nbf": int(Unix Epoch timestamp of now minus 5 seconds),
        "exp": int(Unix Epoch timestamp of now plus 3600 seconds),
        "iss": "the auth domain name",
        "aud": "net.maurus.authclient"
    }


TODO
====

* refactor Vault fullaccess role into actually granting access to new tables


Licensing
=========

Please see the `LICENSE <LICENSE>`__ document for the terms under which this
source code is licensed.

This program includes a copy of
`django12factor <django12factor_>`__ which is licensed under The MIT License
(MIT) Copyright (c) 2013-2017 Kristian Glass.

This program includes a copy of
`Select2 JavaScript library <select2_>`__ which is licensed user the MIT
License (MIT)
Copyright (c) 2012-2017 Kevin Brown, Igor Vaynberg, and Select2 contributors


.. _12factor: https://12factor.net/
.. _appconfig:
   https://github.com/jdelic/saltshaker/blob/master/ETC_APPCONFIG.md
.. _certified_builds:
   https://github.com/jdelic/saltshaker/blob/master/CERTIFIED_BUILDS.md
.. _django12factor: https://github.com/doismellburning/django12factor/
.. _dockerauth: https://docs.docker.com/registry/spec/auth/token/
.. _gopythongo: https://github.com/gopythongo/gopythongo/
.. _jdelics_saltshaker: https://github.com/jdelic/saltshaker/
.. _my OpenSMTPD setup:
   https://github.com/jdelic/saltshaker/blob/master/srv/salt/opensmtpd/
   smtpd.jinja.conf
.. _opensmtpd_spapi:
   https://github.com/jdelic/saltshaker/blob/master/srv/salt/opensmtpd/
   postgresql.table.jinja.conf
.. _select2:
   https://github.com/select2/select2/
