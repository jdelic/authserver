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
applications. Those are useful for creating configuration entries through
configuration management systems.

Finally, it also includes an implementation of the
`Docker Token Authentication protocol <dockerauth_>`__ and can therefore be
used to secure Docker registries for push and pull with SSO credentials. The
included ``manage.py`` command: ``manage.py dockerauth registry add ...``
allows script based setup.


Planned features
----------------
* OAuth2 applications can use a SSL client certificate to authenticate for a
  non-standard HTTP API to register as an OAuth2 client and get their OAuth2
  credentials, cutting down on manual configuration.
  
* OpenID Connect support

* Command-line authentication helper

* Service-specific username and passwords for systems that don't support
  OAuth2/OIDC

* CAS support through ``mama-cas``

* add Google Authenticator support via ``django-otp``


Installation
------------
There is no widely available Docker container or Debian package available yet,
but you can install from this repository.


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
through configuration management).

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
SPAPI_DBUSERS         A comma-separated list of database users which are being
                      granted access to the stored procedure API in migration
                      ``0003_opensmtpd_access``.
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

Build configuration
-------------------
These entries in the appconfig folder are generated during build time using
`GoPythonGo tools <gopythongo_>`__ and are then meant to be shipped with the
application.

==============  ==============================================================
Variable        Description
==============  ==============================================================
VAULT_SSLCERT   The client certificate to be used to connect to Vault to
                retrieve database credentials.
VAULT_SSLKEY    The client key to be used to connect to Vault to retrieve
                database credentials.
SECRET_KEY      The Django settings.SECRET_KEY value to be used.
DB_SSLCERT      An alternative way for connecting to the database. If Vault
                isn't used to manage database access, this can be set to a
                SSL client certificate to authenticate with the database.
DB_SSLKEY       The private key for ``DB_SSLCERT``.
==============  ==============================================================

The ``vaultgetcert`` configurations in ``.gopythongo`` refer to the following
certificate + CA chain bundles. If you're building for an environment that
uses `Certified Build <certified_builds_>`__ then ``VGC_XSIGN_CACERT`` should
contain the following bundles:

==============  ==============================================================
Certificate
==============  ==============================================================
vault.crt       The CA chain used to access Vault for database credentials (if
                used)
postgresql.crt  The CA chain used to access PostgreSQL with a client 
                certificate (if used)
==============  ==============================================================


Build script
------------
This application is meant to be built using `GoPythonGo <gopythongo_>`__ using
gopythongo's ``vaultgetcert`` tool to create a number of SSL client
certificates (see "Environment configuration" above).

If you plan on deploying authserver with usernames and passwords, you can
just comment out the ``vaultgetcert-config`` line in ``.gopythongo/config``.
Otherwise, set up intermediate CAs for your deployment environment and the
``authserver`` application and install one of them in Vault, as described in
`Certified Builds <certified_builds_>`__
and create a cross-signature configuration for the other CA using the
``VGC_XSIGN_CACERT`` environment variable like so:

.. code-block:: shell

    export VGC_XSIGN_CACERT=postgresql.crt=/etc/concourse/cacerts/env-dev-ca.crt,vault.crt=/etc/concourse/cacerts/cas-ca.crt
    export REPO=maurusnet
    export APTLY_DISTRIBUTION=mn-nightly
    export APTLY_PUBLISH_ENDPOINT=s3:maurusnet:nightly/stretch
    export VGC_VAULT_PKI=casserver-ca/issue/build
    export VAULTWRAPPER_READ_PATH=secret/gpg/packaging_passphrase
    export VGC_OVERWRITE=True
    export GNUPGHOME=/etc/gpg-managed-keyring/
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
