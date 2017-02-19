maurus.networks Authentication server
=====================================

This is a Python Django based server application that provides single sign-on
services for my own setup. It has OAuth2 and CAS endpoints and for applications
that don't support any of these a SQL stored procedure database abstraction.

OAuth2 applications can use a SSL client certificate to authenticate for a
non-standard HTTP API to register as an OAuth2 client and get their OAuth2
credentials, cutting down on manual configuration.

Installation
------------


APPCONFIG FOLDER
----------------

This application uses `12factor <https://12factor.net/>`__ and in its systemd
configuration loads its configuration from a
`appconfig folder <https://github.com/jdelic/saltshaker/blob/master/ETC_APPCONFIG.md>`__.

Canonical reserved configuration folders for this app:
**/etc/appconfig/authserver**

Run ``django-admin.py`` like this:

.. code-block:: shell

    bin/envdir /etc/appconfig/authserver/env bin/django-admin.py [command]
        --settings=authserver.settings``


Environment configuration
-------------------------

Build configuration
+++++++++++++++++++

This configuration is generated during build time using
`GoPythonGo tools <https://github.com/gopythongo/gopythongo`__.

==============  ==============================================================
Variable        Description
==============  ==============================================================
VAULT_SSLCERT   The client certificate to be used to connect to Vault to
                retrieve database credentials
VAULT_SSLKEY    The client key to be used to connect to Vault to retrieve
                database credentials
SECRET_KEY      The Django settings.SECRET_KEY value to be used
==============  ==============================================================

Managed configuration
+++++++++++++++++++++

These configuration values in the appconfig folder must be provided manually
(or through comfiguration management).

====================  ========================================================
Variable              Description
====================  ========================================================
VAULT_CA              The CA to use to validate that we're talking to the
                      right Vault
VAULT_DATABASE_PATH   The key path to read from Vault to get database
                      credentials for a full access role
DATABASE_PARENTROLE   The role that authserver should "sudo" into (via
                      ``SET ROLE``) after connecting to the database, i.e. the
                      primary access role.
DATABASE_NAME         The name of the database to connect to.
SPAPI_DBUSERS         A comma-separated list of database users which are being
                      granted access to the stored procedure API in migration
                      ``0003_opensmtpd_access``.
====================  ========================================================


Smartstack services
-------------------

This application relies on the following smartstack services being available
on localhost:

==============
Service
==============
PostgreSQL
Vault
==============


Smartstack registration and loadbalancing
-----------------------------------------


Access methods
--------------

There are multiple ways to authenticate user accounts against this program.
Offered APIs include OAuth2, CAS and a "if nothing else works" abstraction
layer for direct user database access based on stored procedures.

Stored Procdure API
+++++++++++++++++++
Since some applications (like OpenSMTPD and Dovecot) which are used by
`my saltshaker <https://github.com/jdelic/saltshaker>`__  need lowest common
denominator authentication, authserver includes a pgplsql stored procedure API
tailored to OpenSMTPD to validate user accounts.

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
    boolean)``                           ``MNUser`` instances. Resolving a
                                         primary delivery address will return
                                         the "magic" value "virtmail" pointing
                                         to the system user normally handling
                                         email delivery if the boolean
                                         parameter is ``true``. If the boolean
                                         parameter is ``false`` it will return
                                         the primary delivery address again.
4   ``authserver_iterate_users()``       Returns a list of all delivery
                                         mailboxes.
==  ===================================  =====================================



Future extensions
-----------------

 * add Google Authenticator support via ``django-otp``
 * fully implement CAS


TODO
====

 * refactor Vault fullaccess role into actually granting access to new tables
