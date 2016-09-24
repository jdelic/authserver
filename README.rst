APPCONFIG FOLDER
================

Canonical reserved configuration folder for this app:
**/etc/appconfig/authserver**

Run ``django-admin.py`` like this:

.. code-block:: shell

    bin/envdir /etc/appconfig/authserver/env bin/django-admin.py [command]
        --settings=authserver.settings``


Environment configuration
=========================

Build configuration
-------------------

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
---------------------

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
OPENSMTPD_DBUSER      A user being granted access to the stored procedure API
                      in migration ``0003_opensmtpd_access``.
====================  ========================================================


Smartstack services
===================

This application relies on the following smartstack services:

==============
Service       
==============
PostgreSQL      
Vault
==============


Access methods
==============

There are multiple ways to authenticate user accounts against this program.
Offered APIs will include OAuth and CAS.

Stored Procdure API
-------------------
Since some applications (like OpenSMTPD) which are used by
`my saltshaker <https://github.com/jdelic/saltshaker>`__  need lowest common
denominator authentication, authserver includes a pgplsql stored procedure API
tailored to OpenSMTPD to validate user accounts.

=======================================  =====================================
Function Name                            Description
=======================================  =====================================
``authserver_get_credentials(varchar)``  Gets a username password pair for the
                                         provided email address together with
                                         the primary delivery email address.
                                         (Users can log in with every email
                                         alias and their account password.)
``authserver_check_domain(varchar)``     Checks whether the passed domain is a
                                         valid delivery domain.
``authserver_resolve_alias(varchar)``    Resolves email addresses to known
                                         ``MNUser`` instances. Resolving a
                                         primary delivery address will return
                                         the "magic" value "virtmail" pointing
                                         to the system user normally handling
                                         email delivery.
``authserver_iterate_users()``           Returns a list of all delivery
                                         mailboxes.
=======================================  =====================================


Future extensions
=================

 * add Google Authenticator support via ``django-otp``
 * add oauth2 support using ``django-oauth-toolkit``
 * fully implement CAS


TODO
====

 * refactor Vault fullaccess role into actually granting access to new tables
