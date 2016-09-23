APPCONFIG FOLDER
================

Canonical reserved configuration folder for this app:
**/etc/appconfig/authserver**


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


Future extensions
=================

 * add Google Authenticator support via ``django-otp``
 * add oauth2 support using ``django-oauth-toolkit``
 * fully implement CAS


TODO
====

 * refactor Vault fullaccess role into actually granting access to new tables
