Loaded config files (systemd)
=============================

File           | Description
---------------|--------------------------------------------------------------
MANAGED_CONFIG | Configuration (overrides) by configuration management
BUILD_CONFIG   | Configuration provided during build time
SECRET_KEY     | The Django settings.SECRET_KEY value to be used


Environment configuration
=========================

Build configuration
-------------------

Variable      | Description
--------------|---------------------------------------------------------------
VAULT_SSLCERT | The client certificate to be used to connect to Vault to retrieve database credentials
VAULT_SSLKEY  | The client key to be used to connect to Vault to retrieve database credentials
SECRET_KEY    | The Django settings.SECRET_KEY value to be used

Managed configuration
---------------------

Variable            | Description
--------------------|---------------------------------------------------------
VAULT_CA            | The CA to use to validate that we're talking to the right Vault
VAULT_DATABASE_PATH | The key path to read from Vault to get database credentials


Future extensions
=================

 * add Google Authenticator support via `django-otp`
 * add oauth2 support using `django-oauth-toolkit`
 * fully implement CAS


TODO
====

 * Figure out where VAULT_CA should come from
 * refactor Vault fullaccess role into actually granting access to new tables
