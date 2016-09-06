authserver Vault Config
=======================

This application loads its database credentials from a local
[Vault server](https://vaultproject.io/) at vault.local (a /etc/hosts alias)
on port 8200. This Vault server must be configured to give out PostgreSQL
database credentials.

Here is a command list for doing so (assuming you are authenticated to the
Vault instance):

```
vault mount postgresql
vault write postgresql/config/connection connection_url=-

postgresql://vaultadmin:(PASSWORD)@postgresql.local:5432/postgres

vault write postgresql/config/lease lease=1h lease_max=24h

vault write postgresql/roles/authserver sql=-

CREATE ROLE "{{name}}" WITH LOGIN PASSWORD '{{password}}'
    VALID UNTIL '{{expiration}}';
GRANT ALL PRIVILEGES ON DATABASE mnusers TO "{{name}}";

# now you can create database logins like this:
# vault read -format=json postgresql/creds/authserver
```
