authserver Vault Config
=======================

This application loads its database credentials from a local
[Vault server](https://vaultproject.io/) at vault.local (a /etc/hosts alias)
on port 8200. This Vault server must be configured to give out PostgreSQL
database credentials.

Here is a command list for doing so (assuming you are authenticated to the
Vault instance):

As `postgres`:
```
createuser -D -E -I -P -l -r -S vaultadmin
createuser -D -E -I -L -R -S authserver
createdb -E utf8 -O authserver authserver
```

Then configure Vault:
```
vault mount -path=db-authserver postgresql
vault write db-authserver/config/connection connection_url=-
postgresql://vaultadmin:(password)@postgresql.local:5432/authserver

vault write db-authserver/config/lease lease=1h lease_max=24h

vault write db-authserver/roles/authserver sql=-
CREATE ROLE "{{name}}" WITH LOGIN PASSWORD '{{password}}' VALID
UNTIL '{{expiration}}' IN ROLE "mydatabaseowner" INHERIT NOCREATEROLE
NOCREATEDB NOSUPERUSER NOREPLICATION NOBYPASSRLS;

# now you can create database logins like this:
# vault read -format=json postgresql/creds/authserver
```
