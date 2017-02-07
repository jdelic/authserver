#!/usr/bin/env bash

# This removes end-of-life refresh tokens from the database
/usr/local/authserver/bin/envdir /etc/appconfig/authserver/env/ \
    /usr/local/authserver/bin/django-admin.py cleartokens --settings=authserver.settings
