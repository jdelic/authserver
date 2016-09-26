# -*- coding: utf-8 -*-
# Generated by Django 1.10.1 on 2016-09-22 22:34
from django.apps.registry import Apps
from django.conf import settings
from django.core.exceptions import ImproperlyConfigured
from django.db import migrations
from django.db.backends.base.schema import BaseDatabaseSchemaEditor
from django.db.migrations.operations.special import RunSQL, RunPython


def check_preconditions(apps: Apps, schemaeditor: BaseDatabaseSchemaEditor):
    # make sure we have the config
    if not settings.SPAPI_DBUSERS:
        raise ImproperlyConfigured("Missing required settings for this migration: settings.OPENSMTPD_DBUSER")


class Migration(migrations.Migration):

    dependencies = [
        ('mailauth', '0001_initial'),
        ('mailauth', '0002_stored_procedures'),
    ]

    operations = [
        RunPython(check_preconditions),
    ] + \
    [
        RunSQL("""
            GRANT EXECUTE ON FUNCTION authserver_check_domain(varchar) TO "{username}";
            GRANT EXECUTE ON FUNCTION authserver_get_credentials(varchar) TO "{username}";
            GRANT EXECUTE ON FUNCTION authserver_resolve_alias(varchar) TO "{username}";
            GRANT EXECUTE ON FUNCTION authserver_iterate_users() TO "{username}";
        """.format(username=username)) for username in settings.SPAPI_DBUSERS
    ]
