# -*- coding: utf-8 -*-
# Generated by Django 1.11.3 on 2017-07-09 19:01
from __future__ import unicode_literals

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('dockerauth', '0001_initial'),
    ]

    operations = [
        migrations.AlterModelOptions(
            name='dockerregistry',
            options={'verbose_name': 'Docker Registry', 'verbose_name_plural': 'Docker Registries'},
        ),
        migrations.AlterModelOptions(
            name='dockerrepo',
            options={'verbose_name': 'Docker Repository', 'verbose_name_plural': 'Docker Repositories'},
        ),
    ]
