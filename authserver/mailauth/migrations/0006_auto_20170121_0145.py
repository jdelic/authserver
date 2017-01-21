# -*- coding: utf-8 -*-
# Generated by Django 1.10.4 on 2017-01-21 00:45
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('mailauth', '0005_domain_dkimselector'),
    ]

    operations = [
        migrations.AlterField(
            model_name='domain',
            name='dkimselector',
            field=models.CharField(blank=True, default='default', max_length=255, verbose_name='DKIM DNS selector'),
        ),
    ]
