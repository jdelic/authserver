# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('mailauth', '0021_alter_mnapplication_authorization_grant_type'),
    ]

    operations = [
        migrations.AddField(
            model_name='emailalias',
            name='blacklisted',
            field=models.BooleanField(default=False),
        ),
    ]
