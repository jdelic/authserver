# Generated by Django 4.1 on 2022-08-21 23:05

from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ('mailauth', '0016_alter_mnapplication_client_secret_and_more'),
        ('dockerauth', '0006_registry_require_domain_fk'),
    ]

    operations = [
        migrations.AlterField(
            model_name='dockerregistry',
            name='group_pull_access',
            field=models.ManyToManyField(blank=True, related_name='%(class)s_pull_access', to='mailauth.mngroup', verbose_name='Groups with pull access (read)'),
        ),
        migrations.AlterField(
            model_name='dockerregistry',
            name='group_push_access',
            field=models.ManyToManyField(blank=True, related_name='%(class)s_push_access', to='mailauth.mngroup', verbose_name='Groups with push access (write)'),
        ),
        migrations.AlterField(
            model_name='dockerregistry',
            name='user_pull_access',
            field=models.ManyToManyField(blank=True, related_name='%(class)s_pull_access', to=settings.AUTH_USER_MODEL, verbose_name='Users with pull access (read)'),
        ),
        migrations.AlterField(
            model_name='dockerregistry',
            name='user_push_access',
            field=models.ManyToManyField(blank=True, related_name='%(class)s_push_access', to=settings.AUTH_USER_MODEL, verbose_name='Users with push access (write)'),
        ),
        migrations.AlterField(
            model_name='dockerrepo',
            name='group_pull_access',
            field=models.ManyToManyField(blank=True, related_name='%(class)s_pull_access', to='mailauth.mngroup', verbose_name='Groups with pull access (read)'),
        ),
        migrations.AlterField(
            model_name='dockerrepo',
            name='group_push_access',
            field=models.ManyToManyField(blank=True, related_name='%(class)s_push_access', to='mailauth.mngroup', verbose_name='Groups with push access (write)'),
        ),
        migrations.AlterField(
            model_name='dockerrepo',
            name='user_pull_access',
            field=models.ManyToManyField(blank=True, related_name='%(class)s_pull_access', to=settings.AUTH_USER_MODEL, verbose_name='Users with pull access (read)'),
        ),
        migrations.AlterField(
            model_name='dockerrepo',
            name='user_push_access',
            field=models.ManyToManyField(blank=True, related_name='%(class)s_push_access', to=settings.AUTH_USER_MODEL, verbose_name='Users with push access (write)'),
        ),
    ]