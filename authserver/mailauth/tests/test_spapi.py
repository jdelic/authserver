from django.core.management import call_command
from django.db import connection
from django.test import TestCase

from mailauth import models


class SPAPIServiceUserTests(TestCase):
    def setUp(self) -> None:
        self.domain = models.Domain.objects.create(name="example.com")
        self.user = models.MNUser.objects.create_user(
            identifier="alice",
            fullname="Alice Example",
            password="secret",
        )
        self.alias = models.EmailAlias.objects.create(
            mailprefix="alice",
            domain=self.domain,
            user=self.user,
        )
        self.user.delivery_mailbox = self.alias
        self.user.save()

        self.service_user = models.MNServiceUser.objects.create(
            user=self.user,
            username="svc-alice",
            description="IMAP bridge",
        )
        self.service_user.set_password("svc-secret")
        self.service_user.save()

    def test_get_credentials_supports_service_usernames(self) -> None:
        call_command("spapi", "install")

        with connection.cursor() as cursor:
            cursor.execute("SELECT username, password, primary_alias FROM authserver_get_credentials(%s)", ["svc-alice"])
            row = cursor.fetchone()

        self.assertIsNotNone(row)
        self.assertEqual("svc-alice", row[0])
        self.assertEqual(self.service_user.__dict__["password"], row[1])
        self.assertEqual("alice@example.com", row[2])

    def test_get_credentials_with_permission_supports_direct_permissions(self) -> None:
        permission = models.MNApplicationPermission.objects.create(
            name="IMAP Access",
            permission_name="mail.imap",
        )
        self.user.app_permissions.add(permission)  # type: ignore
        call_command("spapi", "install")

        with connection.cursor() as cursor:
            cursor.execute(
                "SELECT username, password, primary_alias FROM authserver_get_credentials(%s, %s)",
                ["alice@example.com", "mail.imap"],
            )
            row = cursor.fetchone()

        self.assertIsNotNone(row)
        self.assertEqual("alice@example.com", row[0])
        self.assertEqual(self.user.__dict__["password"], row[1])
        self.assertEqual("alice@example.com", row[2])

    def test_get_credentials_with_permission_supports_group_permissions(self) -> None:
        permission = models.MNApplicationPermission.objects.create(
            name="SMTP Access",
            permission_name="mail.smtp",
        )
        group = models.MNGroup.objects.create(name="Mail Services")
        group.group_permissions.add(permission)  # type: ignore
        self.user.app_groups.add(group)  # type: ignore
        call_command("spapi", "install")

        with connection.cursor() as cursor:
            cursor.execute(
                "SELECT username, password, primary_alias FROM authserver_get_credentials(%s, %s)",
                ["svc-alice", "mail.smtp"],
            )
            row = cursor.fetchone()

        self.assertIsNotNone(row)
        self.assertEqual("svc-alice", row[0])
        self.assertEqual(self.service_user.__dict__["password"], row[1])
        self.assertEqual("alice@example.com", row[2])

    def test_get_credentials_with_permission_filters_unauthorized_users(self) -> None:
        models.MNApplicationPermission.objects.create(
            name="SMTP Access",
            permission_name="mail.smtp",
        )
        call_command("spapi", "install")

        with connection.cursor() as cursor:
            cursor.execute(
                "SELECT username, password, primary_alias FROM authserver_get_credentials(%s, %s)",
                ["alice@example.com", "mail.smtp"],
            )
            row = cursor.fetchone()

        self.assertIsNone(row)
