import json
from io import StringIO

from django.core.management import call_command
from django.test import TestCase

from mailauth import models


class EmailAliasCommandTests(TestCase):
    def setUp(self) -> None:
        self.domain = models.Domain.objects.create(name="example.com")
        self.user = models.MNUser.objects.create_user(
            identifier="alice",
            fullname="Alice Example",
            password="secret",
        )

    def test_create_and_list_json(self) -> None:
        call_command("emailalias", "create", "alice@example.com", "-u", "alice")
        out = StringIO()
        call_command("emailalias", "list", "-f", "json", stdout=out)
        payload = json.loads(out.getvalue())
        self.assertEqual(1, len(payload))
        self.assertEqual("alice@example.com", payload[0]["alias"])


class MailingListCommandTests(TestCase):
    def test_create_and_update_addresses(self) -> None:
        call_command("mailinglist", "create", "admins", "ops@example.com")
        mlist = models.MailingList.objects.get(name="admins")
        call_command("mailinglist", "add-address", "-m", str(mlist.pk), "eng@example.com")
        mlist.refresh_from_db()
        self.assertIn("ops@example.com", mlist.addresses)
        self.assertIn("eng@example.com", mlist.addresses)


class UserCommandTests(TestCase):
    def setUp(self) -> None:
        self.domain = models.Domain.objects.create(name="example.com")

    def test_create_and_deactivate(self) -> None:
        call_command("user", "create", "bob", "Bob Example", "--password", "secret")
        call_command("user", "deactivate", "bob", "-y")
        user = models.MNUser.objects.get(identifier="bob")
        self.assertFalse(user.is_active)


class ServiceUserCommandTests(TestCase):
    def setUp(self) -> None:
        self.domain = models.Domain.objects.create(name="example.com")
        self.user = models.MNUser.objects.create_user(
            identifier="charlie",
            fullname="Charlie Example",
            password="secret",
        )
        self.alias = models.EmailAlias.objects.create(
            mailprefix="charlie",
            domain=self.domain,
            user=self.user,
            blacklisted=False,
        )
        self.user.delivery_mailbox = self.alias
        self.user.save()

    def test_create_and_list_service_user(self) -> None:
        stdout = StringIO()
        call_command("serviceuser", "create", "-u", "charlie", "--username", "svc-charlie", stdout=stdout)
        self.assertTrue(stdout.getvalue().strip())

        out = StringIO()
        call_command("serviceuser", "list", "-f", "json", stdout=out)
        payload = json.loads(out.getvalue())
        self.assertEqual(1, len(payload))
        self.assertEqual("svc-charlie", payload[0]["username"])
