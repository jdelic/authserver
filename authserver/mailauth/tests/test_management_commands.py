import json
from io import StringIO
from contextlib import redirect_stderr, redirect_stdout

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
        with redirect_stdout(out):
            call_command("emailalias", "list", "-f", "json")
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
        with redirect_stdout(out):
            call_command("serviceuser", "list", "-f", "json")
        payload = json.loads(out.getvalue())
        self.assertEqual(1, len(payload))
        self.assertEqual("svc-charlie", payload[0]["username"])


class EmailAgentTokenCommandTests(TestCase):
    def setUp(self) -> None:
        self.domain = models.Domain.objects.create(name="example.com")
        self.user = models.MNUser.objects.create_user(
            identifier="dana",
            fullname="Dana Example",
            password="secret",
        )
        self.alias = models.EmailAlias.objects.create(
            mailprefix="dana",
            domain=self.domain,
            user=self.user,
            blacklisted=False,
        )
        self.user.delivery_mailbox = self.alias
        self.user.save()

    def test_create_check_and_check_and_burn_token(self) -> None:
        create_out = StringIO()
        call_command("emailagenttoken", "create", "-u", "dana", stdout=create_out)
        raw_token = create_out.getvalue().strip()
        token = models.EmailAgentAuthToken.objects.get(creator=self.user)
        self.assertEqual(token.token, raw_token)

        check_out = StringIO()
        with self.assertRaises(SystemExit) as check_exit:
            call_command("emailagenttoken", "check", raw_token, stdout=check_out)
        self.assertEqual(0, check_exit.exception.code)
        self.assertEqual("VALID", check_out.getvalue().strip())

        burn_out = StringIO()
        with self.assertRaises(SystemExit) as burn_exit:
            call_command("emailagenttoken", "check-and-burn", raw_token, stdout=burn_out)
        self.assertEqual(0, burn_exit.exception.code)
        self.assertEqual("VALID", burn_out.getvalue().strip())

        token.refresh_from_db()
        self.assertTrue(token.burned)
        self.assertIsNotNone(token.used_at)

        invalid_out = StringIO()
        with self.assertRaises(SystemExit) as invalid_exit:
            call_command("emailagenttoken", "check", raw_token, stdout=invalid_out)
        self.assertEqual(1, invalid_exit.exception.code)
        self.assertEqual("INVALID", invalid_out.getvalue().strip())

    def test_burn_marks_token_burned(self) -> None:
        token, raw_token = models.EmailAgentAuthToken.objects.issue_token(self.user)

        burn_err = StringIO()
        with self.assertRaises(SystemExit) as burn_exit, redirect_stderr(burn_err):
            call_command("emailagenttoken", "burn", raw_token)
        self.assertEqual(0, burn_exit.exception.code)

        token.refresh_from_db()
        self.assertTrue(token.burned)
        self.assertIsNotNone(token.used_at)

    def test_list_and_cleanup_commands(self) -> None:
        active_token, _ = models.EmailAgentAuthToken.objects.issue_token(self.user)
        burned_token, burned_raw_token = models.EmailAgentAuthToken.objects.issue_token(self.user)
        models.EmailAgentAuthToken.objects.validate_and_burn(burned_raw_token)

        list_out = StringIO()
        call_command("emailagenttoken", "list", "-u", "dana", "-f", "json", stdout=list_out)
        payload = json.loads(list_out.getvalue())
        self.assertEqual(2, len(payload))
        self.assertEqual({active_token.token, burned_token.token}, {item["token"] for item in payload})

        call_command("emailagenttoken", "cleanup", "-u", "dana")
        self.assertTrue(models.EmailAgentAuthToken.objects.filter(pk=active_token.pk).exists())
        self.assertFalse(models.EmailAgentAuthToken.objects.filter(pk=burned_token.pk).exists())


class PermissionsCommandTests(TestCase):
    def setUp(self) -> None:
        self.permission = models.MNApplicationPermission.objects.create(
            name="WebDAV Storage Jonas",
            permission_name="webdav-storage-jonas",
        )
        models.MNApplicationPermission.objects.create(
            name="Calendar Access",
            permission_name="calendar-access",
        )

    def test_list_can_filter_by_permission_name_in_json_output(self) -> None:
        out = StringIO()
        with redirect_stdout(out):
            call_command("permissions", "list", "--filter-permission", "storage-jonas", "--format", "json")

        payload = json.loads(out.getvalue())
        self.assertEqual(1, len(payload))
        self.assertEqual(self.permission.permission_name, payload[0]["permission_name"])
        self.assertEqual(self.permission.name, payload[0]["name"])

    def test_list_can_filter_by_name_in_json_output(self) -> None:
        out = StringIO()
        with redirect_stdout(out):
            call_command("permissions", "list", "--filter-name", "WebDAV", "--format", "json")

        payload = json.loads(out.getvalue())
        self.assertEqual(1, len(payload))
        self.assertEqual(self.permission.permission_name, payload[0]["permission_name"])


class OAuth2CommandTests(TestCase):
    def setUp(self) -> None:
        self.app = models.MNApplication.objects.create(
            name="testclient",
            client_type=models.MNApplication.CLIENT_CONFIDENTIAL,
            authorization_grant_type=models.MNApplication.GRANT_AUTHORIZATION_CODE,
            redirect_uris="https://client.example.com/callback",
        )

    def test_list_all(self) -> None:
        out = StringIO()
        with redirect_stdout(out):
            call_command("oauth2", "list")
        self.assertIn("testclient", out.getvalue())
        self.assertIn(self.app.client_id, out.getvalue())

    def test_list_search_by_client_name(self) -> None:
        out = StringIO()
        with redirect_stdout(out):
            call_command("oauth2", "list", "--search-client-name", "testclient")
        self.assertIn(self.app.client_id, out.getvalue())

    def test_list_search_by_client_id(self) -> None:
        out = StringIO()
        with redirect_stdout(out):
            call_command("oauth2", "list", "--search-client-id", self.app.client_id)
        self.assertIn("testclient", out.getvalue())

    def test_list_search_by_client_name_not_found(self) -> None:
        out = StringIO()
        err = StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            call_command("oauth2", "list", "--search-client-name", "does-not-exist")
        self.assertNotIn(self.app.client_id, out.getvalue())
        self.assertIn("Client name not found", err.getvalue())
