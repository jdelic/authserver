from django.contrib.auth import SESSION_KEY
from django.test import TestCase
from django.urls import reverse

from authserver.middleware import ROBOTS_POLICY
from authserver.selfservice_forms import EmailAliasCreateForm
from authserver.selfservice_views import SERVICE_USER_SESSION_KEY
from mailauth import models


class SelfServiceViewTests(TestCase):
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
        self.secondary_alias = models.EmailAlias.objects.create(
            mailprefix="projects",
            domain=self.domain,
            user=self.user,
        )
        self.user.delivery_mailbox = self.alias
        self.user.save()

        self.staff_user = models.MNUser.objects.create_user(
            identifier="admin",
            fullname="Admin User",
            password="secret",
            is_staff=True,
        )

        self.service_user = models.MNServiceUser.objects.create(
            user=self.user,
            username="svc-alice",
            description="Calendar sync",
        )
        self.service_user.set_password("svc-secret")
        self.service_user.save()

        self.application = models.MNApplication.objects.create(
            name="Calendar Gateway",
            client_type="public",
            authorization_grant_type="authorization-code",
            redirect_uris="https://calendar.example.com/callback",
        )

    def test_root_for_anonymous_user_renders_login_page(self) -> None:
        response = self.client.get("/")
        self.assertEqual(200, response.status_code)
        self.assertContains(response, "Identity, aliases, and self-service in one place.")
        self.assertContains(response, "Self-service portal")
        self.assertContains(response, "Email or admin ID")
        self.assertEqual(response.headers["X-Robots-Tag"], ROBOTS_POLICY)
        self.assertContains(response, 'name="robots"', html=False)

    def test_robots_txt_disallows_all_crawlers(self) -> None:
        response = self.client.get("/robots.txt")
        self.assertEqual(200, response.status_code)
        self.assertEqual(response.headers["Content-Type"], "text/plain; charset=utf-8")
        self.assertEqual(response.headers["X-Robots-Tag"], ROBOTS_POLICY)
        self.assertEqual(response.content.decode("utf-8"), "User-agent: *\nDisallow: /\n")

    def test_login_page_shows_oidc_application_context(self) -> None:
        response = self.client.get(
            reverse("authserver-login"),
            {
                "next": f"/o2/authorize/?client_id={self.application.client_id}&response_type=code",
            },
        )
        self.assertEqual(200, response.status_code)
        self.assertContains(response, "Calendar Gateway")
        self.assertContains(response, "OpenID Connect")

    def test_root_for_staff_user_redirects_to_admin(self) -> None:
        self.client.force_login(self.staff_user)
        response = self.client.get("/")
        self.assertRedirects(response, "/admin/")

    def test_root_for_regular_user_renders_dashboard(self) -> None:
        self.client.force_login(self.user)
        response = self.client.get("/")
        self.assertEqual(200, response.status_code)
        self.assertContains(response, "Manage your account.")
        self.assertContains(response, "projects@example.com")

    def test_alias_create_form_domains_are_sorted_and_filterable(self) -> None:
        models.Domain.objects.create(name="zeta.example")
        models.Domain.objects.create(name="alpha.example")

        form = EmailAliasCreateForm(self.user)
        self.assertEqual(
            ["alpha.example", "example.com", "zeta.example"],
            list(form.fields["domain"].queryset.values_list("name", flat=True)),
        )
        self.assertIsNone(form.fields["domain"].empty_label)
        self.assertEqual("8", form.fields["domain"].widget.attrs["size"])

        self.client.force_login(self.user)
        response = self.client.get("/")
        self.assertEqual(200, response.status_code)
        self.assertContains(response, 'data-domain-filter')
        self.assertContains(response, 'data-domain-summary')
        self.assertNotContains(response, "---------")

    def test_service_user_cannot_login_to_self_service(self) -> None:
        response = self.client.post(
            reverse("authserver-login"),
            {
                "username": "svc-alice",
                "password": "svc-secret",
                "next": "/",
            },
        )
        self.assertEqual(200, response.status_code)
        self.assertContains(response, "Service user credentials cannot access the self-service portal.")
        self.assertNotIn(SESSION_KEY, self.client.session)

    def test_service_user_can_login_for_oauth_but_is_logged_out_when_visiting_dashboard(self) -> None:
        response = self.client.post(
            reverse("authserver-login"),
            {
                "username": "svc-alice",
                "password": "svc-secret",
                "next": "/o2/authorize/",
            },
        )
        self.assertRedirects(response, "/o2/authorize/", fetch_redirect_response=False)
        self.assertTrue(self.client.session.get(SERVICE_USER_SESSION_KEY))

        dashboard_response = self.client.get("/", follow=True)
        self.assertEqual(200, dashboard_response.status_code)
        self.assertContains(dashboard_response, "Service user credentials cannot access the self-service portal or Django admin.")
        self.assertNotIn(SESSION_KEY, self.client.session)

    def test_service_user_cannot_login_to_admin(self) -> None:
        response = self.client.post(
            "/admin/login/",
            {
                "username": "svc-alice",
                "password": "svc-secret",
                "next": "/admin/",
            },
        )
        self.assertEqual(200, response.status_code)
        self.assertContains(response, "Service user credentials cannot access Django admin.")
        self.assertNotIn(SESSION_KEY, self.client.session)

    def test_user_can_create_block_and_delete_aliases(self) -> None:
        self.client.force_login(self.user)

        create_response = self.client.post(
            reverse("selfservice-alias-create"),
            {
                "mailprefix": "alerts",
                "domain": self.domain.pk,
            },
        )
        self.assertRedirects(create_response, reverse("selfservice-dashboard"))
        alias = models.EmailAlias.objects.get(mailprefix="alerts", domain=self.domain)
        self.assertEqual(self.user, alias.user)

        block_response = self.client.post(reverse("selfservice-alias-block", args=[alias.id]))
        self.assertRedirects(block_response, reverse("selfservice-dashboard"))
        alias.refresh_from_db()
        self.assertTrue(alias.blacklisted)

        delete_response = self.client.post(reverse("selfservice-alias-delete", args=[alias.id]))
        self.assertRedirects(delete_response, reverse("selfservice-dashboard"))
        self.assertFalse(models.EmailAlias.objects.filter(pk=alias.pk).exists())

    def test_user_can_convert_alias_to_mailing_list_and_back(self) -> None:
        self.client.force_login(self.user)

        convert_response = self.client.post(
            reverse("selfservice-alias-convert-mailing-list", args=[self.secondary_alias.id]),
            {
                "name": "Projects list",
                "addresses": "ops@example.net\nalerts@example.net",
                "new_mailfrom": "lists@example.com",
            },
        )
        self.assertRedirects(convert_response, reverse("selfservice-dashboard"))
        self.secondary_alias.refresh_from_db()
        self.assertIsNone(self.secondary_alias.user)
        self.assertEqual(self.user, self.secondary_alias.forward_to.owner)
        self.assertEqual(["ops@example.net", "alerts@example.net"], self.secondary_alias.forward_to.addresses)

        back_response = self.client.post(
            reverse("selfservice-mailing-list-convert-alias", args=[self.secondary_alias.id]),
        )
        self.assertRedirects(back_response, reverse("selfservice-dashboard"))
        self.secondary_alias.refresh_from_db()
        self.assertEqual(self.user, self.secondary_alias.user)
        self.assertIsNone(self.secondary_alias.forward_to)

    def test_user_can_bulk_block_unblock_and_delete_aliases(self) -> None:
        self.client.force_login(self.user)

        third_alias = models.EmailAlias.objects.create(
            mailprefix="alerts",
            domain=self.domain,
            user=self.user,
        )

        block_response = self.client.post(
            reverse("selfservice-alias-bulk"),
            {
                "action": "block",
                "alias_ids": [self.secondary_alias.id, third_alias.id],
            },
        )
        self.assertRedirects(block_response, reverse("selfservice-dashboard"))
        self.secondary_alias.refresh_from_db()
        third_alias.refresh_from_db()
        self.assertTrue(self.secondary_alias.blacklisted)
        self.assertTrue(third_alias.blacklisted)

        unblock_response = self.client.post(
            reverse("selfservice-alias-bulk"),
            {
                "action": "unblock",
                "alias_ids": [self.secondary_alias.id, third_alias.id],
            },
        )
        self.assertRedirects(unblock_response, reverse("selfservice-dashboard"))
        self.secondary_alias.refresh_from_db()
        third_alias.refresh_from_db()
        self.assertFalse(self.secondary_alias.blacklisted)
        self.assertFalse(third_alias.blacklisted)

        delete_response = self.client.post(
            reverse("selfservice-alias-bulk"),
            {
                "action": "delete",
                "alias_ids": [self.alias.id, self.secondary_alias.id, third_alias.id],
            },
            follow=True,
        )
        self.assertEqual(200, delete_response.status_code)
        self.assertContains(delete_response, "Deleted 2 aliases.")
        self.assertContains(delete_response, "Skipped 1 primary delivery alias.")
        self.assertTrue(models.EmailAlias.objects.filter(pk=self.alias.pk).exists())
        self.assertFalse(models.EmailAlias.objects.filter(pk=self.secondary_alias.pk).exists())
        self.assertFalse(models.EmailAlias.objects.filter(pk=third_alias.pk).exists())

    def test_user_can_create_and_delete_service_users(self) -> None:
        self.client.force_login(self.user)

        create_response = self.client.post(
            reverse("selfservice-service-user-create"),
            {
                "username": "svc-new",
                "password": "password-12345",
                "description": "CardDAV sync",
            },
            follow=True,
        )
        self.assertEqual(200, create_response.status_code)
        self.assertContains(create_response, "Created service user svc-new. Password: password-12345")
        service_user = models.MNServiceUser.objects.get(username="svc-new")

        delete_response = self.client.post(
            reverse("selfservice-service-user-delete", args=[service_user.id]),
        )
        self.assertRedirects(delete_response, reverse("selfservice-dashboard"))
        self.assertFalse(models.MNServiceUser.objects.filter(pk=service_user.pk).exists())
