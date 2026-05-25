from urllib.parse import parse_qs, urlsplit

from django.test import TestCase
from django.urls import reverse

from mailauth import models


class DomainAdminTests(TestCase):
    def setUp(self) -> None:
        self.admin_user = models.MNUser.objects.create_superuser(
            identifier="admin",
            fullname="Admin User",
            password="secret",
        )
        self.client.force_login(self.admin_user)

    def test_generate_jwt_key_from_add_popup_preserves_popup_query(self) -> None:
        response = self.client.post(
            reverse("admin:mailauth_domain_add") + "?_popup=1&_to_field=id",
            {
                "name": "example.com",
                "_popup": "1",
                "_to_field": "id",
                "_genkey-jwtkey": "Generate new key",
            },
        )

        self.assertEqual(302, response.status_code)
        domain = models.Domain.objects.get(name="example.com")
        self.assertTrue(domain.jwtkey.startswith("-----BEGIN RSA PRIVATE KEY"))
        self.assertEqual(
            reverse("admin:mailauth_domain_change", args=[domain.pk]),
            urlsplit(response.url).path,
        )
        self.assertEqual({"1"}, set(parse_qs(urlsplit(response.url).query)["_popup"]))
        self.assertEqual({"id"}, set(parse_qs(urlsplit(response.url).query)["_to_field"]))

    def test_generate_jwt_key_from_change_popup_preserves_popup_query(self) -> None:
        domain = models.Domain.objects.create(name="example.com")

        response = self.client.post(
            reverse("admin:mailauth_domain_change", args=[domain.pk]) + "?_popup=1&_to_field=id",
            {
                "name": domain.name,
                "dkimselector": domain.dkimselector,
                "_popup": "1",
                "_to_field": "id",
                "_genkey-jwtkey": "Generate new key",
            },
        )

        self.assertEqual(302, response.status_code)
        domain.refresh_from_db()
        self.assertTrue(domain.jwtkey.startswith("-----BEGIN RSA PRIVATE KEY"))
        self.assertEqual(
            reverse("admin:mailauth_domain_change", args=[domain.pk]),
            urlsplit(response.url).path,
        )
        self.assertEqual({"1"}, set(parse_qs(urlsplit(response.url).query)["_popup"]))
        self.assertEqual({"id"}, set(parse_qs(urlsplit(response.url).query)["_to_field"]))
