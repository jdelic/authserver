import json

from django.test import TestCase
from django.urls import reverse

from mailauth import models


class EmailAgentAuthTokenTests(TestCase):
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

    def test_issue_token_stores_digest_and_validate_and_burn_marks_it_used(self) -> None:
        token, raw_token = models.EmailAgentAuthToken.objects.issue_token(self.user)

        self.assertEqual(raw_token, token.token)
        self.assertEqual(raw_token[:12], token.token_hint)
        self.assertNotEqual(raw_token, token.token_digest)
        self.assertFalse(token.burned)
        self.assertIsNone(token.used_at)

        burned_token = models.EmailAgentAuthToken.objects.validate_and_burn(raw_token)
        self.assertIsNotNone(burned_token)
        assert burned_token is not None
        self.assertTrue(burned_token.burned)
        self.assertIsNotNone(burned_token.used_at)
        self.assertIsNone(models.EmailAgentAuthToken.objects.validate_and_burn(raw_token))

    def test_validation_endpoint_burns_token_and_returns_creator_details(self) -> None:
        token, raw_token = models.EmailAgentAuthToken.objects.issue_token(self.user)

        response = self.client.post(
            reverse("email-agent-auth-token-validate"),
            data=json.dumps({"token": raw_token}),
            content_type="application/json",
            secure=True,
        )

        self.assertEqual(200, response.status_code)
        self.assertJSONEqual(
            response.content,
            {
                "valid": True,
                "burned": True,
                "creator": {
                    "identifier": "alice",
                    "uuid": str(self.user.uuid),
                    "primary_email": "alice@example.com",
                },
                "token_hint": token.token_hint,
                "used_at": models.EmailAgentAuthToken.objects.get(pk=token.pk).used_at.isoformat(),
            },
        )

        token.refresh_from_db()
        self.assertTrue(token.burned)
        self.assertIsNotNone(token.used_at)

    def test_validation_endpoint_rejects_invalid_token(self) -> None:
        response = self.client.post(
            reverse("email-agent-auth-token-validate"),
            data=json.dumps({"token": "not-a-real-token"}),
            content_type="application/json",
            secure=True,
        )

        self.assertEqual(401, response.status_code)
        self.assertJSONEqual(response.content, {"valid": False})
