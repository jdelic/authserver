from django.test import TestCase


class IndexPageTestCase(TestCase):
    """
    Ensure the root URL ('/') mapped to base_views.nothing
    responds with HTTP 200 OK.
    """

    def test_index_page_returns_200(self):
        response = self.client.get('/')
        self.assertEqual(response.status_code, 200)
