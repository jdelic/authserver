# -* encoding: utf-8 *-
from typing import Any

from django.http.request import HttpRequest
from django.http.response import HttpResponse
from oauth2_provider.views.base import AuthorizationView

from mailauth.models import MNApplication


class ScopeValidationAuthView(AuthorizationView):
    def get(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        # super.get will initialize self.oauth2_data and now we can do additional validation
        resp = super().get(request, *args, **kwargs)

        app = kwargs['application']  # type: MNApplication
        app.required_permissions.all()

        return resp
