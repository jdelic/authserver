# -* encoding: utf-8 *-
from typing import Any, List

from django.http.request import HttpRequest
from django.http.response import HttpResponse
from django.shortcuts import render
from oauth2_provider.forms import AllowForm
from oauth2_provider.models import get_application_model
from oauth2_provider.views.base import AuthorizationView

from mailauth.models import MNApplication, MNUser, MNApplicationPermission


class ScopeValidationAuthView(AuthorizationView):
    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)

    def _find_missing_permissions(self, app: MNApplication, user: MNUser) -> List[MNApplicationPermission]:
        """
        returns a list of ``Permission`` objects that the user doesn't have, but that the
        app requires. Consequently, if this returns an empty list, the user is authorized
        to connect to the app.
        :param app: the application in question
        :param user: the user object of this request
        :return: a list of missing permissions or an empty list if the user has all necessary permissions
        """
        reqs = list(app.required_permissions.all())

        user_permissions = set([perm.scope_name for perm in list(user.app_permissions.all())])
        for group in user.app_groups.all():
            for perm in list(group.group_permissions.all()):
                user_permissions.add(perm.scope_name)

        missing_permissions = []
        for req in reqs:
            if req.scope_name not in user_permissions:
                missing_permissions.append(req)

        return missing_permissions

    def form_valid(self, form: AllowForm):
        """
        use the base class' form logic, but always behave like users didn't authorize the app
        if they doesn't have the permissions to do so.
        """
        app = get_application_model().get(client_id=form.cleaned_data.get('client_id'))
        missing_permissions = self._find_missing_permissions(app, self.request.user)
        if missing_permissions:
            form.cleaned_data['allow'] = False

        return super().form_valid(form)

    def get(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        # super.get will initialize self.oauth2_data and now we can do additional validation
        resp = super().get(request, *args, **kwargs)

        app = self.oauth2_data['application']  # type: MNApplication

        missing_permissions = self._find_missing_permissions(app, request.user)

        if missing_permissions:
            return render(
                request,
                "oauth2_provider/unauthorized.html",
                context={
                    "required_permissions": list(app.required_permissions.all()),
                    "missing_permissions": missing_permissions,
                }
            )

        # we have all necessary permissions, so we return the original response
        return resp
