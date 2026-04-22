from typing import Callable

from django.contrib import messages
from django.contrib.auth import logout
from django.http import HttpRequest, HttpResponse
from django.shortcuts import redirect

from authserver.selfservice_views import SERVICE_USER_SESSION_KEY


class ServiceUserSessionGuardMiddleware:
    def __init__(self, get_response: Callable[[HttpRequest], HttpResponse]) -> None:
        self.get_response = get_response

    def __call__(self, request: HttpRequest) -> HttpResponse:
        if (
            request.user.is_authenticated
            and request.session.get(SERVICE_USER_SESSION_KEY)
            and not request.path.startswith("/o2/")
            and request.path != "/action/logout/"
        ):
            messages.error(
                request,
                "Service user credentials cannot access the self-service portal or Django admin.",
            )
            logout(request)
            return redirect("/")

        return self.get_response(request)


class SearchEngineBlockMiddleware:
    def __init__(self, get_response: Callable[[HttpRequest], HttpResponse]) -> None:
        self.get_response = get_response

    def __call__(self, request: HttpRequest) -> HttpResponse:
        response = self.get_response(request)
        response.headers.setdefault(
            "X-Robots-Tag", "noindex, nofollow, noarchive, nosnippet, noimageindex, "
            "notranslate, max-image-preview:none, max-snippet:0, max-video-preview:0"
        )
        return response
