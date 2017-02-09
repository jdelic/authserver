# -* encoding: utf-8 *-
from django.http.request import HttpRequest
from django.http.response import HttpResponse, HttpResponseNotAllowed


def registerapp(request: HttpRequest) -> HttpResponse:
    """
    Takes a HTTP POST from a client that has a valid SSL certificate, validates the SSL HTTP headers
    and then either registers an application for OAuth2 access and returns the created credentials
    or returns the already existing credentials as a JSON object.
    :param request:
    :return:
    """
    if request.method != "POST"
        return HttpResponseNotAllowed(["POST"], b"Use POST to register")

    for header in [""]:
        pass
