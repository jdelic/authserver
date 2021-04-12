# -* encoding: utf-8 *-
import json

from django.conf import settings
from django.db import connection
from django.db.backends.utils import CursorWrapper
from django.db.utils import DatabaseError
from django.http.request import HttpRequest
from django.http.response import HttpResponse, HttpResponseServerError, HttpResponseRedirect

import authserver


def health(request: HttpRequest) -> HttpResponse:
    c = connection.cursor()  # type: CursorWrapper
    try:
        c.execute("SELECT 1")
        res = c.fetchone()
    except DatabaseError as e:
        return HttpResponseServerError(("Health check failed: %s" % str(e)).encode("utf-8"),
                                       content_type="text/plain; charset=utf-8")
    else:
        return HttpResponse(
            json.dumps(
                {
                    "status": "ok",
                    "error": False,
                    "version": authserver.version,
                }
            ).encode("utf-8"), status=200,
            content_type="application/json; charset=utf-8"
        )


def nothing(request: HttpRequest) -> HttpResponse:
    return HttpResponse(b'nothing to see here', status=200,
                        content_type="text/plain; charset=utf-8")


def test_error(request: HttpRequest) -> HttpResponse:
    if settings.DEBUG:
        raise Exception("This is a test")
    else:
        return HttpResponseRedirect("/")
