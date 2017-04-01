# -* encoding: utf-8 *-
from django.db import connection
from django.db.backends.utils import CursorWrapper
from django.db.utils import DatabaseError
from django.http.request import HttpRequest
from django.http.response import HttpResponse, HttpResponseServerError


def health(request: HttpRequest) -> HttpResponse:
    c = connection.cursor()  # type: CursorWrapper
    try:
        c.execute("SELECT 1")
        res = c.fetchone()
    except DatabaseError as e:
        return HttpResponseServerError(("Health check failed: %s" % str(e)).encode("utf-8"),
                                       content_type="text/plain; charset=utf-8")
    else:
        return HttpResponse(b'All green', status=200,
                            content_type="text/plain; charset=utf-8")


def nothing(request: HttpRequest):
    return HttpResponse(b'nothing to see here', status=200,
                        content_type="text/plain; charset=utf-8")
