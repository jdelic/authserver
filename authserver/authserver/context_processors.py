# -* encoding: utf-8 *-
from typing import Dict

from django.conf import settings
from django.http.request import HttpRequest


def branding(request: HttpRequest) -> Dict[str, str]:
    return {
        "company_name": settings.COMPANY_NAME,
        "company_logo": settings.COMPANY_LOGO_URL,
    }
