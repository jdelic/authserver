# -* encoding: utf-8 *-

from django.conf import settings


def branding(request):
    return {
        "company_name": settings.COMPANY_NAME,
        "company_logo": settings.COMPANY_LOGO_URL,
    }
