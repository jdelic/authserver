from django.conf.urls import url, include
from django.contrib import admin
from django.contrib.auth import views as authviews


def ec():
    from django.conf import settings
    extra_context = {
        "company_name": settings.COMPANY_NAME,
        "company_logo": settings.COMPANY_LOGO_URL,
    }
    return extra_context

urlpatterns = [
    url(r"^action/login/$", authviews.login, name="authserver-login"),
    url(r"^action/logout/$", authviews.logout),
    url(r"^action/password_change/$", authviews.password_change),
    url(r"^action/password_change/done/$", authviews.password_change_done),
    url(r"^action/password_reset/$", authviews.password_reset),
    url(r"^action/password_reset/done/$", authviews.password_change_done),
    url(r"^action/reset/(?P<uidb64>[0-9A-Za-z_\-]+)/(?P<token>[0-9A-Za-z]{1,13}-[0-9A-Za-z]{1,20})/$",
        authviews.password_reset_confirm),
    url(r"^action/reset/done/", authviews.password_reset_complete),
    url(r"^admin/", admin.site.urls),
    url(r"^o2/", include("oauth2_provider.urls", namespace="oauth2_provider")),
    url(r"^cas/", include("mama_cas.urls")),
]
