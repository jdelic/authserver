from django.conf.urls import url, include
from django.contrib import admin
from django.contrib.auth import views as authviews

from authserver import base_views

urlpatterns = [
    url(r"^health/$", base_views.health),
    url(r"^$", base_views.nothing),
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
    url(r"^o2/", include('oauth2_provider.urls', namespace="oauth2_provider")),
    url(r"^cas/", include('mama_cas.urls')),

]

# TODO: remove once https://github.com/evonove/django-oauth-toolkit/issues/196 is fixed
urlpatterns = [u for u in urlpatterns if "o2/^applications" not in u._regex]
