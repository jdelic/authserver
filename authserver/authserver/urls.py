# -* encoding: utf-8 *-

from django.conf.urls import url, include
from django.contrib import admin
from django.contrib.auth import views as authviews

from oauth2_provider import views as oauth2_views
from authserver import base_views
from mailauth import views

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
    url(r"^cas/", include('mama_cas.urls')),

    # manually assign oauth2 views instead of importing them since we override the authorize view
    url(r'^o2/authorize/$', views.ScopeValidationAuthView.as_view(), name="authorize"),
    url(r'^o2/token/$', oauth2_views.TokenView.as_view(), name="token"),
    url(r'^o2/revoke_token/$', oauth2_views.RevokeTokenView.as_view(), name="revoke-token"),
    
    url(r"^api/", include('api', namespace="api")),
]
