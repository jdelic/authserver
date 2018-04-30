from django.conf.urls import url, include
from django.contrib import admin
from django.contrib.auth import views as auth_views

from oauth2_provider import views as oauth2_views
from authserver import base_views
from mailauth import views as mail_views
from dockerauth import views as docker_views
from authserver import views as shared_views


urlpatterns = [
    url(r"^health/$", base_views.health),
    url(r"^$", base_views.nothing),
    url(r"^action/login/$", auth_views.login, name="authserver-login"),
    url(r"^action/logout/$", auth_views.logout),
    url(r"^action/password_change/$", auth_views.password_change),
    url(r"^action/password_change/done/$", auth_views.password_change_done),
    url(r"^action/password_reset/$", auth_views.password_reset),
    url(r"^action/password_reset/done/$", auth_views.password_change_done),
    url(r"^action/reset/(?P<uidb64>[0-9A-Za-z_\-]+)/(?P<token>[0-9A-Za-z]{1,13}-[0-9A-Za-z]{1,20})/$",
        auth_views.password_reset_confirm),
    url(r"^action/reset/done/", auth_views.password_reset_complete),
    url(r"^admin/", admin.site.urls),
    url(r"^cas/", include('mama_cas.urls')),

    # manually assign oauth2 views instead of importing them since we override the authorize view
    url(r'^o2/authorize/$', mail_views.ScopeValidationAuthView.as_view(), name="authorize"),
    url(r'^o2/token/$', oauth2_views.TokenView.as_view(), name="token"),
    url(r'^o2/revoke_token/$', oauth2_views.RevokeTokenView.as_view(), name="revoke-token"),

    # Docker auth
    url(r'^docker/token/$', docker_views.DockerAuthView.as_view()),

    # debug
    url(r'^debug/error/$', base_views.test_error),

    # user authentication api
    url(r'^checkpassword/$', mail_views.UserLoginAPIView.as_view(), name="checkpassword"),
    url(r'^getkey/$', shared_views.JWTPublicKeyView.as_view(), name="getkey"),
]
