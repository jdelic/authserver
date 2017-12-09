from django.urls import re_path, include
from django.contrib import admin
from django.contrib.auth import views as auth_views

from oauth2_provider import views as oauth2_views
from authserver import base_views
from mailauth import views as mail_views
from dockerauth import views as docker_views


urlpatterns = [
    re_path(r"^health/$", base_views.health),
    re_path(r"^$", base_views.nothing),
    re_path(r"^action/login/$", auth_views.login, name="authserver-login"),
    re_path(r"^action/logout/$", auth_views.logout),
    re_path(r"^action/password_change/$", auth_views.password_change),
    re_path(r"^action/password_change/done/$", auth_views.password_change_done),
    re_path(r"^action/password_reset/$", auth_views.password_reset),
    re_path(r"^action/password_reset/done/$", auth_views.password_change_done),
    re_path(r"^action/reset/(?P<uidb64>[0-9A-Za-z_\-]+)/(?P<token>[0-9A-Za-z]{1,13}-[0-9A-Za-z]{1,20})/$",
        auth_views.password_reset_confirm),
    re_path(r"^action/reset/done/", auth_views.password_reset_complete),
    re_path(r"^admin/", admin.site.urls),
    re_path(r"^cas/", include('mama_cas.urls')),

    # manually assign oauth2 views instead of importing them since we override the authorize view
    re_path(r'^o2/authorize/$', mail_views.ScopeValidationAuthView.as_view(), name="authorize"),
    re_path(r'^o2/token/$', oauth2_views.TokenView.as_view(), name="token"),
    re_path(r'^o2/revoke_token/$', oauth2_views.RevokeTokenView.as_view(), name="revoke-token"),

    # Docker auth
    re_path(r'^docker/token/$', docker_views.DockerAuthView.as_view()),

    # debug
    re_path(r'^debug/error/$', base_views.test_error),
]
