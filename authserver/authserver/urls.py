from django.urls import path, re_path, include
from django.contrib import admin
from django.contrib.auth import views as auth_views

from oauth2_provider import views as oauth2_views
from oauth2_provider.views import oidc as oidc_views
from authserver import base_views
from authserver import selfservice_views
from mailauth import views as mail_views
from dockerauth import views as docker_views
from authserver import views as shared_views


oauth2_patterns = ([
    # manually assign oauth2 views instead of importing them since we override the authorize view
    re_path(r'^authorize/$', mail_views.ScopeValidationAuthView.as_view(), name='authorize'),
    re_path(r'^token/$', oauth2_views.TokenView.as_view(), name='token'),
    re_path(r'^revoke_token/$', oauth2_views.RevokeTokenView.as_view(), name='revoke-token'),
    re_path(r'^fake-userinfo/$', mail_views.FakeUserInfoView.as_view(), name='fake-user-info'),
    re_path(r'^userinfo/$', oauth2_views.UserInfoView.as_view(), name='user-info'),
    re_path(r'^\.well-known/openid-configuration/?$', oidc_views.ConnectDiscoveryInfoView.as_view(),
            name='oidc-connect-discovery-info'),
    re_path(r"^\.well-known/jwks.json$", mail_views.JwksInfoView.as_view(), name="jwks-info")
], 'oauth2_provider')


urlpatterns = [
    re_path(r'^health/$', base_views.health),
    re_path(r'^robots\.txt$', base_views.robots_txt),
    re_path(r'^$', selfservice_views.HomeView.as_view(), name='selfservice-home'),
    re_path(r'^dashboard/$', selfservice_views.DashboardView.as_view(), name='selfservice-dashboard'),
    re_path(r'^action/login/$', selfservice_views.SelfServiceLoginView.as_view(), name='authserver-login'),
    re_path(r'^action/logout/$', selfservice_views.SelfServiceLogoutView.as_view()),
    re_path(r'^action/password_change/$', auth_views.PasswordChangeView.as_view()),
    re_path(r'^action/password_change/done/$', auth_views.PasswordChangeDoneView.as_view()),
    re_path(r'^action/password_reset/$', auth_views.PasswordResetView.as_view()),
    re_path(r'^action/password_reset/done/$', auth_views.PasswordChangeDoneView.as_view()),
    re_path(r'^action/reset/(?P<uidb64>[0-9A-Za-z_\-]+)/(?P<token>[0-9A-Za-z]{1,13}-[0-9A-Za-z]{1,20})/$',
            auth_views.PasswordResetConfirmView.as_view()),
    re_path(r'^action/reset/done/', auth_views.PasswordResetCompleteView.as_view()),
    re_path(r'^admin/', admin.site.urls),

    # Oauth2 and OpenIDC
    path('o2/', include(oauth2_patterns)),

    # Docker auth
    re_path(r'^docker/token/$', docker_views.DockerAuthView.as_view()),

    # debug
    re_path(r'^debug/error/$', base_views.test_error),

    # self-service
    path('aliases/create/', selfservice_views.EmailAliasCreateView.as_view(), name='selfservice-alias-create'),
    path('aliases/bulk/', selfservice_views.EmailAliasBulkActionView.as_view(), name='selfservice-alias-bulk'),
    path(
        'aliases/<int:alias_id>/block/',
        selfservice_views.EmailAliasBlockToggleView.as_view(blacklisted=True),
        name='selfservice-alias-block',
    ),
    path(
        'aliases/<int:alias_id>/unblock/',
        selfservice_views.EmailAliasBlockToggleView.as_view(blacklisted=False),
        name='selfservice-alias-unblock',
    ),
    path(
        'aliases/<int:alias_id>/delete/',
        selfservice_views.EmailAliasDeleteView.as_view(),
        name='selfservice-alias-delete',
    ),
    path(
        'aliases/<int:alias_id>/mailing-list/',
        selfservice_views.EmailAliasConvertToMailingListView.as_view(),
        name='selfservice-alias-convert-mailing-list',
    ),
    path(
        'mailing-lists/<int:alias_id>/',
        selfservice_views.MailingListEditView.as_view(),
        name='selfservice-mailing-list-edit',
    ),
    path(
        'mailing-lists/<int:alias_id>/convert-to-alias/',
        selfservice_views.MailingListConvertToAliasView.as_view(),
        name='selfservice-mailing-list-convert-alias',
    ),
    path(
        'mailing-lists/<int:alias_id>/delete/',
        selfservice_views.MailingListDeleteView.as_view(),
        name='selfservice-mailing-list-delete',
    ),
    path(
        'service-users/create/',
        selfservice_views.ServiceUserCreateView.as_view(),
        name='selfservice-service-user-create',
    ),
    path(
        'service-users/<int:service_user_id>/delete/',
        selfservice_views.ServiceUserDeleteView.as_view(),
        name='selfservice-service-user-delete',
    ),

    # user authentication api
    re_path(r'^checkpassword/$', mail_views.UserLoginAPIView.as_view(), name='checkpassword'),
    re_path(r'^getkey/$', shared_views.JWTPublicKeyView.as_view(), name='getkey'),
]
