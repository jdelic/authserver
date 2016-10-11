# -* encoding: utf-8 *-
from typing import Tuple

import django.contrib.auth.admin as auth_admin
from django.contrib import admin
from django.core import urlresolvers
from django.utils.html import format_html

from mailauth.forms import MNUserChangeForm, MNUserCreationForm
from mailauth.models import MNUser, Domain, EmailAlias


@admin.register(MNUser)
class MNUserAdmin(auth_admin.UserAdmin):
    # overwrite all the fields
    fieldsets = (
        (None, {'fields': ('identifier', 'password')}),
        ("Personal info", {'fields': ('fullname', 'delivery_mailbox', 'pgp_key_id', 'yubikey_serial', )}),
        ("Permissions", {'fields': ('is_active', 'is_staff', 'is_superuser',
                                    'groups', 'user_permissions')}),
        ("Important dates", {'fields': ('last_login',)}),
    )  # type: Tuple
    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('identifier', 'password1', 'password2'),
        }),
    )  # type: Tuple
    form = MNUserChangeForm
    add_form = MNUserCreationForm
    change_password_form = auth_admin.AdminPasswordChangeForm
    list_display = ('identifier', 'fullname', 'delivery_mailbox', 'is_staff', )
    list_filter = ('is_staff', 'is_superuser', 'is_active', 'groups')
    search_fields = ('identifier', 'fullname')
    ordering = ('identifier',)
    filter_horizontal = ('groups', 'user_permissions',)


@admin.register(Domain)
class DomainAdmin(admin.ModelAdmin):
    search_fields = ('name',)


@admin.register(EmailAlias)
class EmailAliasAdmin(admin.ModelAdmin):
    search_fields = ('mailprefix', 'domain__name',)

    def get_user(self, obj: EmailAlias) -> str:
        return format_html(
            "<a href=\"{}\">{}</a>",
            urlresolvers.reverse('admin:mailauth_mnuser_change', args=[obj.user.uuid]),
            obj.user.identifier,
        )
    get_user.short_description = "User"  # type: ignore  (mypy#708)
    get_user.admin_order_field = 'user__uuid'  # type: ignore  (mypy#708)

    def get_mailalias(self, obj: EmailAlias) -> str:
        return "%s@%s" % (obj.mailprefix, obj.domain.name)
    get_mailalias.short_description = "Mail alias"  # type: ignore  (mypy#708)

    list_display = ('get_mailalias', 'get_user',)
