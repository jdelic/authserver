# -* encoding: utf-8 *-
import functools
from typing import Type, Any
from typing import Union

import django.contrib.auth.admin as auth_admin
from Crypto.PublicKey import RSA
from django.contrib import admin
from django.core import urlresolvers
from django.db.models.fields import Field as _ModelField
from django.forms.fields import Field as _FormField
from django.http.request import HttpRequest
from django.utils.html import format_html
from typing import Tuple

from typing import Dict

from oauth2_provider.admin import ApplicationAdmin
from oauth2_provider.models import get_application_model

from mailauth.forms import MNUserChangeForm, MNUserCreationForm, DomainForm
from mailauth.models import MNUser, Domain, EmailAlias, MNApplicationPermission, MNGroup, MNApplication


admin.site.unregister(auth_admin.Group)


@admin.register(MNUser)
class MNUserAdmin(auth_admin.UserAdmin):
    # overwrite all the fields
    fieldsets = (
        (None, {'fields': ('identifier', 'password')}),
        ("Personal info", {'fields': ('fullname', 'delivery_mailbox', 'pgp_key_id', 'yubikey_serial', )}),
        ("Permissions", {'fields': ('is_active', 'is_staff', 'is_superuser',
                                    'groups', 'user_permissions')}),
        ("Application permissions", {'fields': ('app_permissions', 'app_groups',)}),
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
    filter_horizontal = ('groups', 'user_permissions', 'app_permissions', 'app_groups',)


@admin.register(Domain)
class DomainAdmin(admin.ModelAdmin):
    search_fields = ('name',)
    form = DomainForm

    def get_form(self, req: HttpRequest, obj: Domain=None, **kwargs: Any) -> type:
        if req.GET.get("_prefill_key", "0") == "1":
            def formfield_callback(field: _ModelField, request: HttpRequest=None, **kwargs: Any) -> Type[_FormField]:
                f = self.formfield_for_dbfield(field, request=request, **kwargs)  # type: _FormField
                # f can be None if the dbfield does not get a FormField (like hidden fields
                # or auto increment IDs). Only the dbfield has a .name attribute.
                if f and field.name == "dkimkey":
                    if obj:
                        obj.dkimkey = RSA.generate(2048).exportKey("PEM").decode("utf-8")
                    else:
                        f.initial = RSA.generate(2048).exportKey("PEM").decode("utf-8")
                return f

            kwargs["formfield_callback"] = functools.partial(formfield_callback, request=req)

        form_t = super().get_form(req, obj, **kwargs)
        return form_t


@admin.register(EmailAlias)
class EmailAliasAdmin(admin.ModelAdmin):
    search_fields = ('mailprefix', 'domain__name',)

    def get_user(self, obj: EmailAlias) -> str:
        return format_html(
            "<a href=\"{}\">{}</a>",
            urlresolvers.reverse('admin:mailauth_mnuser_change', args=[obj.user.uuid]),
            obj.user.identifier,
        )
    get_user.short_description = "User"  # type: ignore  # (mypy#708)
    get_user.admin_order_field = 'user__uuid'  # type: ignore  # (mypy#708)

    def get_mailalias(self, obj: EmailAlias) -> str:
        return "%s@%s" % (obj.mailprefix, obj.domain.name)
    get_mailalias.short_description = "Mail alias"  # type: ignore  # (mypy#708)

    list_display = ('get_mailalias', 'get_user',)


@admin.register(MNApplicationPermission)
class MNApplicationPermissionAdmin(admin.ModelAdmin):
    search_fields = ('name',)


@admin.register(MNGroup)
class MNGroupAdmin(admin.ModelAdmin):
    search_fields = ('name',)
    fieldsets = (
        (None, {'fields': ('name',)}),
        ("Application permissions", {'fields': ('group_permissions',)}),
    )  # type: Tuple[Tuple[Union[str, None], Dict[str, Tuple[str, ...]]], ...]
    filter_horizontal = ('group_permissions',)


class MNApplicationAdmin(ApplicationAdmin):
    filter_horizontal = ('required_permissions',)


if get_application_model() == MNApplication:
    admin.site.unregister(MNApplication)
    admin.site.register(MNApplication, MNApplicationAdmin)
