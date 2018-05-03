# -* encoding: utf-8 *-
from typing import Any, Union, Tuple, Dict, Optional

import django.contrib.auth.admin as auth_admin

from django import forms
from django.contrib import admin, messages
from django.contrib.admin.templatetags.admin_urls import add_preserved_filters
from django.core import urlresolvers
from django.http import HttpResponse, HttpResponseRedirect
from django.http.request import HttpRequest
from django.urls import reverse
from django.utils.encoding import force_text
from django.utils.html import format_html
from django.utils.http import urlquote
from django.utils.translation import gettext_lazy as _

from oauth2_provider.admin import ApplicationAdmin
from oauth2_provider.models import get_application_model

from mailauth.forms import MNUserChangeForm, MNUserCreationForm, DomainForm, MailingListForm, \
    MNServiceUserCreationForm, MNServiceUserChangeForm
from mailauth.models import MNUser, Domain, EmailAlias, MNApplicationPermission, MNGroup, MNApplication, MailingList, \
    MNServiceUser
from mailauth.utils import generate_rsa_key

admin.site.unregister(auth_admin.Group)


@admin.register(MNServiceUser)
class MNServiceUserAdmin(admin.ModelAdmin):
    form = MNServiceUserChangeForm
    add_form = MNServiceUserCreationForm
    list_display = ('user', 'username', 'description',)
    list_filter = ('user',)
    search_fields = ('user', 'username', 'description',)
    ordering = ('user',)

    fields = ['username', 'password', 'description', 'user']

    def get_form(self, request: HttpRequest, obj: forms.ModelForm=None, **kwargs: Any) -> forms.ModelForm:
        """
        Use special form during user creation
        """
        defaults = {}
        if obj is None:
            defaults['form'] = self.add_form
        defaults.update(kwargs)
        return super().get_form(request, obj, **defaults)

    def formfield_for_foreignkey(self, db_field: forms.BoundField, request: HttpRequest, **kwargs: Any) -> forms.Field:
        if db_field.name == "user":
            kwargs['queryset'] = MNUser.objects.exclude(delivery_mailbox__isnull=True)
        return super().formfield_for_foreignkey(db_field, request, **kwargs)


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

    def response_add(self, request: HttpRequest, obj: Domain, post_url_continue: str=None) -> \
            HttpResponse:
        opts = self.model._meta
        pk_value = obj._get_pk_val()
        preserved_filters = self.get_preserved_filters(request)

        msg_dict = {
            'name': force_text(opts.verbose_name),
            'obj': format_html('<a href="{}">{}</a>', urlquote(request.path), obj),
        }
        obj_url = reverse(
            'admin:%s_%s_change' % (opts.app_label, opts.model_name),
            args=(urlquote(pk_value),),
            current_app=self.admin_site.name,
        )

        for key in request.POST.keys():
            if key.startswith("_genkey-"):
                if hasattr(obj, key[len("_genkey-"):]):
                    setattr(obj, key[len("_genkey-"):], generate_rsa_key(2048).private_key)
                    obj.save()
                    msg = format_html(
                        _('The {name} "{obj}" was changed successfully. You may edit it again below.'),
                        **msg_dict
                    )
                    self.message_user(request, msg, messages.SUCCESS)
                    if post_url_continue is None:
                        post_url_continue = obj_url
                    post_url_continue = add_preserved_filters(
                        {'preserved_filters': preserved_filters, 'opts': opts},
                        post_url_continue
                    )
                    return HttpResponseRedirect(post_url_continue)
        return super().response_add(request, obj, post_url_continue)

    def response_change(self, request: HttpRequest, obj: Domain) -> HttpResponse:
        opts = self.model._meta
        pk_value = obj._get_pk_val()
        preserved_filters = self.get_preserved_filters(request)

        msg_dict = {
            'name': force_text(opts.verbose_name),
            'obj': format_html('<a href="{}">{}</a>', urlquote(request.path), obj),
        }
        for key in request.POST.keys():
            if key.startswith("_genkey-"):
                if hasattr(obj, key[len("_genkey-"):]):
                    setattr(obj, key[len("_genkey-"):], generate_rsa_key(2048).private_key)
                    obj.save()
                    msg = format_html(
                        _('The {name} "{obj}" was changed successfully. You may edit it again below.'),
                        **msg_dict
                    )
                    self.message_user(request, msg, messages.SUCCESS)
                    redirect_url = request.path
                    redirect_url = add_preserved_filters({'preserved_filters': preserved_filters, 'opts': opts},
                                                         redirect_url)
                    return HttpResponseRedirect(redirect_url)

        return super().response_change(request, obj)


@admin.register(MailingList)
class MailingListAdmin(admin.ModelAdmin):
    form = MailingListForm
    search_fields = ('name', 'addresses',)
    list_display = ('name', 'addresses',)


@admin.register(EmailAlias)
class EmailAliasAdmin(admin.ModelAdmin):
    search_fields = ('mailprefix', 'domain__name',)

    def get_user(self, obj: EmailAlias) -> str:
        if obj.user is not None:
            ret = format_html(
                "<a href=\"{}\">{}</a>",
                urlresolvers.reverse('admin:mailauth_mnuser_change', args=[obj.user.uuid]),
                obj.user.identifier,
            )
        elif obj.forward_to is not None:
            ret = format_html(
                "<a href=\"{}\">{}</a>",
                urlresolvers.reverse('admin:mailauth_mailinglist_change', args=[obj.forward_to.id]),
                obj.forward_to.name,
            )
        return ret
    get_user.short_description = "Owner / Mailing List"  # type: ignore  # (mypy#708)
    get_user.admin_order_field = 'user_id'  # type: ignore  # (mypy#708)

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
