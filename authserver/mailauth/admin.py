# -* encoding: utf-8 *-
import django.contrib.auth.admin as auth_admin
from django.contrib import admin

from mailauth.forms import MNUserChangeForm, MNUserCreationForm
from mailauth.models import MNUser, Domain, EmailAlias


@admin.register(MNUser)
class MNUserAdmin(auth_admin.UserAdmin):
    # overwrite all the fields
    fieldsets = (
        (None, {'fields': ('identifier', 'password')}),
        ("Personal info", {'fields': ('firstname', 'lastname')}),
        ("Permissions", {'fields': ('is_active', 'is_staff', 'is_superuser',
                                       'groups', 'user_permissions')}),
        ("Important dates", {'fields': ('last_login',)}),
    )
    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('identifier', 'password1', 'password2'),
        }),
    )
    form = MNUserChangeForm
    add_form = MNUserCreationForm
    change_password_form = auth_admin.AdminPasswordChangeForm
    list_display = ('identifier', 'fullname', 'is_staff')
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
