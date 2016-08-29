# -* encoding: utf-8 *-
import django.contrib.auth.admin as auth_admin
from django.contrib import admin

from casserver.forms import MNUserChangeForm, MNUserCreationForm
from casserver.models import MNUser


@admin.register(MNUser)
class MNUserAdmin(auth_admin.UserAdmin):
    # overwrite all the fields
    fieldsets = (
        (None, {'fields': ('identifier', 'password')}),
        (_('Personal info'), {'fields': ('firstname', 'lastname')}),
        (_('Permissions'), {'fields': ('is_active', 'is_staff', 'is_superuser',
                                       'groups', 'user_permissions')}),
        (_('Important dates'), {'fields': ('last_login', 'date_joined')}),
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
    list_display = ('identifier', 'firstname', 'lastname', 'is_staff')
    list_filter = ('is_staff', 'is_superuser', 'is_active', 'groups')
    search_fields = ('identifier', 'firstname', 'lastname')
    ordering = ('identifier',)
    filter_horizontal = ('groups', 'user_permissions',)
