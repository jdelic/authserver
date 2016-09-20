# -* encoding: utf-8 *-
#
# The forms in here are hooked up to Django admin via mailauth.admin
#
import django.contrib.auth.forms as auth_forms

from django.utils.text import ugettext_lazy as _
from typing import Any

from mailauth.models import MNUser


class MNUserCreationForm(auth_forms.UserCreationForm):
    class Meta:
        model = MNUser
        fields = ('identifier',)
        field_classes = {'identifier': auth_forms.UsernameField}


class MNUserChangeForm(auth_forms.UserChangeForm):
    def __init__(self, *args: Any, **kwargs: Any):
        super().__init__(*args, **kwargs)

    class Meta:
        model = MNUser
        fields = '__all__'
        field_classes = {'identifier': auth_forms.UsernameField}
