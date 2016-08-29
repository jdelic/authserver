# -* encoding: utf-8 *-
import django.contrib.auth.forms as auth_forms

from casserver.models import MNUser


class MNUserCreationForm(auth_forms.UserCreationForm):
    class Meta:
        model = MNUser
        fields = ('identifier',)
        field_classes = {'identifier': auth_forms.UsernameField}


class MNUserChangeForm(auth_forms.UserChangeForm):
    class Meta:
        model = MNUser
        fields = '__all__'
        field_classes = {'identifier': auth_forms.UsernameField}
