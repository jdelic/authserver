# -* encoding: utf-8 *-
#
# The forms in here are hooked up to Django admin via mailauth.admin
#
import os
import re
import math
import uuid
from typing import Any, Dict, Sequence, Tuple, Optional, List, cast, Match

import django.contrib.auth.forms as auth_forms

from django import forms
from django.contrib.admin import widgets
from django.core.exceptions import ValidationError
from django.core.files.uploadedfile import UploadedFile
from django.forms.renderers import BaseRenderer
from django.utils.html import format_html
from django_select2.forms import Select2TagWidget

from mailauth.models import MNUser, Domain, MailingList, MNServiceUser
from mailauth.utils import import_rsa_key


def generate_password(pass_len: int) -> str:
    symbols = "0123456789=-$%^&*()[]{}\\/!abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
    return ''.join([symbols[int(math.floor(int(x) / 256 * len(symbols)))] for x in os.urandom(pass_len)])


class DisplayHiddenInput(forms.HiddenInput):
    template_name = "display_hidden_input.html"

    @property
    def is_hidden(self) -> bool:
        return False


class MNServiceUserCreationForm(forms.ModelForm):
    username = forms.CharField(widget=DisplayHiddenInput, initial=uuid.uuid4)
    password = forms.CharField(
        label="Password",
        strip=False,
        help_text="This is the only time you will be able to see this password. Note it down now!",
        initial=lambda: generate_password(24)
    )

    class Meta:
        model = MNServiceUser
        fields = forms.ALL_FIELDS

    def save(self, commit: bool=True) -> 'MNUser':
        user = super().save(commit=False)
        user.set_password(self.cleaned_data["password"])
        if commit:
            user.save()
        return user

    def clean_username(self) -> str:
        # make sure nobody edits the hidden input field
        try:
            parsed = uuid.UUID(self.cleaned_data["username"], version=4)
        except ValueError:
            raise ValidationError("Username must be a valid UUID4. Stop editing the hidden field.")
        return self.cleaned_data["username"]


class MNServiceUserChangeForm(forms.ModelForm):
    password = auth_forms.ReadOnlyPasswordHashField(
        label="Password",
        help_text="Password plaintext is never stored. To get a new password, please create a new service user."
    )

    class Meta:
        model = MNServiceUser
        fields = forms.ALL_FIELDS

    def clean_password(self) -> str:
        # Regardless of what the user provides, return the initial value.
        # This is done here, rather than on the field, because the
        # field does not have access to the initial value
        return self.initial["password"]

    def clean_username(self) -> str:
        # make sure nobody edits the hidden input field
        try:
            parsed = uuid.UUID(self.cleaned_data["username"], version=4)
        except ValueError:
            raise ValidationError("Username must be a valid UUID4.")
        return self.cleaned_data["username"]


class MNUserCreationForm(auth_forms.UserCreationForm):
    class Meta:
        model = MNUser
        fields = ('identifier',)
        field_classes = {'identifier': auth_forms.UsernameField}


class MNUserChangeForm(auth_forms.UserChangeForm):
    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)

    class Meta:
        model = MNUser
        fields = forms.ALL_FIELDS
        field_classes = {'identifier': auth_forms.UsernameField}


class RSAKeyWidget(widgets.AdminTextareaWidget):
    def __init__(self, *args: Any, show_dkim: bool=False, **kwargs: Any) -> None:
        self.show_dkim = show_dkim
        super().__init__(*args, **kwargs)

    def render(self, name: str, value: str, attrs: Optional[Dict[str, str]]=None,
               renderer: Optional[BaseRenderer]=None) -> str:
        ret = super().render(name, value, attrs)
        if value and value.startswith("-----BEGIN RSA PRIVATE KEY"):
            public_key = import_rsa_key(value).public_key

            ret += format_html(
                """
<pre>
{public_key}</pre>""",
                public_key=public_key)
            if self.show_dkim:
                ret += format_html("""
<pre>
"v=DKIM1\; k=rsa\; p=" {split_key}</pre>
                """,
                    split_key="\n".join(
                        ['"%s"' % line for line in
                            cast(Match[str], re.search("--\n(.*?)\n--", public_key, re.DOTALL)).group(1).split("\n")])
                )  # the cast tells mypy that re.search will not return None here
        else:
            ret += format_html("""
            <input type="submit" name="_genkey-{name}" value="Generate&nbsp;new&nbsp;key" class="button"/>
        """, name=name)
        return format_html("<div style=\"float: left\">{}</div>", ret)


class DomainForm(forms.ModelForm):
    class Meta:
        model = Domain
        widgets = {
            'dkimkey': RSAKeyWidget(show_dkim=True),
            'jwtkey': RSAKeyWidget(),
        }
        fields = forms.ALL_FIELDS


class ArrayFieldWidget(Select2TagWidget):
    def value_from_datadict(self, data: Dict[str, str], files: Dict[str, UploadedFile], name: str) -> str:
        values = super().value_from_datadict(data, files, name)
        return ",".join(values)

    def optgroups(self, name: str, value: Sequence[str], attrs: Dict[str, str]=None) -> \
            List[Tuple[Optional[str], List[Dict[str, str]], int]]:
        values = value[0].split(',') if value[0] else []
        selected = set(values)
        subgroup = [self.create_option(name, v, v, selected, i) for i, v in enumerate(values)]
        return [(None, subgroup, 0)]


class MailingListForm(forms.ModelForm):
    class Meta:
        model = MailingList
        widgets = {'addresses': ArrayFieldWidget(attrs={"style": "width: 750px"})}
        fields = forms.ALL_FIELDS
