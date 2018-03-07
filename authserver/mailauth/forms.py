# -* encoding: utf-8 *-
#
# The forms in here are hooked up to Django admin via mailauth.admin
#
import os
import re
import math
import string
from typing import Any, Dict, Sequence, Tuple, Optional, List

import django.contrib.auth.forms as auth_forms
from Crypto.PublicKey import RSA
from django import forms
from django.contrib.admin import widgets
from django.core.files.uploadedfile import UploadedFile
from django.forms.renderers import BaseRenderer
from django.utils.html import format_html
from django_select2.forms import Select2TagWidget

from mailauth.models import MNUser, Domain, MailingList, MNServiceUser


def generate_password(pass_len):
    symbols = "0123456789=-$%^&*()[]{}\\/!abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
    return ''.join([symbols[math.floor(int(x) / 256 * len(symbols))] for x in os.urandom(pass_len)])


class MNServiceUserCreationForm(forms.ModelForm):
    password = forms.CharField(
        label="Password",
        strip=False,
        help_text="This is the only time you will be able to see this password. Note it down now!",
        initial=generate_password(24)
    )

    class Meta:
        model = MNServiceUser
        fields = forms.ALL_FIELDS
        readonly_fields = ('username',)

    def save(self, commit=True):
        user = super().save(commit=False)
        user.set_password(self.cleaned_data["password"])
        if commit:
            user.save()
        return user


class MNServiceUserChangeForm(forms.ModelForm):
    password = auth_forms.ReadOnlyPasswordHashField(
        label="Password",
        help_text="Password plaintext is never stored. To get a new password, please create a new service user."
    )

    class Meta:
        model = MNServiceUser
        fields = forms.ALL_FIELDS
        readonly_fields = ('username',)

    def clean_password(self) -> str:
        # Regardless of what the user provides, return the initial value.
        # This is done here, rather than on the field, because the
        # field does not have access to the initial value
        return self.initial["password"]


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


class DomainKeyWidget(widgets.AdminTextareaWidget):
    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)

    def render(self, name: str, value: str, attrs: Optional[Dict[str, str]]=None,
               renderer: Optional[BaseRenderer]=None) -> str:
        ret = super().render(name, value, attrs)
        if value and value.startswith("-----BEGIN RSA PRIVATE KEY"):
            key = RSA.importKey(value)
            public_key = key.publickey().exportKey("PEM").decode('utf-8')
            public_key = public_key.replace("RSA PUBLIC KEY", "PUBLIC KEY")
            ret += format_html(
                """
<pre>
{public_key}</pre>
<pre>
"v=DKIM1\; k=rsa\; p=" {split_key}</pre>
                """,
                public_key=public_key,
                split_key="\n".join(
                    ['"%s"' % line for line in
                        re.search("--\n(.*?)\n--", public_key, re.DOTALL).group(1).split("\n")]
        ))
        else:
            ret += format_html("""
            <a href="?_prefill_key=1" class="button">Generate new key</a>
        """)
        return format_html("<div style=\"float: left\">{}</div>", ret)


class DomainForm(forms.ModelForm):
    class Meta:
        model = Domain
        widgets = {'dkimkey': DomainKeyWidget()}
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
