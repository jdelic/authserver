import uuid
from typing import Optional
from urllib.parse import urlsplit

from django import forms
from django.contrib.admin.forms import AdminAuthenticationForm
from django.contrib.auth import hashers
from django.contrib.auth.forms import AuthenticationForm
from django.core.exceptions import ValidationError
from django.utils.translation import gettext_lazy as _

from mailauth.forms import generate_password
from mailauth.models import Domain, EmailAlias, MailingList, MNServiceUser, MNUser


FORM_CONTROL_CLASSES = "form-control"
TEXTAREA_CLASSES = "form-control form-textarea"


def add_form_control_style(field: forms.Field) -> None:
    existing = field.widget.attrs.get("class", "")
    field.widget.attrs["class"] = f"{existing} {FORM_CONTROL_CLASSES}".strip()


def add_textarea_style(field: forms.Field) -> None:
    existing = field.widget.attrs.get("class", "")
    field.widget.attrs["class"] = f"{existing} {TEXTAREA_CLASSES}".strip()


def get_matching_service_user(username: str, password: str) -> Optional[MNServiceUser]:
    if not username or not password:
        return None

    try:
        service_user = MNServiceUser.objects.select_related("user").get(username=username)
    except MNServiceUser.DoesNotExist:
        return None

    if hashers.check_password(password, service_user.password):
        return service_user
    return None


class ServiceUserAwareAuthenticationMixin:
    redirect_field_name = "next"
    service_user: Optional[MNServiceUser]

    def __init__(self, *args: object, **kwargs: object) -> None:
        super().__init__(*args, **kwargs)  # type: ignore[misc]
        self.service_user = None

    def allow_service_user_login(self) -> bool:
        return False

    def get_blocked_login_message(self) -> str:
        return _("Service user credentials cannot be used here.")

    def get_requested_path(self) -> str:
        next_url = ""
        if hasattr(self, "data"):
            next_url = self.data.get(self.redirect_field_name, "")  # type: ignore[assignment]
        return urlsplit(next_url).path

    def clean(self) -> dict[str, str]:
        cleaned_data = super().clean()  # type: ignore[misc]
        username = cleaned_data.get("username", "")
        password = cleaned_data.get("password", "")

        self.service_user = get_matching_service_user(username, password)
        if self.service_user is not None and not self.allow_service_user_login():
            raise forms.ValidationError(self.get_blocked_login_message(), code="invalid_login")
        return cleaned_data


class SelfServiceAuthenticationForm(ServiceUserAwareAuthenticationMixin, AuthenticationForm):
    username = forms.CharField(
        label="Email or admin ID",
        widget=forms.TextInput(
            attrs={
                "autofocus": True,
                "autocomplete": "username",
                "placeholder": "alice@example.com or admin-id",
            }
        ),
    )

    def __init__(self, *args: object, **kwargs: object) -> None:
        super().__init__(*args, **kwargs)
        add_form_control_style(self.fields["username"])
        add_form_control_style(self.fields["password"])
        self.fields["password"].widget.attrs["placeholder"] = "Password"

    def allow_service_user_login(self) -> bool:
        return self.get_requested_path().startswith("/o2/")

    def get_blocked_login_message(self) -> str:
        return _("Service user credentials cannot access the self-service portal.")


class SelfServiceAdminAuthenticationForm(ServiceUserAwareAuthenticationMixin, AdminAuthenticationForm):
    def clean(self) -> dict[str, str]:
        username = self.data.get("username", "")
        password = self.data.get("password", "")
        self.service_user = get_matching_service_user(username, password)
        if self.service_user is not None:
            raise forms.ValidationError(self.get_blocked_login_message(), code="invalid_login")
        return super().clean()

    def get_blocked_login_message(self) -> str:
        return _("Service user credentials cannot access Django admin.")


class EmailAliasCreateForm(forms.ModelForm):
    class Meta:
        model = EmailAlias
        fields = ("mailprefix", "domain")

    def __init__(self, user: MNUser, *args: object, **kwargs: object) -> None:
        self.user = user
        super().__init__(*args, **kwargs)
        self.fields["domain"].queryset = Domain.objects.order_by("name")
        self.fields["mailprefix"].help_text = "Enter the part before the @ sign."
        self.fields["mailprefix"].widget.attrs["placeholder"] = "team"
        add_form_control_style(self.fields["mailprefix"])
        add_form_control_style(self.fields["domain"])

    def clean(self) -> dict[str, object]:
        self.instance.user = self.user
        self.instance.forward_to = None
        self.instance.blacklisted = False
        return super().clean()

    def save(self, commit: bool = True) -> EmailAlias:
        alias = super().save(commit=False)
        alias.user = self.user
        alias.forward_to = None
        alias.blacklisted = False
        if commit:
            alias.save()
        return alias


class MailingListSettingsForm(forms.Form):
    name = forms.CharField(max_length=255)
    addresses = forms.CharField(widget=forms.Textarea)
    new_mailfrom = forms.EmailField(required=False)

    def __init__(self, *args: object, **kwargs: object) -> None:
        super().__init__(*args, **kwargs)
        self.fields["name"].widget.attrs["placeholder"] = "Operations list"
        self.fields["addresses"].help_text = "Enter one recipient per line or separate addresses with commas."
        self.fields["addresses"].widget.attrs["placeholder"] = "ops@example.com\nalerts@example.net"
        self.fields["new_mailfrom"].widget.attrs["placeholder"] = "Optional rewritten From address"
        add_form_control_style(self.fields["name"])
        add_form_control_style(self.fields["new_mailfrom"])
        add_textarea_style(self.fields["addresses"])

    def clean_addresses(self) -> list[str]:
        raw_value = self.cleaned_data["addresses"]
        tokens = [part.strip() for chunk in raw_value.splitlines() for part in chunk.split(",")]
        addresses = [item for item in tokens if item]
        if not addresses:
            raise ValidationError("Please provide at least one recipient address.")

        validator = forms.EmailField()
        normalized: list[str] = []
        for address in addresses:
            normalized.append(str(validator.clean(address)))
        return normalized

    @classmethod
    def from_mailing_list(cls, mailing_list: MailingList) -> "MailingListSettingsForm":
        return cls(initial={
            "name": mailing_list.name,
            "addresses": "\n".join(mailing_list.addresses),
            "new_mailfrom": mailing_list.new_mailfrom,
        })


class ServiceUserCreateForm(forms.ModelForm):
    password = forms.CharField(
        widget=forms.TextInput(),
        initial=lambda: generate_password(24),
        help_text="This password is only accessible here. Make sure to save it before you click \"Create service user\"",
    )

    class Meta:
        model = MNServiceUser
        fields = ("username", "password", "description")

    def __init__(self, user: MNUser, *args: object, **kwargs: object) -> None:
        self.user = user
        super().__init__(*args, **kwargs)
        self.fields["username"].initial = str(uuid.uuid4())
        self.fields["username"].widget.attrs["placeholder"] = "Autogenerated UUID"
        self.fields["description"].widget.attrs["placeholder"] = "What this credential is used for"
        self.fields["password"].widget.attrs["placeholder"] = "Autogenerated password"
        add_form_control_style(self.fields["username"])
        add_form_control_style(self.fields["password"])
        add_form_control_style(self.fields["description"])

    def clean(self) -> dict[str, object]:
        self.instance.user = self.user
        return super().clean()

    def save(self, commit: bool = True) -> MNServiceUser:
        service_user = super().save(commit=False)
        service_user.user = self.user
        service_user.set_password(self.cleaned_data["password"])
        if commit:
            service_user.save()
        return service_user
