# -* encoding: utf-8 *-
from typing import Dict, Any

from Crypto.PublicKey import RSA
from django.contrib import admin
from django.contrib.admin import widgets
from django.forms.models import ModelForm, ALL_FIELDS
from django.forms.renderers import BaseRenderer
from django.utils.html import format_html

from dockerauth.models import DockerRepo, DockerRegistry


class JWTKeyWidget(widgets.AdminTextareaWidget):
    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)

    def render(self, name: str, value: str, attrs: Dict[str, str]=None, renderer: BaseRenderer=None) -> str:
        ret = super().render(name, value, attrs)
        if value and value.startswith("-----BEGIN RSA PRIVATE KEY"):
            key = RSA.importKey(value)
            public_key = key.publickey().exportKey("PEM").decode('utf-8')
            ret += format_html("<pre>{public_key}</pre>", public_key=public_key)
        else:
            ret += format_html("<pre>ERROR: Unparsable private key (not a PEM object)</pre>")

        return format_html("<div style=\"float: left\">{}</div>", ret)


class DockerRegistryForm(ModelForm):
    class Meta:
        model = DockerRegistry
        widgets = {'dkimkey': JWTKeyWidget()}
        fields = ALL_FIELDS


class DockerPermissionAdminMixin:
    filter_horizontal = ('user_pull_access', 'user_push_access', 'group_pull_access', 'group_push_access',)


@admin.register(DockerRepo)
class DockerRepoAdmin(DockerPermissionAdminMixin, admin.ModelAdmin):
    pass


@admin.register(DockerRegistry)
class DockerRegistryAdmin(DockerPermissionAdminMixin, admin.ModelAdmin):
    form = DockerRegistryForm
