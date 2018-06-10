# -* encoding: utf-8 *-
from typing import Dict, Any, Optional

from django.contrib import admin
from django.contrib.admin import widgets
from django.forms.models import ModelForm, ALL_FIELDS
from django.forms.renderers import BaseRenderer
from django.utils.html import format_html

from dockerauth.models import DockerRepo, DockerRegistry
from mailauth.utils import import_rsa_key


class JWTKeyWidget(widgets.AdminTextareaWidget):
    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)

    def render(self, name: str, value: str, attrs: Optional[Dict[str, str]]=None, renderer: BaseRenderer=None) -> str:
        ret = super().render(name, value, attrs)
        if value and value.startswith("-----BEGIN RSA PRIVATE KEY"):
            public_key = import_rsa_key(value).public_key
            ret += format_html("<pre>{public_key}</pre>", public_key=public_key)
        else:
            ret += format_html("<pre>ERROR: Unparsable private key (not a PEM object)</pre>")

        return format_html("<div style=\"float: left\">{}</div>", ret)


class DockerRegistryForm(ModelForm):
    class Meta:
        model = DockerRegistry
        widgets = {'sign_key': JWTKeyWidget()}
        fields = ALL_FIELDS


class DockerPermissionAdminMixin:
    filter_horizontal = ('user_pull_access', 'user_push_access', 'group_pull_access', 'group_push_access',)


@admin.register(DockerRepo)
class DockerRepoAdmin(DockerPermissionAdminMixin, admin.ModelAdmin):
    search_fields = ('name', 'registry__name', 'registry__client_id',)
    fields = ('name', 'registry', 'unauthenticated_pull', 'unauthenticated_push',
              'user_pull_access', 'user_push_access', 'group_pull_access', 'group_push_access',)

    def get_registry_path(self, obj: DockerRepo) -> str:
        return "%s:%s" % (obj.registry.name, obj.name,)
    get_registry_path.short_description = "Scope"  # type: ignore

    list_display = ('get_registry_path',)


@admin.register(DockerRegistry)
class DockerRegistryAdmin(DockerPermissionAdminMixin, admin.ModelAdmin):
    search_fields = ('name', 'client_id',)
    fields = ('name', 'client_id', 'domain', 'unauthenticated_pull', 'unauthenticated_push',
              'user_pull_access', 'user_push_access', 'group_pull_access', 'group_push_access',)
    form = DockerRegistryForm
    list_display = ('name', 'client_id',)
