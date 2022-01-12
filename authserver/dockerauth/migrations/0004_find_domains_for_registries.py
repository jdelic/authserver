
from django.db import migrations
from django.db.migrations import RunPython
from typing import TYPE_CHECKING, Union, Optional, cast, Iterable


if TYPE_CHECKING:

    from django.db.backends.base.schema import BaseDatabaseSchemaEditor
    from django.apps.registry import Apps
    from mailauth import models as mailauth_models
    from dockerauth import models as dockerauth_models


def find_parent_domain(apps: 'Apps', fqdn: str,
                       require_jwt_subdomains_set: bool = True) -> Union['mailauth_models.Domain', None]:
    # import mailauth.models.Domain here so importing this module does not depend on Django to be initialized
    Domain = cast('mailauth_models.Domain', apps.get_model('mailauth', 'Domain'))  # type: mailauth_models.Domain
    req_domain = None  # type: Optional[mailauth_models.Domain]

    # results in ['sub.example.com', 'example.com', 'com']
    parts = fqdn.split(".")
    for domainstr in [".".join(parts[r:]) for r in range(0, len(parts))]:
        try:
            req_domain = Domain.objects.get(name=domainstr)
        except Domain.DoesNotExist:
            continue
        else:
            if req_domain is None or req_domain.jwtkey == "":
                req_domain = None
                continue

            if req_domain.jwtkey is not None and req_domain.jwtkey != "":
                if domainstr == fqdn or (req_domain.jwt_subdomains and require_jwt_subdomains_set):
                    break
                elif not require_jwt_subdomains_set:
                    # we have a domain which has a jwtkey and we don't require jwt_subdomains to be True, so
                    # we return the current result
                    break
                elif require_jwt_subdomains_set and not req_domain.jwt_subdomains:
                    # prevent the case where domainstr is the last str in parts, it matches, has a jwtkey but
                    # is not valid for subdomains. req_domain would be != None in that case and the loop would exit
                    req_domain = None
                    continue

    return req_domain


# type helper
if TYPE_CHECKING:
    from django.db import models

    class _LegacyDockerRegistry(dockerauth_models.DockerRegistry):
        sign_key: models.TextField


def find_registry_defaults(apps: 'Apps', schema_editor: 'BaseDatabaseSchemaEditor') -> None:
    _DockerRegistry = cast('_LegacyDockerRegistry',
                           apps.get_model("dockerauth", "DockerRegistry"))
    Domain = cast('mailauth_models.Domain', apps.get_model('mailauth', 'Domain'))  # type: mailauth_models.Domain

    for registry in cast('Iterable[_LegacyDockerRegistry]', _DockerRegistry.objects.all()):
        connect_to = find_parent_domain(apps, registry.client_id)
        if connect_to is None:
            connect_to = Domain.objects.create(
                name=registry.client_id,
                jwtkey=registry.sign_key,
            )
        else:
            if connect_to.jwtkey is None or connect_to.jwtkey == "":
                connect_to.jwtkey = registry.sign_key  # type: ignore
                connect_to.save()
        registry.domain = connect_to
        registry.save()


class Migration(migrations.Migration):

    dependencies = [
        ('dockerauth', '0003_remove_signkey_add_domain_fk'),
    ]

    operations = [
        RunPython(find_registry_defaults)
    ]
