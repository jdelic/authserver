"""CIMD (Client ID Metadata Document) policy for authserver.

Gating and post-registration normalization are per mailauth.Domain:
see Domain.cimd_enabled / cimd_client_hosts / cimd_auto_permissions.
"""
import hashlib
import logging
from urllib.parse import urlparse

from django.http.request import validate_host

from mailauth.models import Domain, MNApplication, MNApplicationPermission

_log = logging.getLogger(__name__)


def _domain_for_oauthlib_request(request):
    """Resolve the mailauth.Domain serving an oauthlib request.

    request.headers is a copy of Django's META, so the Host header is
    HTTP_HOST. request.uri holds only the path - do NOT parse it for a
    hostname. Returns None when no signing domain matches.
    """
    host = (request.headers.get("HTTP_HOST") or "").split(":")[0]
    if not host:
        return None
    try:
        return Domain.objects.find_parent_domain(
            host, require_jwt_subdomains_set=True, require_jwt_key=True
        )
    except Domain.DoesNotExist:
        return None


class DomainCIMDPermission:
    """CIMD gate: the request's Domain must have cimd_enabled and the
    client_id URL's host must match the domain's fail-closed allowlist
    (empty allowlist = deny; '*' must be explicit)."""

    def has_permission(self, request, client_id) -> bool:
        domain = _domain_for_oauthlib_request(request)
        if domain is None or not domain.cimd_enabled:
            return False
        client_host = urlparse(client_id).hostname
        if not client_host or not domain.cimd_client_hosts:
            return False
        return validate_host(client_host, domain.cimd_client_hosts)


def auto_permission_name(client_id: str) -> str:
    """Deterministic, unique, <=255 char permission identifier for a CIMD
    client. Includes the client host for readability and a hash of the
    full URL for uniqueness."""
    digest = hashlib.sha256(client_id.encode("utf-8")).hexdigest()[:16]
    host = urlparse(client_id).hostname or "unknown"
    return "cimd:%s:%s" % (host[:200], digest)


def ensure_cimd_application_defaults(application: MNApplication, request) -> None:
    """Idempotent post-registration normalization, called on every
    _load_application hit for a CIMD app: attach the Domain and (if the
    domain wants it) the auto-generated lockdown permission."""
    domain = None
    if application.domain_id is None:
        domain = _domain_for_oauthlib_request(request)
        if domain is None:
            # Permission checks should make this unreachable; never
            # break the OAuth flow from here.
            _log.warning("CIMD app %s has no resolvable domain", application.client_id)
        else:
            application.domain = domain
            application.save(update_fields=["domain"])

    if domain is None and application.domain_id is not None:
        domain = application.domain
    if domain is None or not domain.cimd_auto_permissions:
        return

    permission_name = auto_permission_name(application.client_id)
    permission, _created = MNApplicationPermission.objects.get_or_create(
        permission_name=permission_name,
        defaults={"name": "CIMD client: %s" % application.client_id[:200]},
    )
    if not application.required_permissions.filter(pk=permission.pk).exists():
        application.required_permissions.add(permission)
