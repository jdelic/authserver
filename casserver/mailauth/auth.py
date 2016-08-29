# -* encoding: utf-8 *-
from mailauth.models import Domain, EmailAlias


class MNUserAuthenticationBackend(object):
    def authenticate(self, email: str, password: str) -> bool:
        if "@" not in email or email.count("@") > 1:
            return None

        mailprefix, domain = email.split("@")

        if Domain.objects.filter(name=domain).count() == 0:
            return None
