# -* encoding: utf-8 *-
import sys
import contextlib
from io import TextIOWrapper
from typing import Union, TextIO

from mailauth.models import Domain


def find_parent_domain(fqdn: str, require_jwt_subdomains_set: bool=True) -> Union[Domain, None]:
    # results in ['sub.example.com', 'example.com', 'com']
    req_domain = None  # type: Domain
    parts = fqdn.split(".")
    for domainstr in [".".join(parts[r:]) for r in range(0, len(parts))]:
        try:
            req_domain = Domain.objects.get(name=domainstr)
        except Domain.DoesNotExist:
            continue
        else:
            if req_domain.jwtkey is not None and req_domain.jwtkey != "":
                if domainstr == fqdn or (req_domain.jwt_subdomains and require_jwt_subdomains_set):
                    break
                elif require_jwt_subdomains_set and not req_domain.jwt_subdomains:
                    # prevent the case where domainstr is the last str in parts, it matches, has a jwtkey but
                    # is not valid for subdomains. req_domain would be != None in that case and the loop would exit
                    req_domain = None
                    continue

    return req_domain


@contextlib.contextmanager
def stdout_or_file(path: str) -> Union[TextIOWrapper, TextIO]:
    if path == "-":
        yield sys.stdout
    else:
        fd = open(path, mode="w")
        yield fd
        fd.close()
