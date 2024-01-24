import logging
from typing import Callable, TYPE_CHECKING
from typing import Union

_log = logging.getLogger(__name__)

if TYPE_CHECKING:
    from django.contrib.auth import hashers


orig_identify_hasher = None  # type: Union[Callable[[str], hashers.BasePasswordHasher], None]


def mauth_identify_hasher(encoded: str) -> 'hashers.BasePasswordHasher':
    from mailauth.auth import UnixCryptCompatibleSHA256Hasher
    _log.debug("mauth_identify_hasher called (%s)", encoded)
    if orig_identify_hasher is None or encoded.startswith("$5"):
        return UnixCryptCompatibleSHA256Hasher()
    return orig_identify_hasher(encoded)


def setup() -> None:
    global orig_identify_hasher
    # called by the mailauth app
    import django.contrib.auth.hashers
    _log.debug("Monkey-patching identify_hasher")
    orig_identify_hasher = django.contrib.auth.hashers.identify_hasher
    django.contrib.auth.hashers.identify_hasher = mauth_identify_hasher

