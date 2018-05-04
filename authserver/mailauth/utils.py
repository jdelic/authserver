# -* encoding: utf-8 *-
import sys
import contextlib
from io import TextIOWrapper
from typing import Union, TextIO, Generator, Tuple, NamedTuple

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKeyWithSerialization
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKeyWithSerialization

Key = NamedTuple(
    'Key', [
        ("public_key", str),
        ("private_key", str),
        ("key", RSAPrivateKeyWithSerialization),
])


def _create_key(pkey: RSAPrivateKeyWithSerialization) -> Key:
    privpem = pkey.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")

    pub = pkey.public_key()  # type: RSAPublicKeyWithSerialization
    pubpem = pub.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode("utf-8")
    return Key(public_key=pubpem, private_key=privpem, key=pkey)


def generate_rsa_key(length: int=2048) -> Key:
    pkey = rsa.generate_private_key(
        public_exponent=65537, key_size=length, backend=default_backend())  # type: RSAPrivateKeyWithSerialization
    return _create_key(pkey)


def import_rsa_key(key: str) -> Key:
    pkey = serialization.load_pem_private_key(key.encode("utf-8"), password=None, backend=default_backend())
    return _create_key(pkey)


@contextlib.contextmanager
def stdout_or_file(path: str) -> Generator[Union[TextIOWrapper, TextIO], None, None]:
    if path is None or path == "" or path == "-":
        yield sys.stdout
    else:
        fd = open(path, mode="w")
        yield fd
        fd.close()
