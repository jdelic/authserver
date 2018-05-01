# -* encoding: utf-8 *-
import sys
import contextlib
from io import TextIOWrapper
from typing import Union, TextIO, Generator


@contextlib.contextmanager
def stdout_or_file(path: str) -> Generator[Union[TextIOWrapper, TextIO], None, None]:
    if path is None or path == "" or path == "-":
        yield sys.stdout
    else:
        fd = open(path, mode="w")
        yield fd
        fd.close()
