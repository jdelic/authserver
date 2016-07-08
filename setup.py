#!/usr/bin/env python -u
import os
from setuptools import setup, find_packages
from pip.req import parse_requirements
from pip.download import PipSession

import time
_version = "1.0.dev%s" % int(time.time())
_packages = find_packages(exclude=["*.tests", "*.tests.*", "tests.*", "tests"])

pipsession = PipSession()
reqs_generator = parse_requirements(os.path.join(os.path.abspath(os.path.dirname(__file__)), "requirements.txt"),
                                    session=pipsession)  # prepend setup.py's path (make no assumptions about cwd)
reqs = [str(r.req) for r in reqs_generator]

setup(
    name='net.maurus.casserver',
    scripts=[
        'scripts/checkpassword.py',
        'scripts/createuser.py',
        'scripts/deleteuser.py',
    ],
    version=_version,
    packages=_packages,
    install_requires=reqs,
)
