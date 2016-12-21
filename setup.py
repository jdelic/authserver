#!/usr/bin/env python -u
import os
import re
import time

from setuptools import setup, find_packages
from pip.req import parse_requirements
from pip.download import PipSession


_INCLUDE = re.compile("\.(txt|gif|jpg|png|css|html|js|xml|po|mo)$")


def get_package_data() -> 'Dict[str, List[str]]':
    package_data = {}
    for pkg in os.listdir(_root_directory):
        pkg_path = os.path.join(_root_directory, pkg)
        if os.path.isdir(pkg_path):
            package_data[pkg] = create_paths(pkg_path)
    return package_data


def create_paths(root_dir: str) -> 'List[str]':
    paths = []
    is_package = os.path.exists(os.path.join(root_dir, '__init__.py'))
    children = os.listdir(root_dir)
    for child in children:
        childpath = os.path.join(root_dir, child)
        if os.path.isfile(childpath) and not is_package and \
                _INCLUDE.search(child):
            paths.append(child)
        if os.path.isdir(childpath):
            paths += [os.path.join(child, path) for path in create_paths(os.path.join(root_dir, child))]
    return paths


def read_version() -> str:
    fn = os.path.join(os.path.abspath(os.path.dirname(__file__)), "authserver", "authserver", "__init__.py")
    with open(fn, "rt", encoding="utf-8") as vf:
        lines = vf.readlines()

    for l in lines:
        m = re.match("version = \"(.+?)\"", l)
        if m:
            return m.group(1)
    raise Exception("Can't read base version from %s" % fn)

version = read_version()
if version.endswith(".dev"):
    _version = "%s%s" % (version, int(time.time()))
else:
    _version = version

_packages = find_packages(where='authserver', exclude=["*.tests", "*.tests.*", "tests.*", "tests"])

pipsession = PipSession()
reqs_generator = parse_requirements(os.path.join(os.path.abspath(os.path.dirname(__file__)), "requirements.txt"),
                                    session=pipsession)  # prepend setup.py's path (make no assumptions about cwd)
reqs = [str(r.req) for r in reqs_generator]

_root_directory = "authserver"

setup(
    name="net.maurus.authserver",
    version=_version,
    packages=_packages,
    package_dir={
        '': _root_directory,
    },
    install_requires=reqs,
    package_data=get_package_data(),
)
