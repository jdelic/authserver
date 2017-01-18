#!/usr/bin/env bash

deb-systemd-invoke stop authserver > /dev/null || true
deb-systemd-invoke stop dkimsigner > /dev/null || true

# fpm wraps this script so it is executed inside a shell function, so we know that $1 == "remove" here
find /usr/local/authserver/lib -name \*.pyc -delete
find /usr/local/authserver -type d -name __pycache__ -print0 | xargs -0 rm -rf
find /usr/local/authserver -type d -name static -print0 | xargs -0 rm -rf
