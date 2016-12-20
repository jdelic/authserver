#!/usr/bin/env bash

if [ "$1" = "remove" ]; then
    echo "authserver prerm: removing temp files"
    find /usr/local/authserver/lib -name \*.pyc -delete
    find /usr/local/authserver -name __pycache__ -print0 | xargs -0 rm -rf
fi
