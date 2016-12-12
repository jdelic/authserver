#!/usr/bin/env bash

if [ "$1" = "remove" ]; then
    if [ -x "/usr/bin/deb-systemd-helper" ]; then
        /usr/bin/deb-systemd-helper mask authserver.service >/dev/null
    fi
fi

if [ "$1" = "purge" ]; then
    deluser --system authserver
    delgroup --system authserver

    if [ -x "/usr/bin/deb-systemd-helper" ]; then
        /usr/bin/deb-systemd-helper purge authserver.service >/dev/null
        /usr/bin/deb-systemd-helper unmask authserver.service >/dev/null
    fi
fi
