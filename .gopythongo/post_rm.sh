#!/usr/bin/env bash

if [ "$1" = "purge" ]; then
    deluser --system authserver
    delgroup --system authserver

    if [ -x "/usr/bin/deb-systemd-helper" ]; then
        /usr/bin/deb-systemd-helper purge authserver.service >/dev/null
        /usr/bin/deb-systemd-helper unmask authserver.service >/dev/null
        /usr/bin/deb-systemd-helper purge dkimsigner.service >/dev/null
        /usr/bin/deb-systemd-helper unmask dkimsigner.service >/dev/null
    fi

    if [ -x /etc/appconfig/authserver ]; then
        rm -rf /etc/appconfig/authserver
    fi

    if [ -x /etc/appconfig/dkimsigner ]; then
        rm -rf /etc/appconfig/dkimsigner
    fi
fi
