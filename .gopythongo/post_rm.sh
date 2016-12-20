#!/usr/bin/env bash

# fpm wraps this in a shell function and ignores the "purge" action. So basically we
# handle any invocation like a purge
deluser --system authserver
delgroup --system authserver

if [ -x "/usr/bin/deb-systemd-helper" ]; then
    /usr/bin/deb-systemd-helper purge authserver.service >/dev/null
    /usr/bin/deb-systemd-helper unmask authserver.service >/dev/null
fi

if [ -x /etc/appconfig/authserver ]; then
    rm -rf /etc/appconfig/authserver
fi
