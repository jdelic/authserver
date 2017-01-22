#!/usr/bin/env bash

# add the authserver user and group if it doesn't exist yet
adduser --quiet --home /run/authserver --disabled-login --disabled-password --system --group authserver

chown -R authserver:authserver /etc/appconfig/authserver/* > /dev/null
chown -R authserver:authserver /etc/appconfig/dkimsigner/* > /dev/null

systemctl --system daemon-reload >/dev/null || true

# the following was assembled from various default blocks created by dh_make helpers
# in packages using the default deb build system
if [ -x "/usr/bin/deb-systemd-helper" ]; then
    # unmask if previously masked by apt-get remove
    /usr/bin/deb-systemd-helper unmask authserver.service >/dev/null || true
    /usr/bin/deb-systemd-helper unmask dkimsigner.service >/dev/null || true

    if /usr/bin/deb-systemd-helper --quiet is-enabled authserver.service; then
        # If authserver had been installed before restart it (upgrade)
        deb-systemd-helper reenable authserver.service >/dev/null || true
        deb-systemd-invoke restart authserver >/dev/null || true
    else
        # on first install, disable. The admin will enable and start the service.
        deb-systemd-helper disable authserver.service > /dev/null || true
        deb-systemd-helper update-state authserver.service >/dev/null || true
    fi

    if /usr/bin/deb-systemd-helper --quiet is-enabled dkimsigner.service; then
        # If dkimsigner had been installed before restart it (upgrade)
        deb-systemd-helper reenable dkimsigner.service >/dev/null || true
        deb-systemd-invoke restart dkimsigner >/dev/null || true
    else
        # on first install, disable. The admin will enable and start the service.
        deb-systemd-helper disable dkimsigner.service > /dev/null || true
        deb-systemd-helper update-state dkimsigner.service >/dev/null || true
    fi
fi

if [ -d /run/systemd/system ] ; then
    # make sure tempfiles exist
    systemd-tmpfiles --create /usr/lib/tmpfiles.d/authserver.conf >/dev/null || true
fi
