#!/usr/bin/env bash

# add the authserver user and group if it doesn't exist yet
adduser --home /run/authserver --disabled-login --disabled-password --system --group authserver

chown -R authserver:authserver /etc/appconfig/authserver/*
chown -R authserver:authserver /etc/appconfig/dkimsigner/*

systemctl --system daemon-reload >/dev/null || true

# the following was assembled from various default blocks created by dh_make helpers
# in packages using the default deb build system
if [ -x "/usr/bin/deb-systemd-helper" ]; then
    # unmask if previously masked by apt-get remove
    /usr/bin/deb-systemd-helper unmask authserver.service >/dev/null || true
    /usr/bin/deb-systemd-helper unmask dkimsigner.service >/dev/null || true

    if /usr/bin/deb-systemd-helper --quiet was-enabled authserver.service; then
        # Enables the unit on first installation, creates new
        # symlinks on upgrades if the unit file has changed.
        deb-systemd-helper enable authserver.service >/dev/null || true
        deb-systemd-invoke start authserver >/dev/null || true
    else
        # Update the statefile to add new symlinks (if any), which need to be
        # cleaned up on purge. Also remove old symlinks.
        deb-systemd-helper update-state authserver.service >/dev/null || true
    fi

    if /usr/bin/deb-systemd-helper --quiet was-enabled dkimsigner.service; then
        # Enables the unit on first installation, creates new
        # symlinks on upgrades if the unit file has changed.
        deb-systemd-helper enable dkimsigner.service >/dev/null || true
        deb-systemd-invoke start dkimsigner >/dev/null || true
    else
        # Update the statefile to add new symlinks (if any), which need to be
        # cleaned up on purge. Also remove old symlinks.
        deb-systemd-helper update-state dkimsigner.service >/dev/null || true
    fi
fi

if [ -d /run/systemd/system ] ; then
    # make sure tempfiles exist
    systemd-tmpfiles --create /usr/lib/tmpfiles.d/authserver.conf >/dev/null || true
fi
