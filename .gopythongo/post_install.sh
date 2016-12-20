#!/usr/bin/env bash

# add the authserver user and group if it doesn't exist yet
adduser --home /run/authserver --disabled-login --disabled-password --system --group authserver

chown -R authserver:authserver /etc/appconfig/authserver/*

# the following was assembled from various default blocks created by dh_make helpers
# in packages using the default deb build system
if [ -x "/usr/bin/deb-systemd-helper" ]; then
    # unmask if previously masked by apt-get remove
    /usr/bin/deb-systemd-helper unmask authserver.service >/dev/null || true

    if /usr/bin/deb-systemd-helper --quiet was-enabled authserver.service; then
        # Enables the unit on first installation, creates new
        # symlinks on upgrades if the unit file has changed.
        deb-systemd-helper enable authserver.service >/dev/null || true
    else
        # Update the statefile to add new symlinks (if any), which need to be
        # cleaned up on purge. Also remove old symlinks.
        deb-systemd-helper update-state authserver.service >/dev/null || true
    fi
fi

if [ -d /run/systemd/system ] ; then
    # make sure tempfiles exist
    systemd-tmpfiles --create /usr/lib/tmpfiles.d/authserver.conf >/dev/null || true
fi
