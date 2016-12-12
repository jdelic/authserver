#!/usr/bin/env bash

# add the authserver user and group if it doesn't exist yet
adduser --home /run/authserver --disabled-login --disabled-password --system --group authserver

