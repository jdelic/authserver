#!/bin/bash

# This script is used to create a pbuilder build environment that has FPM
# installed so GoPythonGo can create a .deb package of your project

# do nothing if fpm already exists
test -e /usr/local/bin/fpm && exit 0

EATMYDATA=""
if test -e /usr/bin/eatmydata; then
    EATMYDATA="/usr/bin/eatmydata"
fi

# make sure we have gem
if ! test -e /usr/bin/gem; then
    $EATMYDATA apt-get update
    $EATMYDATA apt-get --no-install-recommends -y install ruby ruby-dev
fi

$EATMYDATA gem install fpm
