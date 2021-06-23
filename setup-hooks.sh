#!/usr/bin/env bash

set -e

GIT_ROOT="$(git rev-parse --show-toplevel)"
pushd $GIT_ROOT >/dev/null

for f in $(dirname $0)/hooks/*; do
    pushd .git/hooks/ >/dev/null
    ln -s ../../hooks/$(basename $f) .
    popd
done

