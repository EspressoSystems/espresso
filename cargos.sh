#!/usr/bin/env bash
# Copyright (c) 2022 Espresso Systems (espressosys.com)
# This file is part of the Espresso library.

set -euo pipefail
cd $(dirname $0)
find -type f -name Cargo.toml | while read f; do
    echo $f
    pushd $(dirname $f) >/dev/null
    cargo $*
    popd >/dev/null
done

