#!/usr/bin/env bash
set -euo pipefail
cd $(dirname $0)
find -type f -name Cargo.toml | while read f; do
    echo $f
    pushd $(dirname $f) >/dev/null
    cargo $*
    popd >/dev/null
done

