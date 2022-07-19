#!/usr/bin/env bash

set -euo pipefail

rm -f *.png *.svg
for file in *.puml; do
    echo $file
    plantuml $file -svg
done
