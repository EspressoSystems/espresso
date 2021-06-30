#!/bin/bash
sed -i "s?PRIVATEREPO?$CARGO_REGISTRIES_TRANSLUCENCE_INDEX?g" cargo-system-config.toml
