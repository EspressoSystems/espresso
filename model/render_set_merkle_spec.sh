#!/usr/bin/env bash
set -euo pipefail

pandoc -t pdf set_merkle_tree_spec.md >set_merkle_tree_spec.pdf
