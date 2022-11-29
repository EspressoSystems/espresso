#!/usr/bin/env bash
# Copyright (c) 2022 Espresso Systems (espressosys.com)
# This file is part of the Espresso library.

set -euo pipefail

pandoc set_merkle_tree_spec.md -o set_merkle_tree_spec.pdf
