# Copyright (c) 2022 Espresso Systems (espressosys.com)
# This file is part of the Espresso library.
#
# This program is free software: you can redistribute it and/or modify it under the terms of the GNU
# General Public License as published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
# This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without
# even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# General Public License for more details.
# You should have received a copy of the GNU General Public License along with this program. If not,
# see <https://www.gnu.org/licenses/>.

FROM ubuntu:jammy

RUN apt-get update \
&&  apt-get install -y curl wait-for-it \
&&  rm -rf /var/lib/apt/lists/*

COPY target/x86_64-unknown-linux-musl/release-lto/espresso-validator /bin/espresso-validator
RUN chmod +x /bin/espresso-validator

# Set file locations.
ENV ESPRESSO_VALIDATOR_PUB_KEY_PATH=/config
ENV ESPRESSO_VALIDATOR_STORE_PATH=/store/atomicstore

# Run a query service at port 50000.
ENV ESPRESSO_ESQS_PORT=50000
EXPOSE $ESPRESSO_ESQS_PORT

# Set a default number of nodes.
ENV ESPRESSO_VALIDATOR_NUM_NODES=10

# Set parameters for consensus connections.
ENV ESPRESSO_VALIDATOR_REPLICATION_FACTOR=5
ENV ESPRESSO_VALIDATOR_BOOTSTRAP_MESH_N_HIGH=50
ENV ESPRESSO_VALIDATOR_BOOTSTRAP_MESH_N_LOW=10
ENV ESPRESSO_VALIDATOR_BOOTSTRAP_MESH_OUTBOUND_MIN=5
ENV ESPRESSO_VALIDATOR_BOOTSTRAP_MESH_N=15
ENV ESPRESSO_VALIDATOR_NONBOOTSTRAP_MESH_N_HIGH=15
ENV ESPRESSO_VALIDATOR_NONBOOTSTRAP_MESH_N_LOW=8
ENV ESPRESSO_VALIDATOR_NONBOOTSTRAP_MESH_OUTBOUND_MIN=4
ENV ESPRESSO_VALIDATOR_NONBOOTSTRAP_MESH_N=12

# Additional configuration not specified here because it must be set per validator:
# ESPRESSO_VALIDATOR_ID
# ESPRESSO_VALIDATOR_BOOTSTRAP_NODES

HEALTHCHECK CMD curl -f 127.0.0.1:$ESPRESSO_ESQS_PORT/healthcheck || exit 1

CMD [ "/bin/espresso-validator", "esqs"]
