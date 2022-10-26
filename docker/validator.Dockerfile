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

# Set up view timing for optimal performance in high volume conditions. We set a fairly long minimum
# propose time to wait to build up a large block before proposing.
ENV ESPRESSO_VALIDATOR_MIN_PROPOSE_TIME=10s
# We set the minimum block size to 1, limiting the number of empty blocks but allowing us to propose
# a block immediately after the minimum propose time, keeping latency low in low-volume cases.
ENV ESPRESSO_VALIDATOR_MIN_TRANSACTIONS=1
# Since min transactions is 1, max propose time only controls the frequency of empty blocks. We set
# this not too much higher than min propose time, for reasonable latency in low volume conditions,
# when empty blocks are required to push non-empty blocks through the pipeline.
ENV ESPRESSO_VALIDATOR_MAX_PROPOSE_TIME=30s
# The view timeout is larger, since it should only matter when something goes wrong (i.e. leader
# failure).
ENV ESPRESSO_VALIDATOR_NEXT_VIEW_TIMEOUT=5m

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
