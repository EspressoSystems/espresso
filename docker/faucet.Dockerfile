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

COPY target/x86_64-unknown-linux-musl/release/faucet /bin/faucet
RUN chmod +x /bin/faucet

# Set up with a test wallet by default.
ENV ESPRESSO_FAUCET_WALLET_MNEMONIC="test test test test test test test test test test test junk"
ENV ESPRESSO_FAUCET_WALLET_STORE_PATH=/store

ENV ESPRESSO_FAUCET_PORT=50001
EXPOSE $ESPRESSO_FAUCET_PORT

HEALTHCHECK CMD curl -f 127.0.0.1:$ESPRESSO_FAUCET_PORT/healthcheck || exit 1

CMD [ "/bin/faucet" ]
