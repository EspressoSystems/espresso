# Copyright (c) 2022 Espresso Systems (espressosys.com)
# This file is part of the Espresso library.

FROM ubuntu:jammy

RUN apt-get update \
&&  apt-get install -y curl wait-for-it \
&&  rm -rf /var/lib/apt/lists/*

COPY target/x86_64-unknown-linux-musl/release-lto/faucet /bin/faucet
RUN chmod +x /bin/faucet

# Set up with a test wallet by default.
ENV ESPRESSO_FAUCET_WALLET_MNEMONIC="test test test test test test test test test test test junk"
ENV ESPRESSO_FAUCET_WALLET_STORE_PATH=/store

ENV ESPRESSO_FAUCET_PORT=50001
EXPOSE $ESPRESSO_FAUCET_PORT

HEALTHCHECK CMD curl -f 127.0.0.1:$ESPRESSO_FAUCET_PORT/healthcheck || exit 1

CMD [ "/bin/faucet" ]
