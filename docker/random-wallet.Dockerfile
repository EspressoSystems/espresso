# Copyright (c) 2022 Espresso Systems (espressosys.com)
# This file is part of the Espresso library.

FROM ubuntu:jammy

RUN apt-get update \
&&  apt-get install -y curl wait-for-it \
&&  rm -rf /var/lib/apt/lists/*

COPY target/x86_64-unknown-linux-musl/release-lto/random-wallet /bin/random-wallet
RUN chmod +x /bin/random-wallet

CMD [ "/bin/random-wallet" ]

