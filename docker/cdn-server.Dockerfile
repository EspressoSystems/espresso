# Copyright (c) 2022 Espresso Systems (espressosys.com)
# This file is part of the Espresso library.

FROM ubuntu:jammy

RUN apt-get update \
&&  apt-get install -y curl wait-for-it \
&&  rm -rf /var/lib/apt/lists/*

COPY target/x86_64-unknown-linux-musl/release-lto/cdn-server /bin/cdn-server
RUN chmod +x /bin/cdn-server

ENV ESPRESSO_CDN_SERVER_PORT=50000

CMD [ "/bin/cdn-server"]
