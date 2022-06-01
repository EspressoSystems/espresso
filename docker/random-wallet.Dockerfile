FROM ubuntu:jammy

RUN apt-get update \
&&  apt-get install -y curl wait-for-it \
&&  rm -rf /var/lib/apt/lists/*

COPY target/x86_64-unknown-linux-musl/release/random_wallet /bin/random-wallet
RUN chmod +x /bin/random-wallet

CMD [ "/bin/random-wallet" ]

