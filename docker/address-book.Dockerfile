FROM ubuntu:jammy

RUN apt-get update \
&&  apt-get install -y curl wait-for-it \
&&  rm -rf /var/lib/apt/lists/*

COPY target/x86_64-unknown-linux-musl/release/address-book /bin/address-book
RUN chmod +x /bin/address-book

ENV ESPRESSO_ADDRESS_BOOK_PORT=50002
EXPOSE $ESPRESSO_ADDRESS_BOOK_PORT

HEALTHCHECK CMD curl -f 127.0.0.1:$ESPRESSO_ADDRESS_BOOK_PORT/healthcheck || exit 1

CMD [ "/bin/address-book" ]

