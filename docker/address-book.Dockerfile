FROM ubuntu:jammy
COPY target/x86_64-unknown-linux-musl/release/address-book /bin/address-book
CMD [ "/bin/address-book" ]

ENV ESPRESSO_ADDRESS_BOOK_PORT=50002
EXPOSE $ESPRESSO_ADDRESS_BOOK_PORT
