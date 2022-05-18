FROM scratch
COPY target/x86_64-unknown-linux-musl/release/address-book /bin/address-book
CMD [ "/bin/address-book" ]
