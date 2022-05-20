FROM ubuntu:jammy
COPY target/x86_64-unknown-linux-musl/release/faucet /bin/faucet

# Set up with a test wallet by default.
ENV ESPRESSO_FAUCET_WALLET_MNEMONIC="test test test test test test test test test test test junk"
ENV ESPRESSO_FAUCET_WALLET_STORE_PATH=/store

ENV ESPRESSO_FAUCET_PORT=50001
EXPOSE $ESPRESSO_FAUCET_PORT

CMD [ "/bin/faucet" ]
