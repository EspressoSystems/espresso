FROM 279906117593.dkr.ecr.us-east-2.amazonaws.com/jellyfish:main as jellyfish
FROM 279906117593.dkr.ecr.us-east-2.amazonaws.com/hotstuff:add-ci as hotstuff
FROM 279906117593.dkr.ecr.us-east-2.amazonaws.com/rust:2021-03-24 as builder
RUN mkdir /app /app/system
COPY --from=jellyfish /app /app/jellyfish
COPY --from=hotstuff /app /app/hotstuff
WORKDIR /app/system
COPY . /app/system
WORKDIR /app/system/zerok
RUN cargo audit || true
RUN cargo clippy --workspace
RUN cargo fmt --all -- --check
RUN cargo build --workspace --release
RUN cargo test --workspace --release
FROM debian:buster
COPY --from=builder /app/system/zerok/target/release/libzerok_lib* /app/
