FROM 279906117593.dkr.ecr.us-east-2.amazonaws.com/rust:2021-03-24 as builder
RUN mkdir /app
WORKDIR /app
COPY . /app/
RUN --mount=type=ssh cargo audit || true
RUN --mount=type=ssh cargo clippy --workspace
RUN cargo fmt --all -- --check
RUN --mount=type=ssh cargo build --workspace --release
RUN cargo test --workspace --release
FROM debian:buster
COPY --from=builder /app/target/release/libzerok_lib* /app/
