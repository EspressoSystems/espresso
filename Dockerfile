FROM 279906117593.dkr.ecr.us-east-2.amazonaws.com/jellyfish:main as jellyfish
FROM 279906117593.dkr.ecr.us-east-2.amazonaws.com/rust:2021-03-24 as builder
RUN mkdir /app
COPY . /app/
WORKDIR /app/
RUN --mount=type=ssh cargo audit || true
RUN --mount=type=ssh cargo build --release
RUN cargo test --release
