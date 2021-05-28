FROM 279906117593.dkr.ecr.us-east-2.amazonaws.com/jellyfish:main as jellyfish
FROM 279906117593.dkr.ecr.us-east-2.amazonaws.com/rust:2021-03-24 as builder
RUN mkdir /app
COPY . /app/
WORKDIR /app/
RUN cargo audit || true
RUN cargo build --release
RUN cargo test --release
