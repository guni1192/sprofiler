ARG RUST_VERSION=1.58

FROM rust:${RUST_VERSION}-slim-bullseye as planner
RUN apt-get update \
    && apt-get install -y \
    libelf-dev \
    libgcc-s1 \
    libbpf-dev \
    bpftool \
    clang \
    curl \
    make \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
RUN cargo install cargo-chef
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

FROM rust:${RUST_VERSION}-slim-bullseye as cacher

RUN apt-get update \
    && apt-get install -y \
    libelf-dev \
    libgcc-s1 \
    libbpf-dev \
    bpftool \
    clang \
    curl \
    make \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
RUN cargo install cargo-chef
COPY --from=planner /app/recipe.json recipe.json
RUN cargo chef cook --release --recipe-path recipe.json

FROM rust:${RUST_VERSION}-slim-bullseye as builder

RUN apt-get update \
    && apt-get install -y \
    libelf-dev \
    libgcc-s1 \
    libbpf-dev \
    bpftool \
    clang \
    curl \
    make \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY . .
COPY --from=cacher /app/target target
COPY --from=cacher /usr/local/cargo /usr/local/cargo
# RUN rustup component add rustfmt
RUN cargo build --release

FROM rust:${RUST_VERSION}-slim-bullseye as runtime
# FROM gcr.io/distroless/cc-debian10 as runtime
COPY --from=builder /app/target/release/sprofiler /
COPY --from=builder /app/target/release/sprofiler-bpf /
ENTRYPOINT ["/sprofiler"]
