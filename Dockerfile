# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: MIT
# `docker build --target test` runs the suite in this image.
# The demo image below does not run it.
FROM rust:1-bookworm AS test
RUN apt-get update && apt-get install -y --no-install-recommends python3 \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY . .
RUN cargo test

FROM rust:1-bookworm
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends curl && rm -rf /var/lib/apt/lists/*
COPY Cargo.toml Cargo.lock ./
COPY src src
# src/demo.rs compiles demo/public/styles.css in (include_str!).
COPY demo/public demo/public
RUN cargo build --release --bin wsfed-demo --bin wsfed-caep \
 && cp target/release/wsfed-demo /usr/local/bin/wsfed-demo \
 && cp target/release/wsfed-caep /usr/local/bin/wsfed-caep
# demo/ comes after the build, so a new trust chain does not rebuild the binaries.
# .dockerignore admits one file of demo/generated: idp-ca.pem, the iya-sts listener
# CA trust chain scripts/configure_iya_sts.py writes where idpCa names it. When it
# exists, this COPY puts it at /app/demo/generated/idp-ca.pem; when it does not (a
# fresh clone, CI), the directory carries nothing from demo/generated and the build
# still succeeds. Keys and metadata never enter the image.
COPY demo demo
COPY scripts scripts
COPY README.md LICENSE VERSION ./
ENV PORT=3000
EXPOSE 3000
HEALTHCHECK --interval=15s --timeout=3s --start-period=5s \
  CMD curl -fsS "http://127.0.0.1:${PORT}/healthz" || exit 1
CMD ["wsfed-demo"]
