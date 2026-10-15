FROM rust:1.80-bookworm AS builder
WORKDIR /app
COPY . .
RUN cargo build --release --locked --bin aegisguardd --bin aegisguard --bin aegiswrap

FROM debian:bookworm-slim
WORKDIR /app
COPY --from=builder /app/target/release/aegisguard /usr/local/bin/aegisguard
COPY --from=builder /app/target/release/aegisguardd /usr/local/bin/aegisguardd
COPY --from=builder /app/target/release/aegiswrap /usr/local/bin/aegiswrap
ENV AEGISGUARD_SOCKET=/tmp/aegisguard.sock
CMD ["aegisguardd"]
