FROM rust:1.80-bookworm
WORKDIR /app
COPY . .
RUN cargo test --offline
CMD ["cargo", "run", "--release", "--offline"]
