.PHONY: test build
test:
	cargo test --offline
build:
	cargo build --release --offline
