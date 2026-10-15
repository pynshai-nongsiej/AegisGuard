.PHONY: test build fmt check
test:
	cargo test --offline --locked
build:
	cargo build --release --locked
fmt:
	cargo fmt --all -- --check
check:
	cargo check --offline --locked
