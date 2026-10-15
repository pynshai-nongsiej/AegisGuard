# AegisGuard

Dependency-free Rust security policy primitives for agent command approval. The policy detects common AWS, GitHub, SSH, Stripe and `.env` secrets, network transfers, destructive commands and shell obfuscation, returning a 0–100 risk score and `Allow`/`Review`/`Deny` decision. `SnapshotLedger` captures and atomically restores local files for tests and recovery.

## Setup and checks

Requires Rust 1.80 (the pinned `rust-toolchain.toml`). `cargo test --offline` or `make test` runs all checks without network access. Build with `make build`; Docker builds and runs with `docker build -t aegisguard . && docker run --rm aegisguard`.

Public API is in `src/policy.rs` (`analyze_command`, `detect_secrets`) and `src/ledger.rs` (`SnapshotLedger`).
