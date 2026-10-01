# tc_aead_cipher

A Rust workspace for authenticated encryption with associated data (AEAD). It
holds `tc_aead_cipher`, the shared `AeadCipher` and `AeadCipherInit`
contracts together with GCM, GCM-SIV, CCM, KCCM, EAX and OCB, which run over
any engine that implements the
[`tc_block_cipher`](https://crates.io/crates/tc_block_cipher) traits, and the
algorithms built on those contracts that carry their own primitive:
`tc_ascon_aead`, `tc_grain128_aead` and `tc_sparkle_aead`.
Each crate is published separately and keeps its own README, changelog, and
validation commands.

[![CI](https://github.com/TomiCheng/tc_aead_cipher/actions/workflows/ci.yml/badge.svg)](https://github.com/TomiCheng/tc_aead_cipher/actions/workflows/ci.yml)
[![license](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](#license)
![rustc](https://img.shields.io/badge/rustc-1.85+-blue.svg)

## Crates

| Crate | Version | Description |
| --- | --- | --- |
| [`tc_aead_cipher`](tc_aead_cipher) | [![crates.io](https://img.shields.io/crates/v/tc_aead_cipher.svg)](https://crates.io/crates/tc_aead_cipher) [![docs.rs](https://docs.rs/tc_aead_cipher/badge.svg)](https://docs.rs/tc_aead_cipher) | The `AeadCipher` and `AeadCipherInit` contracts, and GCM and EAX over any `tc_block_cipher` engine. A default-off `alloc` feature adds CCM, GCM-SIV, OCB and KCCM, which buffer the whole message, and parameters that own and wipe their bytes. `no_std`, no `unsafe`; constant time exactly when the cipher is. |
| [`tc_ascon_aead`](tc_ascon_aead) | [![crates.io](https://img.shields.io/crates/v/tc_ascon_aead.svg)](https://crates.io/crates/tc_ascon_aead) [![docs.rs](https://docs.rs/tc_ascon_aead/badge.svg)](https://docs.rs/tc_ascon_aead) | Ascon-AEAD128 (NIST SP 800-232) and the Ascon-128, Ascon-128a and Ascon-80pq variants of Ascon v1.2. Constant time. `no_std`, no allocator, no `unsafe`, no features. |
| [`tc_grain128_aead`](tc_grain128_aead) | [![crates.io](https://img.shields.io/crates/v/tc_grain128_aead.svg)](https://crates.io/crates/tc_grain128_aead) [![docs.rs](https://docs.rs/tc_grain128_aead/badge.svg)](https://docs.rs/tc_grain128_aead) | Grain-128AEAD, with associated data held in a fixed buffer or, with the default-off `alloc` feature, a `Vec`. Constant time. `no_std`, no `unsafe`. |
| [`tc_sparkle_aead`](tc_sparkle_aead) | [![crates.io](https://img.shields.io/crates/v/tc_sparkle_aead.svg)](https://crates.io/crates/tc_sparkle_aead) [![docs.rs](https://docs.rs/tc_sparkle_aead/badge.svg)](https://docs.rs/tc_sparkle_aead) | The four SCHWAEMM parameter sets over the SPARKLE permutation, with an SSE2 permutation after run-time detection on x86, its only `unsafe` code. Constant time. `no_std`, no allocator, no features. |

## Requirements

Rust 1.85 or later, edition 2024. Every crate builds without `std` and
reaches the heap only through its default-off `alloc` feature.

Rust 1.85 is the earliest compiler for edition 2024, and it is guaranteed for
every build, since every dependency is a `tc_*` crate; dev-dependencies used
only by tests are exempt. The workspace lock tracks the latest dependency
releases, so CI on stable tests what a user on a current toolchain resolves.

## Workspace checks

```text
cargo test --locked
cargo test --locked --all-features
cargo fmt --all -- --check
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo doc --locked --no-deps --all-features
```

CI additionally runs these on Linux x64, i686 and ARM64, macOS ARM64, and
Windows x64, tests the portable SPARKLE permutation on x86 hosts with SSE2
detection disabled, checks the `wasm32-unknown-unknown` and
`aarch64-unknown-none` targets and each crate's dependency set on each
target, checks the build on Rust 1.85.0, and verifies the package archives.
See
[.github/workflows/ci.yml](.github/workflows/ci.yml).

## License

Licensed under either the [MIT license](LICENSE-MIT) or the
[Apache License, Version 2.0](LICENSE-APACHE), at your option.
