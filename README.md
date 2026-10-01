# tc_block_cipher

A Rust workspace for block ciphers. It holds `tc_block_cipher`, the shared
traits, errors and key containers through which an engine is initialized and
processes one block, and the crates built on it: the engines `tc_aes`,
`tc_des`, `tc_aria`, `tc_rc_cipher` and `tc_dstu7624`; `tc_block_modes`, the
modes of operation that run over any of them; and `tc_block_padding`, the padding
schemes for the modes that process whole blocks.
Each crate is published separately and keeps its own README, changelog, and
validation commands.

[![CI](https://github.com/TomiCheng/tc_block_cipher/actions/workflows/ci.yml/badge.svg)](https://github.com/TomiCheng/tc_block_cipher/actions/workflows/ci.yml)
[![license](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](#license)
![rustc](https://img.shields.io/badge/rustc-1.85+-blue.svg)

## Crates

| Crate | Version | Description |
| --- | --- | --- |
| [`tc_block_cipher`](tc_block_cipher) | [![crates.io](https://img.shields.io/crates/v/tc_block_cipher.svg)](https://crates.io/crates/tc_block_cipher) [![docs.rs](https://docs.rs/tc_block_cipher/badge.svg)](https://docs.rs/tc_block_cipher) | Initialization and single-block processing traits, reusable error types, and key containers that borrow, or own and wipe, key bytes. No algorithm, mode, padding or authentication. `no_std`, no `unsafe`, depends only on `tc_zeroize`; a default-off `alloc` feature adds a vector-backed key container. |
| [`tc_aes`](tc_aes) | [![crates.io](https://img.shields.io/crates/v/tc_aes.svg)](https://crates.io/crates/tc_aes) [![docs.rs](https://docs.rs/tc_aes/badge.svg)](https://docs.rs/tc_aes) | AES-128, AES-192 and AES-256 with AES-NI, table-based and small-footprint engines, and a dispatcher that picks the safest one at runtime. `no_std`, no allocator; depends on `tc_block_cipher`, `tc_zeroize`, and `tc_runtime` on x86 only. A default-off `rustcrypto` feature adds a constant-time engine backed by RustCrypto's `aes`. |
| [`tc_des`](tc_des) | [![crates.io](https://img.shields.io/crates/v/tc_des.svg)](https://crates.io/crates/tc_des) [![docs.rs](https://docs.rs/tc_des/badge.svg)](https://docs.rs/tc_des) | DES and EDE Triple DES for legacy interoperability, with table-based engines and dispatchers that pick an engine at compile time. Every engine is variable time. `no_std`, no allocator, no `unsafe`; depends on `tc_block_cipher` and `tc_zeroize`. A default-off `rustcrypto` feature adds engines backed by RustCrypto's `des`, which the dispatchers then use because they leak less. |
| [`tc_aria`](tc_aria) | [![crates.io](https://img.shields.io/crates/v/tc_aria.svg)](https://crates.io/crates/tc_aria) [![docs.rs](https://docs.rs/tc_aria/badge.svg)](https://docs.rs/tc_aria) | ARIA-128, ARIA-192 and ARIA-256 (RFC 5794) with a table-based engine and a dispatcher that picks an engine at compile time. Every engine is variable time. `no_std`, no allocator, no `unsafe`; depends on `tc_block_cipher` and `tc_zeroize`. A default-off `rustcrypto` feature adds an engine backed by RustCrypto's `aria`, which the dispatcher then uses. |
| [`tc_block_modes`](tc_block_modes) | [![crates.io](https://img.shields.io/crates/v/tc_block_modes.svg)](https://crates.io/crates/tc_block_modes) [![docs.rs](https://docs.rs/tc_block_modes/badge.svg)](https://docs.rs/tc_block_modes) | ECB, CBC, CFB, OFB and CTR modes of operation over any engine, and key-and-IV containers that borrow, or own and wipe, their bytes. Each mode adds only data-independent work, so it is constant time exactly when its engine is. `no_std`, no allocator, no `unsafe`; depends on `tc_block_cipher` and `tc_zeroize`. A default-off `alloc` feature adds runtime-sized modes and a vector-backed container. |
| [`tc_block_padding`](tc_block_padding) | [![crates.io](https://img.shields.io/crates/v/tc_block_padding.svg)](https://crates.io/crates/tc_block_padding) [![docs.rs](https://docs.rs/tc_block_padding/badge.svg)](https://docs.rs/tc_block_padding) | PKCS#7, ISO 7816-4, ANSI X9.23, TBC and zero-byte padding for the modes that process whole blocks, added and checked in constant time with respect to the block contents. `no_std`, no allocator, no `unsafe`, no dependencies. A default-off `rand_core` feature adds ISO 10126 padding, drawing its filler from a generator the caller supplies. |
| [`tc_rc_cipher`](tc_rc_cipher) | [![crates.io](https://img.shields.io/crates/v/tc_rc_cipher.svg)](https://crates.io/crates/tc_rc_cipher) [![docs.rs](https://docs.rs/tc_rc_cipher/badge.svg)](https://docs.rs/tc_rc_cipher) | RC2, RC5 and RC6 for legacy interoperability, with a portable RC2 engine and a dispatcher that picks an engine at compile time. RC2 is variable time; RC5 and RC6 are constant time on processors with fixed-latency rotations and, for RC6, multiplication. `no_std`, no allocator, no `unsafe`; depends on `tc_block_cipher` and `tc_zeroize`. A default-off `rustcrypto` feature adds an RC2 engine backed by RustCrypto's `rc2`, and a default-off `alloc` feature adds parameter types that own and wipe the key. |
| [`tc_dstu7624`](tc_dstu7624) | [![crates.io](https://img.shields.io/crates/v/tc_dstu7624.svg)](https://crates.io/crates/tc_dstu7624) [![docs.rs](https://docs.rs/tc_dstu7624/badge.svg)](https://docs.rs/tc_dstu7624) | DSTU 7624:2014 (Kalyna) with 128-, 256- and 512-bit blocks and one- or two-block keys. Every engine is variable time. `no_std`, no allocator, no `unsafe`; depends on `tc_block_cipher` and `tc_zeroize`. |

`tc_block_cipher` defines the contract and knows no algorithm; each engine
crate implements it and documents its own key lengths and timing guarantees.
`tc_block_modes` builds on the contract alone, so its modes work with any
engine.

## Requirements

Rust 1.85 or later, edition 2024. Every crate builds without `std` and
reaches the heap only through the default-off `alloc` features of
`tc_block_cipher`, `tc_block_modes` and `tc_rc_cipher`.

Rust 1.85 is the earliest compiler for edition 2024, and it is guaranteed for
every build that uses only this workspace's crates and their `tc_*`
dependencies. A feature that enables a third-party crate, such as the
`rustcrypto` features of `tc_aes`, `tc_des`, `tc_aria` and `tc_rc_cipher` or
the `rand_core` feature of `tc_block_padding`, follows that crate's minimum Rust version
instead, and dev-dependencies used only by tests
and benchmarks are exempt. The workspace
lock tracks the latest dependency releases, so CI on stable tests what a user
on a current toolchain resolves.

## Workspace checks

```text
cargo test --locked
cargo test --locked --all-features
cargo fmt --all -- --check
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo doc --locked --no-deps --all-features
```

CI additionally runs these on Linux x64, i686 and ARM64, macOS ARM64, and
Windows x64, tests the AES dispatcher with AES-NI detection disabled, checks
the `wasm32-unknown-unknown` and `aarch64-unknown-none` targets and each
crate's dependency set, checks the build that Rust 1.85.0 covers, and verifies
the package archives. See [.github/workflows/ci.yml](.github/workflows/ci.yml).

## License

Licensed under either the [MIT license](LICENSE-MIT) or the
[Apache License, Version 2.0](LICENSE-APACHE), at your option.
