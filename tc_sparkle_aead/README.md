# tc_sparkle_aead

[![crates.io](https://img.shields.io/crates/v/tc_sparkle_aead.svg)](https://crates.io/crates/tc_sparkle_aead)
[![docs.rs](https://docs.rs/tc_sparkle_aead/badge.svg)](https://docs.rs/tc_sparkle_aead)
[![CI](https://github.com/TomiCheng/tc_aead_cipher/actions/workflows/ci.yml/badge.svg)](https://github.com/TomiCheng/tc_aead_cipher/actions/workflows/ci.yml)
[![license](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](#license)
![rustc](https://img.shields.io/badge/rustc-1.85+-blue.svg)

SCHWAEMM authenticated encryption, the AEAD family built on the SPARKLE
permutation, a finalist of the NIST lightweight cryptography competition. The
engine implements the `AeadCipher` and `AeadCipherInit` contracts of
[`tc_aead_cipher`](https://crates.io/crates/tc_aead_cipher). Ported from
Bouncy Castle C#.

The crate is `no_std` and needs no allocator. It has no features and depends
on `tc_aead_cipher`, `tc_block_cipher`,
[`tc_constant_time`](https://crates.io/crates/tc_constant_time) and
[`tc_zeroize`](https://crates.io/crates/tc_zeroize), and on x86 targets also
on [`tc_runtime`](https://crates.io/crates/tc_runtime) for SSE2 detection.

Requires Rust 1.85 or later (edition 2024).

## Types

- `SparkleEngine` — SCHWAEMM for the parameter set chosen at construction.
- `SparkleVariant` — the parameter set, with its key, nonce and tag sizes.

The four parameter sets are SCHWAEMM128-128 (16-byte key, nonce and tag),
SCHWAEMM256-128 (16-byte key and tag, 32-byte nonce), SCHWAEMM192-192 (24
bytes each) and SCHWAEMM256-256 (32 bytes each). `init` rejects a tag size
other than the variant's. `Display` writes the variant's name, such as
`"SCHWAEMM128-128"`.

On x86, SCHWAEMM256-256 runs its 16-word permutation with SSE2 when run-time
detection finds it, and with the portable permutation otherwise, which
enabling `tc_runtime`'s `disable-x86-sse2` feature also selects.

## Usage

```toml
[dependencies]
tc_sparkle_aead = "0.1.0"
tc_aead_cipher = "0.1.0"
tc_block_cipher = "0.1.0"
```

```rust
use tc_aead_cipher::{AeadCipher, AeadCipherInit, AeadParamsRef};
use tc_block_cipher::CipherDirection;
use tc_sparkle_aead::{SparkleEngine, SparkleVariant};

let (key, nonce) = ([0x42; 16], [0x24; 16]);
let mut schwaemm = SparkleEngine::new(SparkleVariant::Schwaemm128_128);
schwaemm.init(CipherDirection::Encrypt, &AeadParamsRef::new(&key, &nonce, 16, b"header")).expect("valid sizes");
let mut sealed = [0; 14 + 16];
let written = schwaemm.process_bytes(b"attack at dawn", &mut sealed).expect("initialized");
schwaemm.do_final(&mut sealed[written..]).expect("room for the tag");
```

The type documentation carries an executable example.

## Security

Never encrypt two messages under one key and nonce. The engine does not
detect a repeated nonce, so the caller must guarantee it. Decryption may write
plaintext before `do_final` verifies the tag; discard all of it when
`do_final` fails.

The engine is constant time: SPARKLE adds, rotates and XORs 32-bit words, its
SSE2 form does the same work, and tags are compared in fixed time. Lengths
are public, and the result of a tag check shows in the outcome. The SSE2
permutation is the crate's only `unsafe` code; it runs only after detection
has proved the instructions are available.

The engine wipes its key, state and buffers on drop. Wiping does not reach the
caller's buffers or copies left in registers and on the stack.

## Validation

All four parameter sets are tested against the official SCHWAEMM
known-answer vectors, and the SSE2 permutation against the portable one. CI
also runs the tests on x86 with SSE2 detection disabled. Contract tests cover
associated data and messages split across calls, initial associated data, the
tag size, `reset`, tampering and size errors. A test requires every public
API to document whether it is constant or variable time.

Missing public documentation is rejected by a crate-level lint, as is
`unsafe` code outside the SSE2 permutation.

Run these commands from the workspace root:

```text
cargo test -p tc_sparkle_aead --locked
cargo test -p tc_sparkle_aead --locked --features tc_runtime/disable-x86-sse2
cargo clippy -p tc_sparkle_aead --all-targets --locked -- -D warnings
cargo fmt -p tc_sparkle_aead --check
cargo doc -p tc_sparkle_aead --no-deps --locked
```

Before a release, check the archive contents and run publication validation
from a committed checkout, after `tc_aead_cipher` is published:

```text
cargo package -p tc_sparkle_aead --list --locked
cargo publish -p tc_sparkle_aead --dry-run --locked
```

The archive includes both license texts, this README, the changelog, the source
and the integration tests. It must not include `target/` or other build
artifacts.

## License

Licensed under either the [MIT license](LICENSE-MIT) or the
[Apache License, Version 2.0](LICENSE-APACHE), at your option.
