# tc_ascon_aead

[![crates.io](https://img.shields.io/crates/v/tc_ascon_aead.svg)](https://crates.io/crates/tc_ascon_aead)
[![docs.rs](https://docs.rs/tc_ascon_aead/badge.svg)](https://docs.rs/tc_ascon_aead)
[![CI](https://github.com/TomiCheng/tc_aead_cipher/actions/workflows/ci.yml/badge.svg)](https://github.com/TomiCheng/tc_aead_cipher/actions/workflows/ci.yml)
[![license](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](#license)
![rustc](https://img.shields.io/badge/rustc-1.85+-blue.svg)

Ascon authenticated encryption: Ascon-AEAD128, standardized in NIST
SP 800-232, and the Ascon-128, Ascon-128a and Ascon-80pq variants of Ascon
v1.2. Both engines implement the `AeadCipher` and `AeadCipherInit` contracts
of [`tc_aead_cipher`](https://crates.io/crates/tc_aead_cipher). Ported from
Bouncy Castle C#.

The crate is `no_std`, needs no allocator and contains no `unsafe` code. It
has no features and depends on `tc_aead_cipher`, `tc_block_cipher`,
[`tc_constant_time`](https://crates.io/crates/tc_constant_time) and
[`tc_zeroize`](https://crates.io/crates/tc_zeroize).

Requires Rust 1.85 or later (edition 2024).

## Types

- `AsconAead128Engine` — Ascon-AEAD128 with 16-byte keys and nonces and tags
  of 4 to 16 bytes.
- `AsconLegacyEngine`, `AsconLegacyVariant` — Ascon-128, Ascon-128a and
  Ascon-80pq from Ascon v1.2, with 16-byte nonces and tags.

A truncated Ascon-AEAD128 tag is the leftmost bytes of the full tag, as
SP 800-232 specifies. The legacy variants take 16-byte keys, 20 for
Ascon-80pq, and produce different output from Ascon-AEAD128, so they serve
only data produced before the standard. Tag sizes are in bytes, not bits as
in Bouncy Castle. `Display` writes `"Ascon-AEAD128"`, `"Ascon-128 AEAD"`,
`"Ascon-128a AEAD"` or `"Ascon-80pq AEAD"`.

## Usage

```toml
[dependencies]
tc_ascon_aead = "0.1.0"
tc_aead_cipher = "0.1.0"
tc_block_cipher = "0.1.0"
```

```rust
use tc_aead_cipher::{AeadCipher, AeadCipherInit, AeadParamsRef};
use tc_ascon_aead::AsconAead128Engine;
use tc_block_cipher::CipherDirection;

let (key, nonce) = ([0x42; 16], [0x24; 16]);
let mut ascon = AsconAead128Engine::new();
ascon.init(CipherDirection::Encrypt, &AeadParamsRef::new(&key, &nonce, 16, b"header")).expect("valid sizes");
let mut sealed = [0; 14 + 16];
let written = ascon.process_bytes(b"attack at dawn", &mut sealed).expect("initialized");
ascon.do_final(&mut sealed[written..]).expect("room for the tag");
```

The type documentation carries an executable example for both engines.

## Security

Never encrypt two messages under one key and nonce. Encryption refuses an
`init` that repeats the previous key and nonce of the same instance, but
nothing tracks nonces across instances or restarts. Decryption may
write plaintext before `do_final` verifies the tag; discard all of it when
`do_final` fails.

Both engines are constant time: the permutation is a bitsliced S-box and
linear layer on 64-bit words, without tables or data-dependent branches, and
tags are compared in fixed time. Lengths are public, and the result of a tag
check shows in the outcome.

The engines wipe their key, state and buffers on drop. Wiping does not reach
the caller's buffers or copies left in registers and on the stack.

## Validation

Ascon-AEAD128 and the three Ascon v1.2 variants are tested against their
official known-answer vectors. Contract tests cover associated data and
messages split across calls, initial associated data, truncated tags,
`reset`, nonce-reuse detection, tampering and size errors. A test requires every public API to
document whether it is constant or variable time.

Missing public documentation and `unsafe` code are rejected by crate-level
lints.

Run these commands from the workspace root:

```text
cargo test -p tc_ascon_aead --locked
cargo clippy -p tc_ascon_aead --all-targets --locked -- -D warnings
cargo fmt -p tc_ascon_aead --check
cargo doc -p tc_ascon_aead --no-deps --locked
```

Before a release, check the archive contents and run publication validation
from a committed checkout, after `tc_aead_cipher` is published:

```text
cargo package -p tc_ascon_aead --list --locked
cargo publish -p tc_ascon_aead --dry-run --locked
```

The archive includes both license texts, this README, the changelog, the source
and the integration tests. It must not include `target/` or other build
artifacts.

## License

Licensed under either the [MIT license](LICENSE-MIT) or the
[Apache License, Version 2.0](LICENSE-APACHE), at your option.
