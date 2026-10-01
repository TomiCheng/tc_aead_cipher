# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Rules

- Comments and documentation are written in English only — doc comments,
  README, changelog, and inline comments alike.
- Never wire a README into rustdoc (`#![doc = include_str!("../README.md")]`).
  The README's badges and relative links do not survive rustdoc rendering.
  Crate documentation lives in `//!` and `///` comments; the README repeats what
  a reader on crates.io needs.
- No breaking changes. Public API work is additive: adding items, trait
  implementations, or default methods. If a change cannot be made additively,
  stop and raise it rather than altering an existing signature or behavior.
- Every crate README opens with the badge block: crates.io, docs.rs, CI,
  license, and rustc.
- Crate READMEs use no Markdown tables; crates.io renders them badly. Traits,
  types and features are flat one-line bullets (`` `Item` — what it does. ``),
  with any further detail in the paragraph below the list. Benchmark results
  and how to reproduce them live in the crate's `BENCHES.md`, which is in the
  `include` list, and the README links to it. `BENCHES.md` is read on GitHub,
  so its results may use tables.

The crate list and workspace-wide checks live in the root
[README.md](README.md); read it rather than restating it here. Every crate is
`no_std` and needs no allocator by default. `tc_aead_cipher` holds the
`AeadCipher`, `AeadCipherInit` and `AeadBlockCipher` contracts, the parameter
types and errors, and the modes over a block cipher; its `alloc` feature adds
CCM, GCM-SIV, OCB and KCCM, which buffer the whole message, and
`AeadParamsOwned`. It depends on `tc_block_cipher`, `tc_constant_time` and
`tc_zeroize`. The modes carry no cipher: key lengths and timing guarantees of
the block ciphers belong to their own crates, such as `tc_aes`.

Algorithms that carry their own primitive live in their own crates and
implement the core contracts rather than defining their own:
`tc_ascon_aead` (Ascon-AEAD128 and Ascon v1.2, no features), `tc_grain128_aead`
(Grain-128AEAD; `alloc` adds the `Vec`-backed engine) and `tc_sparkle_aead`
(SCHWAEMM, no features). Each depends on `tc_aead_cipher`, `tc_block_cipher`,
`tc_constant_time` and `tc_zeroize`; `tc_sparkle_aead` adds `tc_runtime` on
x86 targets only, for SSE2 detection. CI enforces every crate's dependency set
with `cargo tree` on the `wasm32-unknown-unknown`, `aarch64-unknown-none` and
x86 targets. A new algorithm belongs in a new crate, not in `tc_aead_cipher`.

Engines that wrap a block cipher are named `XxxBlockCipher`, as in
`tc_block_modes`; engines that carry their own primitive are named
`XxxEngine`, as in `tc_aes`, and their crates `tc_<algorithm>_aead`. Parameter
types only carry values; each engine validates them in `init`. A failed
`init` leaves the engine uninitialized, and `mac()` returns the transmitted
tag. Tag sizes are in bytes. Every engine but GCM-SIV, which tolerates nonce
reuse, refuses an encryption `init` that repeats the previous key and nonce:
the modes compare a key-derived value in fixed time, never a copy of the key,
and the algorithm engines compare the key they already hold, also in fixed
time. A failed `init` keeps the previous key and nonce for the check.

The six modes are constant time exactly when their cipher is. The Ascon,
Grain-128AEAD and SCHWAEMM engines are constant time, the SSE2 form of SPARKLE
included. Lengths are public. Each crate's `tests/documentation.rs` requires
each declaration it scans to say which, and matches the phrase within one
line, so never wrap a line between "constant" or "variable" and "time". Keep
the timing contract of each item stated in its doc comment, and disclose what
cannot be prevented, such as a growing `Vec` freeing its old allocation
unwiped. A failed tag check must never release plaintext from `do_final`.

`unsafe` code is forbidden in every crate but `tc_sparkle_aead`, which denies
it at the crate root and allows it only in its `sse2` module, behind run-time
detection. Keep it there.

Rust 1.85 is guaranteed for every build, since every dependency is a `tc_*`
crate; dev-dependencies are exempt. The MSRV job therefore runs `cargo check`
on 1.85 with and without `alloc`; tests run on stable. Stable Rust reports
some `unsafe` blocks around SPARKLE's SSE2 intrinsics as unused because they
became safe in 1.87, so those helpers carry a scoped `allow(unused_unsafe)`
until the MSRV moves. `.cargo/config.toml` sets `incompatible-rust-versions = "allow"` so
`Cargo.lock` tracks the latest releases and stable CI tests what current
toolchains resolve. Adding a third-party dependency to a default build or a
first-party feature hands the 1.85 guarantee to that crate; raise it before
doing so.

A crate depends on a workspace sibling through `path` plus `version`, so the
workspace builds and tests against the local crate while the published package
requires the release. When a change needs a sibling API that is not released
yet, raise the `version` requirement to the release that adds it; that release
has to be published first.

## Conventions

Each crate ships its own `README.md`, `CHANGELOG.md`, `LICENSE-MIT`,
`LICENSE-APACHE`, and an explicit `include` list in `Cargo.toml`. Changelog
entries are written as `## <version> - Unreleased` and dated in a separate
commit at release, with `### Added` and `### Compatibility` sections.

Adding a crate to the workspace means five edits beyond the crate itself: the
`members` list, a `-p <crate>` on the single `cargo package --locked` step in
the CI `quality` job (the only place package archives are verified; packaging
the crates in one invocation checks each against its siblings' local sources
rather than their releases), a `cargo tree` check of its dependency set in the
CI `portable` job, a row in the root `README.md`, and
workspace inheritance for `edition`, `rust-version`, `license`, and
`repository`. A missing `rust-version` also leaves clippy suggesting APIs newer
than 1.85.

Documentation is part of the contract: crates use `#![deny(missing_docs)]`,
doctests carry the executable examples, and CI runs `cargo doc` with
`RUSTDOCFLAGS: -D warnings`, with and without `--all-features`. Doc links to
feature-gated items break the build without that feature, so name them in plain
code spans. An additive public API change belongs in the crate README's
contract lists — "Types", "Traits" and "Features" in `tc_aead_cipher/README.md`,
"Types" and "Features" in `tc_grain128_aead/README.md`, and "Types" in
`tc_ascon_aead/README.md` and `tc_sparkle_aead/README.md` — and in the
changelog, not only in the code.

Work happens on `feat/*` branches off `develop`; pull requests target `develop`,
which merges to `main`. Commit messages use an imperative subject and a wrapped
body that explains the reasoning, not a bullet list of the diff.

Note: the root `Cargo.toml` uses CRLF line endings while the rest of the tree
uses LF. Tools that rewrite whole files will flip it and produce a noisy diff.
