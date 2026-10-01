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
`no_std` and needs no allocator by default. Features are default-off and
additive: `alloc` on `tc_block_cipher`, `tc_block_modes` and `tc_rc_cipher`,
`rustcrypto` on `tc_aes`, `tc_des`, `tc_aria` and `tc_rc_cipher`, and
`rand_core` on `tc_block_padding`.
`tc_block_cipher` depends on `tc_zeroize` alone; `tc_aes` adds
`tc_block_cipher` and, on x86 targets only, `tc_runtime`; `tc_des`, `tc_aria`,
`tc_rc_cipher`, `tc_dstu7624` and `tc_block_modes` add `tc_block_cipher` on
every target; `tc_block_padding`
depends on nothing by default. CI enforces each
crate's default dependency set with `cargo tree` on the
`wasm32-unknown-unknown`, `aarch64-unknown-none` and x86 targets.
`tc_block_cipher` carries no algorithm knowledge: key lengths,
round counts, S-boxes and timing guarantees belong to the engine crates built
on it, such as `tc_aes` and `tc_des`, never to `tc_block_cipher`.

`tc_aes` is constant time on its AES-NI and RustCrypto engines and variable
time on its table and light engines. Every `tc_des`, `tc_aria` and
`tc_dstu7624` engine is variable time, as is every RC2 engine in `tc_rc_cipher`; its RC5 and RC6
engines are constant time only on processors with fixed-latency rotations and,
for RC6, multiplication. `tc_block_modes` adds only data-independent work, so each mode
is constant time exactly when its engine is. `tc_block_padding` adds and
checks padding in constant time with respect to the block contents; only
`pad_count`'s result reveals the count and whether the padding was valid.
`tests/documentation.rs` in `tc_des`, `tc_aria`, `tc_rc_cipher`,
`tc_dstu7624`, `tc_block_modes` and `tc_block_padding` requires each declaration it scans to
say which. Keep the timing contract of each item stated in its doc
comment, and do not let a dispatcher (`AesEngine`, `DesEngine`,
`DesEdeEngine`, `AriaEngine`, `Rc2Engine`) select a leakier engine where a less leaky one
is available.

Rust 1.85 is guaranteed only where the workspace controls every crate: the
default build and first-party features such as `alloc`, whose dependencies are
all `tc_*` crates. A feature that enables a third-party crate (`rustcrypto`
enables `aes`, 0.9.3 of which requires 1.89) follows that crate's MSRV, and
dev-dependencies (`criterion` requires 1.86) are exempt. The MSRV job therefore
runs `cargo check` on 1.85 for the guaranteed builds only; tests run on stable.
`.cargo/config.toml` sets `incompatible-rust-versions = "allow"` so
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
`RUSTDOCFLAGS: -D warnings`, with and without `--all-features`. An additive
public API change belongs in the crate README's contract lists — "Traits" and
"Types" in `tc_block_cipher/README.md`, `tc_block_modes/README.md` and
`tc_block_padding/README.md` and `tc_rc_cipher/README.md`,
"Types" in `tc_aes/README.md`, `tc_des/README.md`, `tc_aria/README.md` and
`tc_dstu7624/README.md` —
and in the changelog, not only in the code.

Work happens on `feat/*` branches off `develop`; pull requests target `develop`,
which merges to `main`. Commit messages use an imperative subject and a wrapped
body that explains the reasoning, not a bullet list of the diff.

Note: the root `Cargo.toml` uses CRLF line endings while the rest of the tree
uses LF. Tools that rewrite whole files will flip it and produce a noisy diff.
