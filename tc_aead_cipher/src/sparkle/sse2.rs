//! SSE2 implementation of SPARKLE with a 16-word state.

#[cfg(target_arch = "x86")]
use core::arch::x86::*;
#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::*;

use tc_runtime::intrinsics::x86::Sse2;

use super::engine::{MAX_STATE_WORDS, RCON};

/// Applies the SPARKLE permutation to a 16-word state using SSE2.
///
/// The proof token keeps the target-feature safety requirement out of the
/// caller. Only `Sse2::detect()` can construct it.
pub(crate) fn sparkle_opt16(state: &mut [u32; MAX_STATE_WORDS], steps: usize, _sse2: Sse2) {
    debug_assert_eq!(steps & 1, 0);

    // SAFETY: `_sse2` proves that the current processor supports SSE2.
    unsafe { sparkle_opt16_inner(state, steps) }
}

// Rust 1.85 still declares these intrinsics `unsafe fn`, so the helpers need an
// `unsafe` block. From 1.87 they are safe inside an SSE2 `target_feature`
// function and the same block is reported as unused. Drop the blocks and the
// `allow` once the MSRV reaches 1.87.
#[inline]
#[target_feature(enable = "sse2")]
#[allow(unused_unsafe)]
unsafe fn set4(a: u32, b: u32, c: u32, d: u32) -> __m128i {
    unsafe { _mm_setr_epi32(a as i32, b as i32, c as i32, d as i32) }
}

#[inline]
#[target_feature(enable = "sse2")]
#[allow(unused_unsafe)]
unsafe fn arx_box(rc: __m128i, x: &mut __m128i, y: &mut __m128i) {
    unsafe {
        *x = _mm_add_epi32(
            *x,
            _mm_add_epi32(_mm_srli_epi32::<31>(*y), _mm_slli_epi32::<1>(*y)),
        );
        *y = _mm_xor_si128(
            *y,
            _mm_xor_si128(_mm_srli_epi32::<24>(*x), _mm_slli_epi32::<8>(*x)),
        );
        *x = _mm_xor_si128(*x, rc);

        *x = _mm_add_epi32(
            *x,
            _mm_add_epi32(_mm_srli_epi32::<17>(*y), _mm_slli_epi32::<15>(*y)),
        );
        *y = _mm_xor_si128(
            *y,
            _mm_xor_si128(_mm_srli_epi32::<17>(*x), _mm_slli_epi32::<15>(*x)),
        );
        *x = _mm_xor_si128(*x, rc);

        *x = _mm_add_epi32(*x, *y);
        *y = _mm_xor_si128(
            *y,
            _mm_xor_si128(_mm_srli_epi32::<31>(*x), _mm_slli_epi32::<1>(*x)),
        );
        *x = _mm_xor_si128(*x, rc);

        *x = _mm_add_epi32(
            *x,
            _mm_add_epi32(_mm_srli_epi32::<24>(*y), _mm_slli_epi32::<8>(*y)),
        );
        *y = _mm_xor_si128(
            *y,
            _mm_xor_si128(_mm_srli_epi32::<16>(*x), _mm_slli_epi32::<16>(*x)),
        );
        *x = _mm_xor_si128(*x, rc);
    }
}

#[inline]
#[target_feature(enable = "sse2")]
#[allow(unused_unsafe)]
unsafe fn ell(value: __m128i) -> __m128i {
    unsafe {
        let high = _mm_slli_epi32::<16>(value);
        let combined = _mm_xor_si128(value, high);
        _mm_xor_si128(high, _mm_srli_epi32::<16>(combined))
    }
}

#[inline]
#[target_feature(enable = "sse2")]
#[allow(unused_unsafe)]
unsafe fn horizontal_xor(value: __m128i) -> __m128i {
    unsafe {
        let paired = _mm_xor_si128(value, _mm_shuffle_epi32::<0x1b>(value));
        _mm_xor_si128(paired, _mm_shuffle_epi32::<0xb1>(paired))
    }
}

/// # Safety
///
/// The caller must establish SSE2 support.
#[target_feature(enable = "sse2")]
unsafe fn sparkle_opt16_inner(state: &mut [u32; MAX_STATE_WORDS], steps: usize) {
    unsafe {
        let mut s0246 = set4(state[0], state[2], state[4], state[6]);
        let mut s1357 = set4(state[1], state[3], state[5], state[7]);
        let mut s8ace = set4(state[8], state[10], state[12], state[14]);
        let mut s9bdf = set4(state[9], state[11], state[13], state[15]);

        let rc03 = set4(RCON[0], RCON[1], RCON[2], RCON[3]);
        let rc47 = set4(RCON[4], RCON[5], RCON[6], RCON[7]);

        for step in 0..steps {
            let round_ant = set4(RCON[step & 7], step as u32, 0, 0);
            s1357 = _mm_xor_si128(s1357, round_ant);

            arx_box(rc03, &mut s0246, &mut s1357);
            arx_box(rc47, &mut s8ace, &mut s9bdf);

            let t0246 = ell(horizontal_xor(s0246));
            let t1357 = ell(horizontal_xor(s1357));
            let u0246 = _mm_xor_si128(s0246, s8ace);
            let u1357 = _mm_xor_si128(s1357, s9bdf);

            s8ace = s0246;
            s9bdf = s1357;
            s0246 = _mm_xor_si128(t1357, _mm_shuffle_epi32::<0x39>(u0246));
            s1357 = _mm_xor_si128(t0246, _mm_shuffle_epi32::<0x39>(u1357));
        }

        _mm_storeu_si128(state.as_mut_ptr().cast(), _mm_unpacklo_epi32(s0246, s1357));
        _mm_storeu_si128(
            state.as_mut_ptr().add(4).cast(),
            _mm_unpackhi_epi32(s0246, s1357),
        );
        _mm_storeu_si128(
            state.as_mut_ptr().add(8).cast(),
            _mm_unpacklo_epi32(s8ace, s9bdf),
        );
        _mm_storeu_si128(
            state.as_mut_ptr().add(12).cast(),
            _mm_unpackhi_epi32(s8ace, s9bdf),
        );
    }
}
