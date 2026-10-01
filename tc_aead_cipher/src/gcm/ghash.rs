//! Portable GHASH arithmetic used internally by GCM.

use super::BLOCK_BYTES;
use tc_zeroize::{Zeroize, ZeroizeOnDrop};

pub(crate) struct Multiplier {
    h: [u8; BLOCK_BYTES],
}

impl Multiplier {
    pub(crate) const fn new(h: [u8; BLOCK_BYTES]) -> Self {
        Self { h }
    }

    pub(crate) fn multiply_h(&self, value: &mut [u8; BLOCK_BYTES]) {
        *value = multiply(value, &self.h);
    }

    pub(crate) const fn h(&self) -> &[u8; BLOCK_BYTES] {
        &self.h
    }
}

impl Zeroize for Multiplier {
    fn zeroize(&mut self) {
        self.h.zeroize();
    }
}

impl Drop for Multiplier {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for Multiplier {}

fn multiply(left: &[u8; BLOCK_BYTES], right: &[u8; BLOCK_BYTES]) -> [u8; BLOCK_BYTES] {
    let mut product = [0u8; BLOCK_BYTES];
    let mut factor = *right;

    for bit_index in 0..128 {
        let bit = (left[bit_index / 8] >> (7 - bit_index % 8)) & 1;
        let bit_mask = 0u8.wrapping_sub(bit);
        for index in 0..BLOCK_BYTES {
            product[index] ^= factor[index] & bit_mask;
        }

        let reduce = factor[BLOCK_BYTES - 1] & 1;
        let mut carry = 0u8;
        for byte in &mut factor {
            let next_carry = (*byte & 1) << 7;
            *byte = (*byte >> 1) | carry;
            carry = next_carry;
        }
        factor[0] ^= 0xe1 & 0u8.wrapping_sub(reduce);
    }

    product
}
