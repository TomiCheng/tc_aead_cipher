//! Portable POLYVAL arithmetic used internally by GCM-SIV.

use super::BLOCK_BYTES;

pub(crate) struct Polyval {
    h: [u8; BLOCK_BYTES],
    state: [u8; BLOCK_BYTES],
}

impl Polyval {
    pub(crate) fn new(auth_key: [u8; BLOCK_BYTES]) -> Self {
        // POLYVAL can be evaluated through GHASH by reversing every block and
        // multiplying the reversed authentication key by x once (RFC 8452,
        // Appendix A). This mirrors Bouncy Castle's portable implementation.
        let mut h = auth_key;
        h.reverse();
        multiply_x(&mut h);
        Self {
            h,
            state: [0; BLOCK_BYTES],
        }
    }

    pub(crate) fn update_padded(&mut self, mut input: &[u8]) {
        while input.len() >= BLOCK_BYTES {
            let block: &[u8; BLOCK_BYTES] = input[..BLOCK_BYTES].try_into().unwrap();
            self.update_block(block);
            input = &input[BLOCK_BYTES..];
        }

        if !input.is_empty() {
            let mut block = [0u8; BLOCK_BYTES];
            block[..input.len()].copy_from_slice(input);
            self.update_block(&block);
        }
    }

    pub(crate) fn finish(mut self, aad_len: u64, data_len: u64) -> [u8; BLOCK_BYTES] {
        let mut lengths = [0u8; BLOCK_BYTES];
        lengths[..8].copy_from_slice(&(aad_len * 8).to_le_bytes());
        lengths[8..].copy_from_slice(&(data_len * 8).to_le_bytes());
        self.update_block(&lengths);
        self.state.reverse();
        self.state
    }

    fn update_block(&mut self, block: &[u8; BLOCK_BYTES]) {
        for index in 0..BLOCK_BYTES {
            self.state[index] ^= block[BLOCK_BYTES - 1 - index];
        }
        self.state = multiply(&self.state, &self.h);
    }
}

fn multiply_x(value: &mut [u8; BLOCK_BYTES]) {
    let reduce = value[BLOCK_BYTES - 1] & 1;
    let mut carry = 0u8;
    for byte in value.iter_mut() {
        let next_carry = (*byte & 1) << 7;
        *byte = (*byte >> 1) | carry;
        carry = next_carry;
    }
    value[0] ^= 0xe1 & 0u8.wrapping_sub(reduce);
}

fn multiply(left: &[u8; BLOCK_BYTES], right: &[u8; BLOCK_BYTES]) -> [u8; BLOCK_BYTES] {
    let mut product = [0u8; BLOCK_BYTES];
    let mut factor = *right;

    for bit_index in 0..128 {
        let bit = (left[bit_index / 8] >> (7 - bit_index % 8)) & 1;
        let mask = 0u8.wrapping_sub(bit);
        for index in 0..BLOCK_BYTES {
            product[index] ^= factor[index] & mask;
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

#[cfg(test)]
mod tests {
    use super::Polyval;

    #[test]
    fn matches_rfc_8452_field_example() {
        let h = 0x25629347589242761d31f826ba4b757bu128.to_be_bytes();
        let x1 = 0x4f4f95668c83dfb6401762bb2d01a262u128.to_be_bytes();
        let x2 = 0xd1a24ddd2721d006bbe45f20d3c9f362u128.to_be_bytes();
        let expected = 0xf7a3b47b846119fae5b7866cf5e5b77eu128.to_be_bytes();
        let mut polyval = Polyval::new(h);
        polyval.update_padded(&x1);
        polyval.update_padded(&x2);
        let mut actual = polyval.state;
        actual.reverse();
        assert_eq!(actual, expected);
    }
}
