//! Authenticated block-cipher construction contract.

use crate::AeadCipher;
use tc_block_cipher::BlockCipher;

pub trait AeadBlockCipher: AeadCipher {
    type Cipher: BlockCipher + ?Sized;

    fn block_size(&self) -> usize {
        self.underlying_cipher().block_size()
    }

    fn underlying_cipher(&self) -> &Self::Cipher;
}
