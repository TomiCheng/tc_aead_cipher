//! Authenticated block-cipher construction contract.

use crate::AeadCipher;
use tc_block_cipher::BlockCipher;

/// An [`AeadCipher`] built on a block cipher, which it exposes.
pub trait AeadBlockCipher: AeadCipher {
    /// The block cipher the construction runs on.
    type Cipher: BlockCipher + ?Sized;

    /// Returns the underlying cipher's block size in bytes.
    fn block_size(&self) -> usize {
        self.underlying_cipher().block_size()
    }

    /// Returns the block cipher the construction runs on.
    fn underlying_cipher(&self) -> &Self::Cipher;
}
