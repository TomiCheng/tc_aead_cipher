#![cfg(feature = "alloc")]

use tc_aead_cipher::{AeadCipher, AeadCipherInit, AeadError, AeadParamsRef, OcbBlockCipher};
use tc_aes::AesEngine;
use tc_block_cipher::CipherDirection;

#[test]
fn reset_discards_packet_data_preserves_initial_aad_and_blocks_nonce_reuse() {
    let key = [0x11; 16];
    let nonce = [0x22; 12];
    let params = AeadParamsRef::new(&key, &nonce, 16, b"initial aad");
    let plaintext = b"ocb reset";

    let mut expected_engine = OcbBlockCipher::new(AesEngine::new(), AesEngine::new());
    expected_engine
        .init(CipherDirection::Encrypt, &params)
        .unwrap();
    expected_engine.process_bytes(plaintext, &mut []).unwrap();
    let mut expected = [0u8; 25];
    expected_engine.do_final(&mut expected).unwrap();

    let mut engine = OcbBlockCipher::new(AesEngine::new(), AesEngine::new());
    engine.init(CipherDirection::Encrypt, &params).unwrap();
    engine.process_aad_bytes(b"discarded").unwrap();
    engine.process_bytes(b"discarded", &mut []).unwrap();
    engine.reset();
    engine.process_bytes(plaintext, &mut []).unwrap();
    let mut actual = [0u8; 25];
    engine.do_final(&mut actual).unwrap();
    assert_eq!(actual, expected);

    engine.reset();
    assert!(matches!(
        engine.process_bytes(&[], &mut []),
        Err(AeadError::AlreadyFinalized)
    ));
}
