#![cfg(feature = "alloc")]

use tc_aead_cipher::{AeadCipher, AeadCipherInit, AeadError, AeadParamsRef, KccmBlockCipher};
use tc_block_cipher::CipherDirection;
use tc_dstu7624::Dstu7624Engine128;

#[test]
fn reset_discards_packet_data_preserves_initial_aad_and_blocks_nonce_reuse() {
    let key = [0x11; 16];
    let nonce = [0x22; 16];
    let initial_aad = [0x33; 16];
    let params = AeadParamsRef::new(&key, &nonce, 16, &initial_aad);
    let plaintext = [0x44; 16];

    let mut expected_engine = KccmBlockCipher::new(Dstu7624Engine128::new());
    expected_engine
        .init(CipherDirection::Encrypt, &params)
        .unwrap();
    expected_engine.process_bytes(&plaintext, &mut []).unwrap();
    let mut expected = [0u8; 32];
    expected_engine.do_final(&mut expected).unwrap();

    let mut engine = KccmBlockCipher::new(Dstu7624Engine128::new());
    engine.init(CipherDirection::Encrypt, &params).unwrap();
    engine.process_aad_bytes(&[0x55; 16]).unwrap();
    engine.process_bytes(&[0x66; 16], &mut []).unwrap();
    engine.reset();
    engine.process_bytes(&plaintext, &mut []).unwrap();
    let mut actual = [0u8; 32];
    engine.do_final(&mut actual).unwrap();
    assert_eq!(actual, expected);

    engine.reset();
    assert!(matches!(
        engine.process_bytes(&[], &mut []),
        Err(AeadError::AlreadyFinalized)
    ));
}
