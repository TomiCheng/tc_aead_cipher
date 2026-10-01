use tc_aead_cipher::{
    AeadCipher, AeadCipherInit, AeadError, AeadInitError, AeadParamsRef, FixedGrain128Aead,
};
use tc_block_cipher::CipherDirection;

const KEY_BYTES: usize = 16;
const NONCE_BYTES: usize = 12;
const TAG_BYTES: usize = 8;

#[test]
fn the_fixed_engine_matches_the_official_vector_with_incremental_aad() {
    let key = core::array::from_fn::<_, KEY_BYTES, _>(|index| index as u8);
    let nonce = core::array::from_fn::<_, NONCE_BYTES, _>(|index| index as u8);
    let aad = core::array::from_fn::<_, 16, _>(|index| index as u8);
    let plaintext = core::array::from_fn::<_, 16, _>(|index| index as u8);
    let params = AeadParamsRef::new(&key, &nonce, 8, &[]);
    let mut engine = FixedGrain128Aead::<16>::new();

    engine.init(CipherDirection::Encrypt, &params).unwrap();
    engine.process_aad_bytes(&aad[..7]).unwrap();
    engine.process_aad_bytes(&aad[7..]).unwrap();

    let mut output = [0_u8; 16 + TAG_BYTES];
    let mut written = engine.process_bytes(&plaintext, &mut output).unwrap();
    written += engine.do_final(&mut output[written..]).unwrap();

    assert_eq!(written, output.len());
    assert_eq!(
        output,
        [
            0x80, 0xB5, 0x3B, 0xE2, 0x8E, 0x93, 0x8B, 0xAE, 0x76, 0xB6, 0x4C, 0xCD, 0x53, 0xBE,
            0x4D, 0xE5, 0xFB, 0x07, 0x20, 0xDE, 0x18, 0xEA, 0x8F, 0xAE,
        ]
    );
}

#[test]
fn aad_beyond_the_fixed_capacity_is_rejected() {
    let key = [0_u8; KEY_BYTES];
    let nonce = [0_u8; NONCE_BYTES];
    let params = AeadParamsRef::new(&key, &nonce, 8, &[]);
    let mut engine = FixedGrain128Aead::<3>::new();

    engine.init(CipherDirection::Encrypt, &params).unwrap();
    engine.process_aad_bytes(&[1, 2]).unwrap();
    assert_eq!(
        engine.process_aad_bytes(&[3, 4]),
        Err(AeadError::AadTooLong {
            maximum: 3,
            actual: 4,
        })
    );
}

#[test]
fn initial_aad_beyond_the_fixed_capacity_is_rejected() {
    let key = [0_u8; KEY_BYTES];
    let nonce = [0_u8; NONCE_BYTES];
    let params = AeadParamsRef::new(&key, &nonce, 8, &[1, 2]);
    let mut engine = FixedGrain128Aead::<1>::new();

    assert_eq!(
        engine.init(CipherDirection::Encrypt, &params),
        Err(AeadInitError::InvalidInitialAadLength { actual: 2 })
    );
}
