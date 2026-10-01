#![cfg(feature = "alloc")]

use tc_aead_cipher::{
    AeadCipher, AeadCipherInit, AeadError, AeadParamsRef, FixedGrain128Aead, Grain128Aead,
};
use tc_block_cipher::CipherDirection;

const KEY_BYTES: usize = 16;
const NONCE_BYTES: usize = 12;
const TAG_BYTES: usize = 8;

fn ciphertext() -> ([u8; KEY_BYTES], [u8; NONCE_BYTES], Vec<u8>) {
    let key = [0x11; KEY_BYTES];
    let nonce = [0x22; NONCE_BYTES];
    let params = AeadParamsRef::new(&key, &nonce, 8, b"initial aad");
    let plaintext = b"grain reset";
    let mut encryptor = Grain128Aead::new();
    encryptor.init(CipherDirection::Encrypt, &params).unwrap();
    let mut output = vec![0u8; plaintext.len() + TAG_BYTES];
    let mut written = encryptor.process_bytes(plaintext, &mut output).unwrap();
    written += encryptor.do_final(&mut output[written..]).unwrap();
    output.truncate(written);
    encryptor.reset();
    assert_eq!(
        encryptor.process_bytes(&[], &mut []),
        Err(AeadError::AlreadyFinalized)
    );
    (key, nonce, output)
}

#[test]
fn reset_restores_allocating_decryptor_with_initial_aad() {
    let (key, nonce, ciphertext) = ciphertext();
    let params = AeadParamsRef::new(&key, &nonce, 8, b"initial aad");
    let mut decryptor = Grain128Aead::new();
    decryptor.init(CipherDirection::Decrypt, &params).unwrap();
    decryptor.process_aad_bytes(b"discarded").unwrap();
    decryptor.process_bytes(&ciphertext[..4], &mut []).unwrap();
    decryptor.reset();

    let mut recovered = vec![0u8; b"grain reset".len()];
    let mut written = decryptor
        .process_bytes(&ciphertext, &mut recovered)
        .unwrap();
    written += decryptor.do_final(&mut recovered[written..]).unwrap();
    assert_eq!(&recovered[..written], b"grain reset");
}

#[test]
fn reset_restores_fixed_decryptor_with_initial_aad() {
    let (key, nonce, ciphertext) = ciphertext();
    let params = AeadParamsRef::new(&key, &nonce, 8, b"initial aad");
    let mut decryptor = FixedGrain128Aead::<32>::new();
    decryptor.init(CipherDirection::Decrypt, &params).unwrap();
    decryptor.process_aad_bytes(b"discarded").unwrap();
    decryptor.reset();

    let mut recovered = [0u8; 11];
    let mut written = decryptor
        .process_bytes(&ciphertext, &mut recovered)
        .unwrap();
    written += decryptor.do_final(&mut recovered[written..]).unwrap();
    assert_eq!(&recovered[..written], b"grain reset");
}

#[test]
fn reset_right_after_an_encryption_init_with_initial_aad_keeps_the_engine_usable() {
    let (key, nonce, expected) = ciphertext();
    let params = AeadParamsRef::new(&key, &nonce, 8, b"initial aad");
    let mut encryptor = Grain128Aead::new();
    encryptor.init(CipherDirection::Encrypt, &params).unwrap();
    encryptor.reset();
    let mut output = vec![0u8; expected.len()];
    let mut written = encryptor
        .process_bytes(b"grain reset", &mut output)
        .unwrap();
    written += encryptor.do_final(&mut output[written..]).unwrap();
    assert_eq!(output[..written], expected[..]);
}
