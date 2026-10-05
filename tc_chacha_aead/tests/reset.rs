use tc_aead_cipher::{AeadCipher, AeadCipherInit, AeadError, AeadParamsRef};
use tc_block_cipher::CipherDirection;
use tc_chacha_aead::{
    ChaCha20Poly1305Engine, KEY_BYTES, NONCE_BYTES, TAG_BYTES, XChaCha20Poly1305Engine,
    XNONCE_BYTES,
};

#[test]
fn reset_restores_chacha_decryption_with_initial_aad() {
    let key = [0x11; KEY_BYTES];
    let nonce = [0x22; NONCE_BYTES];
    let params = AeadParamsRef::new(&key, &nonce, TAG_BYTES, b"initial aad");
    let plaintext = b"chacha reset";
    let mut encryptor = ChaCha20Poly1305Engine::new();
    encryptor.init(CipherDirection::Encrypt, &params).unwrap();
    let mut ciphertext = vec![0u8; plaintext.len() + TAG_BYTES];
    let mut written = encryptor.process_bytes(plaintext, &mut ciphertext).unwrap();
    written += encryptor.do_final(&mut ciphertext[written..]).unwrap();
    ciphertext.truncate(written);
    encryptor.reset();
    assert_eq!(
        encryptor.process_bytes(&[], &mut []),
        Err(AeadError::AlreadyFinalized)
    );

    let mut decryptor = ChaCha20Poly1305Engine::new();
    decryptor.init(CipherDirection::Decrypt, &params).unwrap();
    decryptor.process_aad_bytes(b"discarded").unwrap();
    decryptor.process_bytes(&ciphertext[..5], &mut []).unwrap();
    decryptor.reset();

    let mut recovered = vec![0u8; plaintext.len()];
    let mut recovered_len = decryptor
        .process_bytes(&ciphertext, &mut recovered)
        .unwrap();
    recovered_len += decryptor.do_final(&mut recovered[recovered_len..]).unwrap();
    assert_eq!(&recovered[..recovered_len], plaintext);
}

#[test]
fn xchacha_reset_restores_decryption() {
    let key = [0x33; KEY_BYTES];
    let nonce = [0x44; XNONCE_BYTES];
    let params = AeadParamsRef::new(&key, &nonce, TAG_BYTES, b"initial aad");
    let plaintext = b"xchacha reset";
    let mut encryptor = XChaCha20Poly1305Engine::new();
    encryptor.init(CipherDirection::Encrypt, &params).unwrap();
    let mut ciphertext = vec![0u8; plaintext.len() + TAG_BYTES];
    let mut written = encryptor.process_bytes(plaintext, &mut ciphertext).unwrap();
    written += encryptor.do_final(&mut ciphertext[written..]).unwrap();
    ciphertext.truncate(written);

    let mut decryptor = XChaCha20Poly1305Engine::new();
    decryptor.init(CipherDirection::Decrypt, &params).unwrap();
    decryptor.process_aad_bytes(b"discarded").unwrap();
    decryptor.reset();
    let mut recovered = vec![0u8; plaintext.len()];
    let mut recovered_len = decryptor
        .process_bytes(&ciphertext, &mut recovered)
        .unwrap();
    recovered_len += decryptor.do_final(&mut recovered[recovered_len..]).unwrap();
    assert_eq!(&recovered[..recovered_len], plaintext);
}

#[test]
fn reset_restarts_encryption_that_has_released_no_output() {
    let key = [0x55; KEY_BYTES];
    let nonce = [0x66; NONCE_BYTES];
    let params = AeadParamsRef::new(&key, &nonce, TAG_BYTES, b"initial aad");
    let plaintext = b"restarted before any message data";

    let mut expected = ChaCha20Poly1305Engine::new();
    expected.init(CipherDirection::Encrypt, &params).unwrap();
    expected.process_aad_bytes(b" and more").unwrap();
    let mut sealed = vec![0u8; plaintext.len() + TAG_BYTES];
    let mut sealed_len = expected.process_bytes(plaintext, &mut sealed).unwrap();
    sealed_len += expected.do_final(&mut sealed[sealed_len..]).unwrap();

    let mut restarted = ChaCha20Poly1305Engine::new();
    restarted.init(CipherDirection::Encrypt, &params).unwrap();
    restarted.process_aad_bytes(b"discarded").unwrap();
    restarted.reset();
    restarted.process_aad_bytes(b" and more").unwrap();
    let mut output = vec![0u8; plaintext.len() + TAG_BYTES];
    let mut written = restarted.process_bytes(plaintext, &mut output).unwrap();
    written += restarted.do_final(&mut output[written..]).unwrap();

    assert_eq!(output[..written], sealed[..sealed_len]);
}

#[test]
fn reset_keeps_encryption_finalized_once_message_data_started() {
    let key = [0x77; KEY_BYTES];
    let nonce = [0x88; XNONCE_BYTES];
    let params = AeadParamsRef::new(&key, &nonce, TAG_BYTES, &[]);
    let mut encryptor = XChaCha20Poly1305Engine::new();
    encryptor.init(CipherDirection::Encrypt, &params).unwrap();
    assert_eq!(encryptor.process_bytes(&[0; 64], &mut [0; 64]), Ok(64));
    encryptor.reset();
    assert_eq!(
        encryptor.process_aad_bytes(b"aad"),
        Err(AeadError::AlreadyFinalized)
    );
    assert_eq!(
        encryptor.do_final(&mut [0; TAG_BYTES]),
        Err(AeadError::AlreadyFinalized)
    );
}
