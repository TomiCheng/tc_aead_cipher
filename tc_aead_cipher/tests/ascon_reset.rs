use tc_aead_cipher::{
    AeadCipher, AeadCipherInit, AeadError, AeadParamsRef, AsconAead128, AsconLegacyEngine,
    AsconLegacyVariant,
};
use tc_block_cipher::CipherDirection;

#[test]
fn ascon_aead128_reset_restores_decryption_with_initial_aad() {
    let key = [0x11; 16];
    let nonce = [0x22; 16];
    let params = AeadParamsRef::new(&key, &nonce, 16, b"initial aad");
    let plaintext = b"reset message";

    let mut encryptor = AsconAead128::new();
    encryptor.init(CipherDirection::Encrypt, &params).unwrap();
    let mut ciphertext = vec![0u8; plaintext.len() + 16];
    let mut written = encryptor.process_bytes(plaintext, &mut ciphertext).unwrap();
    written += encryptor.do_final(&mut ciphertext[written..]).unwrap();
    ciphertext.truncate(written);
    encryptor.reset();
    assert_eq!(encryptor.mac(), None);
    assert_eq!(
        encryptor.process_bytes(&[], &mut []),
        Err(AeadError::AlreadyFinalized)
    );

    let mut decryptor = AsconAead128::new();
    decryptor.init(CipherDirection::Decrypt, &params).unwrap();
    decryptor.process_aad_bytes(b"discarded").unwrap();
    assert_eq!(decryptor.process_bytes(&ciphertext[..5], &mut []), Ok(0));
    decryptor.reset();

    let mut recovered = vec![0u8; plaintext.len()];
    let mut recovered_len = decryptor
        .process_bytes(&ciphertext, &mut recovered)
        .unwrap();
    recovered_len += decryptor.do_final(&mut recovered[recovered_len..]).unwrap();
    assert_eq!(&recovered[..recovered_len], plaintext);
}

#[test]
fn legacy_reset_restores_decryption_with_initial_aad() {
    let key = [0x33; 16];
    let nonce = [0x44; 16];
    let params = AeadParamsRef::new(&key, &nonce, 16, b"initial aad");
    let plaintext = b"legacy reset";

    let mut encryptor = AsconLegacyEngine::new(AsconLegacyVariant::Ascon128a);
    encryptor.init(CipherDirection::Encrypt, &params).unwrap();
    let mut ciphertext = vec![0u8; plaintext.len() + 16];
    let mut written = encryptor.process_bytes(plaintext, &mut ciphertext).unwrap();
    written += encryptor.do_final(&mut ciphertext[written..]).unwrap();
    ciphertext.truncate(written);

    let mut decryptor = AsconLegacyEngine::new(AsconLegacyVariant::Ascon128a);
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
