use tc_aead_cipher::{
    AeadCipher, AeadCipherInit, AeadError, AeadParamsRef, SparkleEngine, SparkleVariant,
};
use tc_block_cipher::CipherDirection;

#[test]
fn reset_restores_decryption_with_initial_aad_and_blocks_encryption_reuse() {
    let variant = SparkleVariant::Schwaemm128_128;
    let key = [0x11; 16];
    let nonce = [0x22; 16];
    let params = AeadParamsRef::new(&key, &nonce, variant.tag_bytes(), b"initial aad");
    let plaintext = b"sparkle reset";

    let mut encryptor = SparkleEngine::new(variant);
    encryptor.init(CipherDirection::Encrypt, &params).unwrap();
    let mut ciphertext = vec![0u8; plaintext.len() + variant.tag_bytes()];
    let mut written = encryptor.process_bytes(plaintext, &mut ciphertext).unwrap();
    written += encryptor.do_final(&mut ciphertext[written..]).unwrap();
    ciphertext.truncate(written);
    encryptor.reset();
    assert_eq!(encryptor.mac(), None);
    assert_eq!(
        encryptor.process_bytes(&[], &mut []),
        Err(AeadError::AlreadyFinalized)
    );

    let mut decryptor = SparkleEngine::new(variant);
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
fn reset_right_after_an_encryption_init_with_initial_aad_keeps_the_engine_usable() {
    let variant = SparkleVariant::Schwaemm128_128;
    let key = [0x11; 16];
    let nonce = [0x22; 16];
    let params = AeadParamsRef::new(&key, &nonce, variant.tag_bytes(), b"initial aad");
    let plaintext = b"sparkle reset";

    let mut expected = vec![0u8; plaintext.len() + variant.tag_bytes()];
    let mut reference = SparkleEngine::new(variant);
    reference.init(CipherDirection::Encrypt, &params).unwrap();
    let written = reference.process_bytes(plaintext, &mut expected).unwrap();
    reference.do_final(&mut expected[written..]).unwrap();

    let mut encryptor = SparkleEngine::new(variant);
    encryptor.init(CipherDirection::Encrypt, &params).unwrap();
    encryptor.reset();
    let mut output = vec![0u8; expected.len()];
    let mut written = encryptor.process_bytes(plaintext, &mut output).unwrap();
    written += encryptor.do_final(&mut output[written..]).unwrap();
    assert_eq!(output[..written], expected[..]);
}
