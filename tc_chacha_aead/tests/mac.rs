use core::fmt::Debug;

use tc_aead_cipher::{AeadCipher, AeadCipherInit, AeadError, AeadParamsRef};
use tc_block_cipher::CipherDirection;
use tc_chacha_aead::{
    ChaCha20Poly1305Engine, KEY_BYTES, NONCE_BYTES, TAG_BYTES, XChaCha20Poly1305Engine,
    XNONCE_BYTES,
};

fn seal<A>(engine: &mut A, params: &AeadParamsRef<'_>, plaintext: &[u8]) -> Vec<u8>
where
    for<'a> A: AeadCipher + AeadCipherInit<AeadParamsRef<'a>>,
    for<'a> <A as AeadCipherInit<AeadParamsRef<'a>>>::Error: Debug,
    <A as AeadCipher>::Error: Debug,
{
    engine.init(CipherDirection::Encrypt, params).unwrap();
    let mut ciphertext = vec![0u8; engine.output_len(plaintext.len()).unwrap()];
    let mut written = engine.process_bytes(plaintext, &mut ciphertext).unwrap();
    written += engine.do_final(&mut ciphertext[written..]).unwrap();
    ciphertext.truncate(written);
    ciphertext
}

fn assert_mac_is_the_appended_tag<A>(mut engine: A, nonce: &[u8])
where
    for<'a> A: AeadCipher + AeadCipherInit<AeadParamsRef<'a>>,
    for<'a> <A as AeadCipherInit<AeadParamsRef<'a>>>::Error: Debug,
    <A as AeadCipher>::Error: Debug,
{
    let key = [0x11; KEY_BYTES];
    let params = AeadParamsRef::new(&key, nonce, TAG_BYTES, b"associated data!");
    let plaintext = [0x44u8; 100];

    let ciphertext = seal(&mut engine, &params, &plaintext);
    let tag = &ciphertext[ciphertext.len() - TAG_BYTES..];
    assert_eq!(engine.mac(), Some(tag));

    engine.init(CipherDirection::Decrypt, &params).unwrap();
    assert_eq!(engine.mac(), None);
    let mut recovered = vec![0u8; engine.output_len(ciphertext.len()).unwrap()];
    let mut recovered_len = engine.process_bytes(&ciphertext, &mut recovered).unwrap();
    recovered_len += engine.do_final(&mut recovered[recovered_len..]).unwrap();
    assert_eq!(recovered[..recovered_len], plaintext);
    assert_eq!(engine.mac(), Some(tag));
}

#[test]
fn every_engine_reports_the_tag_that_ends_the_ciphertext_as_its_mac() {
    assert_mac_is_the_appended_tag(ChaCha20Poly1305Engine::new(), &[1; NONCE_BYTES]);
    assert_mac_is_the_appended_tag(XChaCha20Poly1305Engine::new(), &[1; XNONCE_BYTES]);
}

fn assert_a_failed_tag_check_releases_no_plaintext<A>(mut engine: A, nonce: &[u8])
where
    for<'a> A: AeadCipher<Error = AeadError> + AeadCipherInit<AeadParamsRef<'a>>,
    for<'a> <A as AeadCipherInit<AeadParamsRef<'a>>>::Error: Debug,
{
    let key = [0x11; KEY_BYTES];
    let params = AeadParamsRef::new(&key, nonce, TAG_BYTES, b"header");
    // Short of a block, so do_final writes the whole plaintext.
    let plaintext = [0x44u8; 40];
    let ciphertext = seal(&mut engine, &params, &plaintext);

    for position in [0, plaintext.len(), ciphertext.len() - 1] {
        let mut tampered = ciphertext.clone();
        tampered[position] ^= 1;

        engine.init(CipherDirection::Decrypt, &params).unwrap();
        let mut recovered = [0xaau8; 40];
        assert_eq!(engine.process_bytes(&tampered, &mut recovered), Ok(0));
        assert_eq!(
            engine.do_final(&mut recovered),
            Err(AeadError::AuthenticationFailed)
        );
        assert_eq!(recovered, [0; 40]);
        assert_eq!(engine.mac(), None);
    }
}

#[test]
fn a_failed_tag_check_releases_no_plaintext_from_do_final() {
    assert_a_failed_tag_check_releases_no_plaintext(
        ChaCha20Poly1305Engine::new(),
        &[1; NONCE_BYTES],
    );
    assert_a_failed_tag_check_releases_no_plaintext(
        XChaCha20Poly1305Engine::new(),
        &[1; XNONCE_BYTES],
    );
}
