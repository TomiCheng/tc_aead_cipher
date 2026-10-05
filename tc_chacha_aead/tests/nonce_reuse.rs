use tc_aead_cipher::{AeadCipher, AeadCipherInit, AeadError, AeadInitError, AeadParamsRef};
use tc_block_cipher::CipherDirection;
use tc_chacha_aead::{
    ChaCha20Poly1305Engine, KEY_BYTES, NONCE_BYTES, TAG_BYTES, XChaCha20Poly1305Engine,
    XNONCE_BYTES,
};

fn assert_nonce_reuse_is_refused<A>(mut engine: A, nonce: &[u8])
where
    for<'a> A: AeadCipherInit<AeadParamsRef<'a>, Error = AeadInitError>,
{
    let key = [0x11; KEY_BYTES];
    let other_key = [0x10; KEY_BYTES];
    let other_nonce: Vec<u8> = nonce.iter().map(|byte| byte ^ 1).collect();
    let params = AeadParamsRef::new(&key, nonce, TAG_BYTES, &[]);

    engine.init(CipherDirection::Encrypt, &params).unwrap();
    assert_eq!(
        engine.init(CipherDirection::Encrypt, &params),
        Err(AeadInitError::NonceReuse)
    );

    // A failed init keeps the previous key and nonce for the check.
    let bad_tag = AeadParamsRef::new(&key, nonce, TAG_BYTES - 1, &[]);
    assert!(engine.init(CipherDirection::Encrypt, &bad_tag).is_err());
    assert_eq!(
        engine.init(CipherDirection::Encrypt, &params),
        Err(AeadInitError::NonceReuse)
    );

    // Decryption may repeat them.
    engine.init(CipherDirection::Decrypt, &params).unwrap();

    // A new key or a new nonce makes the pair fresh.
    let new_key = AeadParamsRef::new(&other_key, nonce, TAG_BYTES, &[]);
    engine.init(CipherDirection::Encrypt, &new_key).unwrap();
    let new_nonce = AeadParamsRef::new(&other_key, &other_nonce, TAG_BYTES, &[]);
    engine.init(CipherDirection::Encrypt, &new_nonce).unwrap();
    assert_eq!(
        engine.init(CipherDirection::Encrypt, &new_nonce),
        Err(AeadInitError::NonceReuse)
    );
}

#[test]
fn encryption_refuses_the_key_and_nonce_of_the_previous_init_and_decryption_does_not() {
    assert_nonce_reuse_is_refused(ChaCha20Poly1305Engine::new(), &[0x22; NONCE_BYTES]);
    assert_nonce_reuse_is_refused(XChaCha20Poly1305Engine::new(), &[0x22; XNONCE_BYTES]);
}

fn assert_failed_init_leaves_the_engine_uninitialized<A>(mut engine: A, nonce: &[u8])
where
    for<'a> A:
        AeadCipher<Error = AeadError> + AeadCipherInit<AeadParamsRef<'a>, Error = AeadInitError>,
{
    let key = [0x11; KEY_BYTES];
    let other_nonce: Vec<u8> = nonce.iter().map(|byte| byte ^ 1).collect();
    let params = AeadParamsRef::new(&key, nonce, TAG_BYTES, &[]);
    let short_key = AeadParamsRef::new(&key[..KEY_BYTES - 1], &other_nonce, TAG_BYTES, &[]);

    for failing in [
        short_key,
        AeadParamsRef::new(&key, &other_nonce[1..], TAG_BYTES, &[]),
        AeadParamsRef::new(&key, &other_nonce, 12, &[]),
        params,
    ] {
        // Decryption may repeat the key and nonce, so each round starts
        // initialized.
        engine.init(CipherDirection::Decrypt, &params).unwrap();
        assert!(engine.init(CipherDirection::Encrypt, &failing).is_err());
        assert_eq!(
            engine.process_aad_bytes(b"aad"),
            Err(AeadError::NotInitialized)
        );
        assert_eq!(
            engine.process_bytes(&[0; 64], &mut [0; 64]),
            Err(AeadError::NotInitialized)
        );
        assert_eq!(
            engine.do_final(&mut [0; TAG_BYTES]),
            Err(AeadError::NotInitialized)
        );
        assert_eq!(engine.mac(), None);
    }
}

#[test]
fn a_failed_init_leaves_the_engine_uninitialized() {
    assert_failed_init_leaves_the_engine_uninitialized(
        ChaCha20Poly1305Engine::new(),
        &[0x22; NONCE_BYTES],
    );
    assert_failed_init_leaves_the_engine_uninitialized(
        XChaCha20Poly1305Engine::new(),
        &[0x22; XNONCE_BYTES],
    );
}
