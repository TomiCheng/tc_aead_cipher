use tc_aead_cipher::{AeadCipherInit, AeadInitError, AeadParamsRef};
use tc_block_cipher::CipherDirection;
use tc_sparkle_aead::{SparkleEngine, SparkleVariant};

fn assert_nonce_reuse_is_refused<A>(mut engine: A, key: &[u8], nonce: &[u8], mac_size: usize)
where
    for<'a> A: AeadCipherInit<AeadParamsRef<'a>, Error = AeadInitError>,
{
    let other_key: Vec<u8> = key.iter().map(|byte| byte ^ 1).collect();
    let other_nonce: Vec<u8> = nonce.iter().map(|byte| byte ^ 1).collect();
    let params = AeadParamsRef::new(key, nonce, mac_size, &[]);

    engine.init(CipherDirection::Encrypt, &params).unwrap();
    assert_eq!(
        engine.init(CipherDirection::Encrypt, &params),
        Err(AeadInitError::NonceReuse)
    );

    // A failed init keeps the previous key and nonce for the check.
    let bad_tag = AeadParamsRef::new(key, nonce, mac_size + 1, &[]);
    assert!(engine.init(CipherDirection::Encrypt, &bad_tag).is_err());
    assert_eq!(
        engine.init(CipherDirection::Encrypt, &params),
        Err(AeadInitError::NonceReuse)
    );

    // Decryption may repeat them.
    engine.init(CipherDirection::Decrypt, &params).unwrap();

    // A new key or a new nonce makes the pair fresh.
    let new_key = AeadParamsRef::new(&other_key, nonce, mac_size, &[]);
    engine.init(CipherDirection::Encrypt, &new_key).unwrap();
    let new_nonce = AeadParamsRef::new(&other_key, &other_nonce, mac_size, &[]);
    engine.init(CipherDirection::Encrypt, &new_nonce).unwrap();
    assert_eq!(
        engine.init(CipherDirection::Encrypt, &new_nonce),
        Err(AeadInitError::NonceReuse)
    );
}

#[test]
fn encryption_refuses_the_key_and_nonce_of_the_previous_init_and_decryption_does_not() {
    for variant in [
        SparkleVariant::Schwaemm128_128,
        SparkleVariant::Schwaemm256_128,
        SparkleVariant::Schwaemm192_192,
        SparkleVariant::Schwaemm256_256,
    ] {
        let key = vec![0x11; variant.key_bytes()];
        let nonce = vec![0x22; variant.nonce_bytes()];
        assert_nonce_reuse_is_refused(
            SparkleEngine::new(variant),
            &key,
            &nonce,
            variant.tag_bytes(),
        );
    }
}
