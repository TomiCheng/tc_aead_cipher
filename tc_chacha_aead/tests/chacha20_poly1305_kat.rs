use tc_aead_cipher::{AeadCipher, AeadCipherInit, AeadError, AeadInitError, AeadParamsRef};
use tc_block_cipher::CipherDirection;
use tc_chacha_aead::{ChaCha20Poly1305Engine, TAG_BYTES, XChaCha20Poly1305Engine};

fn decode<const N: usize>(hex: &str) -> [u8; N] {
    assert_eq!(hex.len(), N * 2);
    let mut output = [0u8; N];
    for (byte, pair) in output.iter_mut().zip(hex.as_bytes().chunks_exact(2)) {
        *byte = (nibble(pair[0]) << 4) | nibble(pair[1]);
    }
    output
}

fn nibble(value: u8) -> u8 {
    match value {
        b'0'..=b'9' => value - b'0',
        b'a'..=b'f' => value - b'a' + 10,
        b'A'..=b'F' => value - b'A' + 10,
        _ => panic!("invalid hexadecimal digit"),
    }
}

#[test]
fn matches_rfc_8439_vector() {
    let key = decode::<32>("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f");
    let nonce = decode::<12>("070000004041424344454647");
    let aad = decode::<12>("50515253c0c1c2c3c4c5c6c7");
    let plaintext = *b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
    let expected = decode::<130>(concat!(
        "d31a8d34648e60db7b86afbc53ef7ec2",
        "a4aded51296e08fea9e2b5a736ee62d6",
        "3dbea45e8ca9671282fafb69da92728b",
        "1a71de0a9e060b2905d6a5b67ecd3b36",
        "92ddbd7f2d778b8c9803aee328091b58",
        "fab324e4fad675945585808b4831d7bc",
        "3ff4def08e4b7a9de576d26586cec64b",
        "61161ae10b594f09e26a7e902ecbd0600691",
    ));
    let params = AeadParamsRef::new(&key, &nonce, TAG_BYTES, &aad);

    let mut encryptor = ChaCha20Poly1305Engine::new();
    encryptor.init(CipherDirection::Encrypt, &params).unwrap();
    let mut ciphertext = [0u8; 130];
    let mut written = encryptor
        .process_bytes(&plaintext, &mut ciphertext)
        .unwrap();
    written += encryptor.do_final(&mut ciphertext[written..]).unwrap();
    assert_eq!(written, ciphertext.len());
    assert_eq!(ciphertext, expected);
    assert_eq!(
        encryptor.mac(),
        Some(&expected[expected.len() - TAG_BYTES..])
    );

    let mut decryptor = ChaCha20Poly1305Engine::new();
    decryptor.init(CipherDirection::Decrypt, &params).unwrap();
    let mut recovered = [0u8; 114];
    let mut recovered_len = decryptor
        .process_bytes(&ciphertext, &mut recovered)
        .unwrap();
    recovered_len += decryptor.do_final(&mut recovered[recovered_len..]).unwrap();
    assert_eq!(recovered_len, plaintext.len());
    assert_eq!(recovered, plaintext);
}

#[test]
fn chunked_aad_and_message_processing_match() {
    let key = [0x11u8; 32];
    let nonce = [0x22u8; 12];
    let aad = [0x33u8; 21];
    let plaintext = [0x44u8; 137];

    let mut one_shot = ChaCha20Poly1305Engine::new();
    one_shot
        .init(
            CipherDirection::Encrypt,
            &AeadParamsRef::new(&key, &nonce, TAG_BYTES, &aad),
        )
        .unwrap();
    let mut expected = [0u8; 137 + TAG_BYTES];
    let mut expected_len = one_shot.process_bytes(&plaintext, &mut expected).unwrap();
    expected_len += one_shot.do_final(&mut expected[expected_len..]).unwrap();

    let mut chunked = ChaCha20Poly1305Engine::new();
    chunked
        .init(
            CipherDirection::Encrypt,
            &AeadParamsRef::new(&key, &nonce, TAG_BYTES, &[]),
        )
        .unwrap();
    for chunk in aad.chunks(4) {
        chunked.process_aad_bytes(chunk).unwrap();
    }
    let mut actual = [0u8; 137 + TAG_BYTES];
    let mut actual_len = 0;
    for chunk in plaintext.chunks(11) {
        actual_len += chunked
            .process_bytes(chunk, &mut actual[actual_len..])
            .unwrap();
    }
    actual_len += chunked.do_final(&mut actual[actual_len..]).unwrap();

    assert_eq!(expected_len, expected.len());
    assert_eq!(actual_len, actual.len());
    assert_eq!(actual, expected);
}

#[test]
fn rejects_invalid_parameters_nonce_reuse_and_bad_tags() {
    let key = [0x11u8; 32];
    let nonce = [0x22u8; 12];
    let params = AeadParamsRef::new(&key, &nonce, TAG_BYTES, &[]);
    let mut cipher = ChaCha20Poly1305Engine::new();

    assert_eq!(
        cipher.init(
            CipherDirection::Encrypt,
            &AeadParamsRef::new(&key[..31], &nonce, TAG_BYTES, &[]),
        ),
        Err(AeadInitError::InvalidKeyLength { actual: 31 })
    );
    assert_eq!(
        cipher.init(
            CipherDirection::Encrypt,
            &AeadParamsRef::new(&key, &nonce[..11], TAG_BYTES, &[]),
        ),
        Err(AeadInitError::InvalidNonceLength { actual: 11 })
    );

    cipher.init(CipherDirection::Encrypt, &params).unwrap();
    let mut ciphertext = [0u8; TAG_BYTES];
    assert_eq!(cipher.do_final(&mut ciphertext), Ok(TAG_BYTES));
    assert_eq!(
        cipher.init(CipherDirection::Encrypt, &params),
        Err(AeadInitError::NonceReuse)
    );

    ciphertext[TAG_BYTES - 1] ^= 1;
    let mut decryptor = ChaCha20Poly1305Engine::new();
    decryptor.init(CipherDirection::Decrypt, &params).unwrap();
    assert_eq!(decryptor.process_bytes(&ciphertext, &mut []), Ok(0));
    assert_eq!(
        decryptor.do_final(&mut []),
        Err(AeadError::AuthenticationFailed)
    );
    assert_eq!(decryptor.mac(), None);
}

#[test]
fn reports_name_and_output_sizes() {
    let key = [0u8; 32];
    let nonce = [0u8; 12];
    let params = AeadParamsRef::new(&key, &nonce, TAG_BYTES, &[]);
    let mut cipher = ChaCha20Poly1305Engine::new();
    assert_eq!(cipher.to_string(), "ChaCha20-Poly1305");

    cipher.init(CipherDirection::Encrypt, &params).unwrap();
    assert_eq!(cipher.update_output_len(63), Ok(0));
    assert_eq!(cipher.update_output_len(64), Ok(64));
    assert_eq!(cipher.output_len(63), Ok(63 + TAG_BYTES));
}

#[test]
fn xchacha20_poly1305_matches_draft_vector() {
    let key = decode::<32>("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f");
    let nonce = decode::<24>("404142434445464748494a4b4c4d4e4f5051525354555657");
    let aad = decode::<12>("50515253c0c1c2c3c4c5c6c7");
    let plaintext = *b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
    let expected = decode::<130>(concat!(
        "bd6d179d3e83d43b9576579493c0e939",
        "572a1700252bfaccbed2902c21396cbb",
        "731c7f1b0b4aa6440bf3a82f4eda7e39",
        "ae64c6708c54c216cb96b72e1213b452",
        "2f8c9ba40db5d945b11b69b982c1bb9e",
        "3f3fac2bc369488f76b2383565d3fff9",
        "21f9664c97637da9768812f615c68b13",
        "b52ec0875924c1c7987947deafd8780acf49",
    ));
    let params = AeadParamsRef::new(&key, &nonce, TAG_BYTES, &aad);

    let mut encryptor = XChaCha20Poly1305Engine::new();
    encryptor.init(CipherDirection::Encrypt, &params).unwrap();
    let mut ciphertext = [0u8; 130];
    let mut written = encryptor
        .process_bytes(&plaintext, &mut ciphertext)
        .unwrap();
    written += encryptor.do_final(&mut ciphertext[written..]).unwrap();
    assert_eq!(written, ciphertext.len());
    assert_eq!(ciphertext, expected);
    assert_eq!(
        encryptor.mac(),
        Some(&expected[expected.len() - TAG_BYTES..])
    );

    let mut decryptor = XChaCha20Poly1305Engine::new();
    decryptor.init(CipherDirection::Decrypt, &params).unwrap();
    let mut recovered = [0u8; 114];
    let mut recovered_len = decryptor
        .process_bytes(&ciphertext, &mut recovered)
        .unwrap();
    recovered_len += decryptor.do_final(&mut recovered[recovered_len..]).unwrap();
    assert_eq!(recovered_len, plaintext.len());
    assert_eq!(recovered, plaintext);
}

#[test]
fn xchacha20_poly1305_validates_nonce_and_name() {
    let key = [0u8; 32];
    let nonce = [0u8; 24];
    let mut cipher = XChaCha20Poly1305Engine::new();
    assert_eq!(cipher.to_string(), "XChaCha20-Poly1305");

    assert_eq!(
        cipher.init(
            CipherDirection::Encrypt,
            &AeadParamsRef::new(&key, &nonce[..23], TAG_BYTES, &[]),
        ),
        Err(AeadInitError::InvalidNonceLength { actual: 23 })
    );
    cipher
        .init(
            CipherDirection::Encrypt,
            &AeadParamsRef::new(&key, &nonce, TAG_BYTES, &[]),
        )
        .unwrap();
}

#[test]
fn a_tag_size_other_than_16_bytes_is_rejected() {
    let key = [0u8; 32];
    let nonce = [0u8; 12];
    let mut cipher = ChaCha20Poly1305Engine::new();
    assert_eq!(
        cipher.init(
            CipherDirection::Encrypt,
            &AeadParamsRef::new(&key, &nonce, 12, &[]),
        ),
        Err(AeadInitError::InvalidMacSize { actual: 12 })
    );
}

#[test]
fn a_different_key_with_the_same_nonce_is_not_reuse() {
    let nonce = [0u8; 12];
    let mut cipher = ChaCha20Poly1305Engine::new();
    cipher
        .init(
            CipherDirection::Encrypt,
            &AeadParamsRef::new(&[1u8; 32], &nonce, TAG_BYTES, &[]),
        )
        .unwrap();
    cipher
        .init(
            CipherDirection::Encrypt,
            &AeadParamsRef::new(&[2u8; 32], &nonce, TAG_BYTES, &[]),
        )
        .unwrap();
}
