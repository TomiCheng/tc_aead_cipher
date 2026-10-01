#![cfg(feature = "alloc")]

use tc_aead_cipher::{
    AeadBlockCipher, AeadCipher, AeadCipherInit, AeadError, AeadInitError, AeadParamsRef,
    CcmBlockCipher,
};
use tc_aes::AesEngine;
use tc_block_cipher::{BlockCipher, CipherDirection};

fn decode(hex: &str) -> Vec<u8> {
    assert_eq!(hex.len() % 2, 0);
    hex.as_bytes()
        .chunks_exact(2)
        .map(|pair| (nibble(pair[0]) << 4) | nibble(pair[1]))
        .collect()
}

fn nibble(value: u8) -> u8 {
    match value {
        b'0'..=b'9' => value - b'0',
        b'a'..=b'f' => value - b'a' + 10,
        b'A'..=b'F' => value - b'A' + 10,
        _ => panic!("invalid hexadecimal digit"),
    }
}

fn check_vector(
    key_hex: &str,
    nonce_hex: &str,
    aad_hex: &str,
    plaintext_hex: &str,
    mac_hex: &str,
    ciphertext_hex: &str,
) {
    let key = decode(key_hex);
    let nonce = decode(nonce_hex);
    let aad = decode(aad_hex);
    let plaintext = decode(plaintext_hex);
    let expected_mac = decode(mac_hex);
    let expected_ciphertext = decode(ciphertext_hex);
    let params = AeadParamsRef::new(&key, &nonce, expected_mac.len(), &aad);

    let mut encryptor = CcmBlockCipher::new(AesEngine::new());
    encryptor.init(CipherDirection::Encrypt, &params).unwrap();
    let mut ciphertext = vec![0u8; encryptor.output_len(plaintext.len()).unwrap()];
    assert_eq!(encryptor.process_bytes(&plaintext, &mut []), Ok(0));
    assert_eq!(
        encryptor.do_final(&mut ciphertext),
        Ok(expected_ciphertext.len())
    );
    assert_eq!(ciphertext, expected_ciphertext);
    assert_eq!(encryptor.mac(), Some(expected_mac.as_slice()));

    let mut decryptor = CcmBlockCipher::new(AesEngine::new());
    decryptor.init(CipherDirection::Decrypt, &params).unwrap();
    let mut recovered = vec![0u8; decryptor.output_len(ciphertext.len()).unwrap()];
    assert_eq!(decryptor.process_bytes(&ciphertext, &mut []), Ok(0));
    assert_eq!(decryptor.do_final(&mut recovered), Ok(plaintext.len()));
    assert_eq!(recovered, plaintext);
    assert_eq!(decryptor.mac(), Some(expected_mac.as_slice()));
}

#[test]
fn encryption_and_decryption_match_the_bouncy_castle_ccm_vectors() {
    check_vector(
        "404142434445464748494a4b4c4d4e4f",
        "10111213141516",
        "0001020304050607",
        "20212223",
        "6084341b",
        "7162015b4dac255d",
    );
    check_vector(
        "404142434445464748494a4b4c4d4e4f",
        "1011121314151617",
        "000102030405060708090a0b0c0d0e0f",
        "202122232425262728292a2b2c2d2e2f",
        "7f479ffca464",
        "d2a1f0e051ea5f62081a7792073d593d1fc64fbfaccd",
    );
    check_vector(
        "404142434445464748494a4b4c4d4e4f",
        "101112131415161718191a1b",
        "000102030405060708090a0b0c0d0e0f10111213",
        "202122232425262728292a2b2c2d2e2f3031323334353637",
        "67c99240c7d51048",
        "e3b201a9f5b71a7a9b1ceaeccd97e70b6176aad9a4428aa5484392fbc1b09951",
    );
}

#[test]
fn a_large_aad_matches_the_bouncy_castle_vector() {
    let aad: Vec<u8> = (0u8..=255).cycle().take(65_536).collect();
    check_vector(
        "404142434445464748494a4b4c4d4e4f",
        "101112131415161718191a1b1c",
        &aad.iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>(),
        "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f",
        "f4dd5d0ee404617225ffe34fce91",
        "69915dad1e84c6376a68c2967e4dab615ae0fd1faec44cc484828529463ccf72b4ac6bec93e8598e7f0dadbcea5b",
    );
}

#[test]
fn a_long_message_matches_the_bouncy_castle_vector() {
    let pattern: Vec<u8> = (0u8..=255).collect();
    let pattern_hex = pattern
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    check_vector(
        "404142434445464748494a4b4c4d4e4f",
        "101112131415161718191a1b1c",
        &pattern_hex,
        &pattern_hex,
        "5c768856796b627b13ec8641581b",
        concat!(
            "49b17d8d3ea4e6174a48e2b65e6d8b417ac0dd3f8ee46ce4a4a2a509661cef52",
            "528c1cd9805333a5cfd482fa3f095a3c2fdd1cc47771c5e55fddd60b5c8d6d3f",
            "a5c8dd79d08b16242b6642106e7c0c28bd1064b31e6d7c9800c8397dbc3fa807",
            "1e6a38278b386c18d65d39c6ad1ef9501a5c8f68d38eb6474799f3cc898b4b9b",
            "97e87f9c95ce5c51bc9d758f17119586663a5684e0a0daf6520ec572b87473eb1",
            "41d10471e4799ded9e607655402eca5176bbf792ef39dd135ac8d710da8e9e854f",
            "d3b95c681023f36b5ebe2fb213d0b62dd6e9e3cfe190b792ccb20c53423b2dca1",
            "28f861a61d306910e1af418839467e466f0ec361d2539eedd99d4724f1b51c07be",
            "b40e875a87491ec8b27cd1",
        ),
    );
}

#[test]
fn split_aad_and_data_match_the_initial_aad_result() {
    let key = [0x11u8; 16];
    let nonce = [0x22u8; 11];
    let aad = [0x33u8; 37];
    let plaintext = [0x44u8; 91];

    let mut expected_engine = CcmBlockCipher::new(AesEngine::new());
    expected_engine
        .init(
            CipherDirection::Encrypt,
            &AeadParamsRef::new(&key, &nonce, 12, &aad),
        )
        .unwrap();
    expected_engine.process_bytes(&plaintext, &mut []).unwrap();
    let mut expected = [0u8; 103];
    expected_engine.do_final(&mut expected).unwrap();

    let mut actual_engine = CcmBlockCipher::new(AesEngine::new());
    actual_engine
        .init(
            CipherDirection::Encrypt,
            &AeadParamsRef::new(&key, &nonce, 12, &[]),
        )
        .unwrap();
    for chunk in aad.chunks(5) {
        actual_engine.process_aad_bytes(chunk).unwrap();
    }
    for chunk in plaintext.chunks(7) {
        assert_eq!(actual_engine.process_bytes(chunk, &mut []), Ok(0));
    }
    let mut actual = [0u8; 103];
    actual_engine.do_final(&mut actual).unwrap();

    assert_eq!(actual, expected);
}

#[test]
fn bad_parameters_nonce_reuse_and_tampering_are_rejected_without_releasing_plaintext() {
    let key = [0x11u8; 16];
    let nonce = [0x22u8; 12];
    let params = AeadParamsRef::new(&key, &nonce, 8, &[]);
    let mut cipher = CcmBlockCipher::new(AesEngine::new());

    assert!(matches!(
        cipher.init(
            CipherDirection::Encrypt,
            &AeadParamsRef::new(&key, &[0u8; 6], 8, &[]),
        ),
        Err(AeadInitError::InvalidNonceLength { actual: 6 })
    ));
    assert!(matches!(
        cipher.init(
            CipherDirection::Encrypt,
            &AeadParamsRef::new(&key, &nonce, 5, &[]),
        ),
        Err(AeadInitError::InvalidMacSize { actual: 5 })
    ));

    cipher.init(CipherDirection::Encrypt, &params).unwrap();
    cipher.process_bytes(b"secret", &mut []).unwrap();
    let mut ciphertext = [0u8; 14];
    cipher.do_final(&mut ciphertext).unwrap();
    assert!(matches!(
        cipher.init(CipherDirection::Encrypt, &params),
        Err(AeadInitError::NonceReuse)
    ));

    ciphertext[0] ^= 1;
    let mut decryptor = CcmBlockCipher::new(AesEngine::new());
    decryptor.init(CipherDirection::Decrypt, &params).unwrap();
    decryptor.process_bytes(&ciphertext, &mut []).unwrap();
    let mut output = [0xabu8; 6];
    assert_eq!(
        decryptor.do_final(&mut output),
        Err(AeadError::AuthenticationFailed)
    );
    assert_eq!(output, [0xab; 6]);
    assert_eq!(decryptor.mac(), None);
}

#[test]
fn the_name_block_size_and_packet_output_lengths_are_reported() {
    let key = [0u8; 16];
    let nonce = [0u8; 12];
    let params = AeadParamsRef::new(&key, &nonce, 10, &[]);
    let mut cipher = CcmBlockCipher::new(AesEngine::new());
    assert_eq!(cipher.to_string(), "AES/CCM");
    assert_eq!(cipher.block_size(), 16);
    assert_eq!(cipher.underlying_cipher().block_size(), 16);

    cipher.init(CipherDirection::Encrypt, &params).unwrap();
    assert_eq!(cipher.update_output_len(123).unwrap(), 0);
    assert_eq!(cipher.output_len(123).unwrap(), 133);
    cipher.process_bytes(&[0u8; 7], &mut []).unwrap();
    assert_eq!(cipher.output_len(3).unwrap(), 20);
}

#[test]
fn the_message_length_limit_follows_the_nonce_length() {
    let key = [0u8; 16];
    let nonce = [0u8; 13];
    let mut accepted = CcmBlockCipher::new(AesEngine::new());
    accepted
        .init(
            CipherDirection::Encrypt,
            &AeadParamsRef::new(&key, &nonce, 4, &[]),
        )
        .unwrap();
    assert_eq!(accepted.process_bytes(&vec![0u8; 65_535], &mut []), Ok(0));

    let mut rejected = CcmBlockCipher::new(AesEngine::new());
    rejected
        .init(
            CipherDirection::Encrypt,
            &AeadParamsRef::new(&key, &nonce, 4, &[]),
        )
        .unwrap();
    assert_eq!(
        rejected.process_bytes(&vec![0u8; 65_536], &mut []),
        Err(AeadError::InputTooLong)
    );
}
