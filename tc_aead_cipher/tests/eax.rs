use tc_aead_cipher::{
    AeadBlockCipher, AeadCipher, AeadCipherInit, AeadError, AeadInitError, AeadParamsRef,
    EaxBlockCipher,
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
    mac_size: usize,
    expected_hex: &str,
) {
    let key = decode(key_hex);
    let nonce = decode(nonce_hex);
    let aad = decode(aad_hex);
    let plaintext = decode(plaintext_hex);
    let expected = decode(expected_hex);
    let aad_split = aad.len() / 2;
    let params = AeadParamsRef::new(&key, &nonce, mac_size, &aad[..aad_split]);

    let mut encryptor = EaxBlockCipher::new(AesEngine::new());
    encryptor.init(CipherDirection::Encrypt, &params).unwrap();
    encryptor.process_aad_bytes(&aad[aad_split..]).unwrap();
    let mut encrypted = vec![0u8; encryptor.output_len(plaintext.len()).unwrap()];
    let mut written = 0;
    for chunk in plaintext.chunks(3) {
        written += encryptor
            .process_bytes(chunk, &mut encrypted[written..])
            .unwrap();
    }
    written += encryptor.do_final(&mut encrypted[written..]).unwrap();
    assert_eq!(written, expected.len());
    assert_eq!(encrypted, expected);
    assert_eq!(
        encryptor.mac(),
        Some(&expected[expected.len() - mac_size..])
    );

    let mut decryptor = EaxBlockCipher::new(AesEngine::new());
    decryptor.init(CipherDirection::Decrypt, &params).unwrap();
    decryptor.process_aad_bytes(&aad[aad_split..]).unwrap();
    let mut recovered = vec![0u8; decryptor.output_len(encrypted.len()).unwrap()];
    let mut recovered_len = 0;
    for chunk in encrypted.chunks(5) {
        recovered_len += decryptor
            .process_bytes(chunk, &mut recovered[recovered_len..])
            .unwrap();
    }
    recovered_len += decryptor.do_final(&mut recovered[recovered_len..]).unwrap();
    assert_eq!(recovered_len, plaintext.len());
    assert_eq!(recovered, plaintext);
    assert_eq!(
        decryptor.mac(),
        Some(&expected[expected.len() - mac_size..])
    );
}

#[test]
fn encryption_and_decryption_match_the_bouncy_castle_eax_vectors() {
    check_vector(
        "233952DEE4D5ED5F9B9C6D6FF80FF478",
        "62EC67F9C3A4A407FCB2A8C49031A8B3",
        "6BFB914FD07EAE6B",
        "",
        16,
        "E037830E8389F27B025A2D6527E79D01",
    );
    check_vector(
        "91945D3F4DCBEE0BF45EF52255F095A4",
        "BECAF043B0A23D843194BA972C66DEBD",
        "FA3BFD4806EB53FA",
        "F7FB",
        16,
        "19DD5C4C9331049D0BDAB0277408F67967E5",
    );
    check_vector(
        "01F74AD64077F2E704C0F60ADA3DD523",
        "70C3DB4F0D26368400A10ED05D2BFF5E",
        "234A3463C1264AC6",
        "1A47CB4933",
        16,
        "D851D5BAE03A59F238A23E39199DC9266626C40F80",
    );
    check_vector(
        "7C77D6E813BED5AC98BAA417477A2E7D",
        "1A8C98DCD73D38393B2BF1569DEEFC19",
        "65D2017990D62528",
        "8B0A79306C9CE7ED99DAE4F87F8DD61636",
        16,
        "02083E3979DA014812F59F11D52630DA30137327D10649B0AA6E1C181DB617D7F2",
    );
    check_vector(
        "8395FCF1E95BEBD697BD010BC766AAC3",
        "22E7ADD93CFC6393C57EC0B3C17D6B44",
        "126735FCC320D25A",
        "CA40D7446E545FFAED3BD12A740A659FFBBB3CEAB7",
        4,
        "CB8920F87A6C75CFF39627B56E3ED197C552D295A7CFC46AFC",
    );
}

#[test]
fn bad_tag_sizes_late_aad_nonce_reuse_and_tampering_are_rejected() {
    let key = [0x11u8; 16];
    let nonce = [0x22u8; 12];
    let params = AeadParamsRef::new(&key, &nonce, 12, b"header");
    let mut cipher = EaxBlockCipher::new(AesEngine::new());

    assert!(matches!(
        cipher.init(
            CipherDirection::Encrypt,
            &AeadParamsRef::new(&key, &nonce, 3, &[]),
        ),
        Err(AeadInitError::InvalidMacSize { actual: 3 })
    ));
    cipher.init(CipherDirection::Encrypt, &params).unwrap();
    cipher.process_bytes(b"message", &mut []).unwrap();
    assert_eq!(
        cipher.process_aad_bytes(b"late"),
        Err(AeadError::AadAfterData)
    );
    let mut encrypted = [0u8; 19];
    cipher.do_final(&mut encrypted).unwrap();
    assert!(matches!(
        cipher.init(CipherDirection::Encrypt, &params),
        Err(AeadInitError::NonceReuse)
    ));

    encrypted[0] ^= 1;
    let mut decryptor = EaxBlockCipher::new(AesEngine::new());
    decryptor.init(CipherDirection::Decrypt, &params).unwrap();
    assert_eq!(decryptor.process_bytes(&encrypted, &mut [0u8; 7]), Ok(0));
    let mut output = [0xabu8; 7];
    assert_eq!(
        decryptor.do_final(&mut output),
        Err(AeadError::AuthenticationFailed)
    );
    assert_eq!(output, [0xab; 7]);
    assert_eq!(decryptor.mac(), None);
}

#[test]
fn the_name_block_size_and_output_lengths_are_reported() {
    let params = AeadParamsRef::new(&[0x11; 16], &[0x22; 12], 8, b"header");
    let mut cipher = EaxBlockCipher::new(AesEngine::new());
    assert_eq!(cipher.to_string(), "AES/EAX");
    assert_eq!(cipher.block_size(), 16);
    assert_eq!(cipher.underlying_cipher().block_size(), 16);

    cipher.init(CipherDirection::Encrypt, &params).unwrap();
    assert_eq!(cipher.update_output_len(15).unwrap(), 0);
    assert_eq!(cipher.update_output_len(16).unwrap(), 16);
    assert_eq!(cipher.output_len(15).unwrap(), 23);
}

#[test]
fn an_encryption_cannot_run_twice_under_one_nonce() {
    let key = [0x11u8; 16];
    let mut cipher = EaxBlockCipher::new(AesEngine::new());

    // A reset before any data keeps the encryption usable.
    cipher
        .init(
            CipherDirection::Encrypt,
            &AeadParamsRef::new(&key, &[0x22; 12], 8, b"header"),
        )
        .unwrap();
    cipher.reset();
    let mut tag = [0u8; 8];
    cipher.do_final(&mut tag).unwrap();
    assert_eq!(cipher.mac(), Some(tag.as_slice()));

    // do_final finalizes, and so does a reset once data was encrypted.
    assert_eq!(cipher.do_final(&mut tag), Err(AeadError::AlreadyFinalized));
    cipher.reset();
    assert_eq!(
        cipher.process_bytes(&[], &mut []),
        Err(AeadError::AlreadyFinalized)
    );

    cipher
        .init(
            CipherDirection::Encrypt,
            &AeadParamsRef::new(&key, &[0x23; 12], 8, &[]),
        )
        .unwrap();
    cipher.process_bytes(b"spent", &mut []).unwrap();
    cipher.reset();
    assert_eq!(
        cipher.do_final(&mut [0; 16]),
        Err(AeadError::AlreadyFinalized)
    );
}

#[test]
fn a_decryption_can_be_reset_and_verified_again() {
    let key = [0x11u8; 16];
    let params = AeadParamsRef::new(&key, &[0x22; 12], 16, b"header");
    let mut encryptor = EaxBlockCipher::new(AesEngine::new());
    encryptor.init(CipherDirection::Encrypt, &params).unwrap();
    let mut encrypted = [0u8; 23];
    let written = encryptor.process_bytes(b"message", &mut encrypted).unwrap();
    encryptor.do_final(&mut encrypted[written..]).unwrap();

    let mut decryptor = EaxBlockCipher::new(AesEngine::new());
    decryptor.init(CipherDirection::Decrypt, &params).unwrap();
    decryptor
        .process_bytes(&encrypted[..5], &mut [0; 16])
        .unwrap();
    decryptor.reset();
    for _ in 0..2 {
        let mut recovered = [0u8; 7];
        let written = decryptor.process_bytes(&encrypted, &mut recovered).unwrap();
        decryptor.do_final(&mut recovered[written..]).unwrap();
        assert_eq!(&recovered, b"message");
        decryptor.reset();
    }
}

#[test]
fn every_whole_byte_aes_tag_size_round_trips() {
    let key = [0x11u8; 16];
    let nonce = [0x22u8; 9];
    let plaintext = b"a message spanning more than one AES block";

    for mac_size in 4..=16 {
        let params = AeadParamsRef::new(&key, &nonce, mac_size, b"aad");
        let mut encryptor = EaxBlockCipher::new(AesEngine::new());
        encryptor.init(CipherDirection::Encrypt, &params).unwrap();
        let mut encrypted = vec![0u8; encryptor.output_len(plaintext.len()).unwrap()];
        let mut written = encryptor.process_bytes(plaintext, &mut encrypted).unwrap();
        written += encryptor.do_final(&mut encrypted[written..]).unwrap();
        assert_eq!(written, plaintext.len() + mac_size);

        let mut decryptor = EaxBlockCipher::new(AesEngine::new());
        decryptor.init(CipherDirection::Decrypt, &params).unwrap();
        let mut recovered = vec![0u8; plaintext.len()];
        let mut recovered_len = decryptor.process_bytes(&encrypted, &mut recovered).unwrap();
        recovered_len += decryptor.do_final(&mut recovered[recovered_len..]).unwrap();
        assert_eq!(recovered_len, plaintext.len());
        assert_eq!(recovered, plaintext);
    }
}

#[test]
fn nonce_reuse_is_detected_through_l_and_the_initial_counter() {
    let key = [0x11u8; 16];
    let other_key = [0x12u8; 16];
    let nonce = [0x22u8; 12];
    let other_nonce = [0x23u8; 12];
    let long_nonce = [0x24u8; 40];
    let mut cipher = EaxBlockCipher::new(AesEngine::new());

    cipher
        .init(
            CipherDirection::Encrypt,
            &AeadParamsRef::new(&key, &nonce, 16, &[]),
        )
        .unwrap();
    assert_eq!(
        cipher.init(
            CipherDirection::Encrypt,
            &AeadParamsRef::new(&key, &nonce, 8, b"different aad"),
        ),
        Err(AeadInitError::NonceReuse)
    );
    cipher
        .init(
            CipherDirection::Encrypt,
            &AeadParamsRef::new(&key, &other_nonce, 16, &[]),
        )
        .unwrap();
    cipher
        .init(
            CipherDirection::Encrypt,
            &AeadParamsRef::new(&other_key, &other_nonce, 16, &[]),
        )
        .unwrap();

    // A decryption init counts toward reuse but may itself repeat.
    let params = AeadParamsRef::new(&key, &long_nonce, 16, &[]);
    cipher.init(CipherDirection::Decrypt, &params).unwrap();
    cipher.init(CipherDirection::Decrypt, &params).unwrap();
    assert_eq!(
        cipher.init(CipherDirection::Encrypt, &params),
        Err(AeadInitError::NonceReuse)
    );
}

#[test]
fn output_lengths_report_overflow_as_input_too_long() {
    let mut cipher = EaxBlockCipher::new(AesEngine::new());
    cipher
        .init(
            CipherDirection::Encrypt,
            &AeadParamsRef::new(&[0x11; 16], &[0x22; 12], 16, &[]),
        )
        .unwrap();
    assert_eq!(cipher.output_len(usize::MAX), Err(AeadError::InputTooLong));
    cipher.process_bytes(b"x", &mut []).unwrap();
    assert_eq!(
        cipher.update_output_len(usize::MAX),
        Err(AeadError::InputTooLong)
    );
}
