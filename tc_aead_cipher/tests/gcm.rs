use core::convert::Infallible;
use core::error::Error;
use tc_aead_cipher::{
    AeadBlockCipher, AeadCipher, AeadCipherInit, AeadError, AeadInitError, AeadParamsRef,
    GcmBlockCipher,
};
use tc_aes::AesEngine;
use tc_block_cipher::{BlockCipher, BlockCipherInit, BlockError, CipherDirection, KeyRef};

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

fn encrypt(params: &AeadParamsRef<'_>, plaintext: &[u8]) -> Vec<u8> {
    let mut gcm = GcmBlockCipher::new(AesEngine::new());
    gcm.init(CipherDirection::Encrypt, params).unwrap();
    let mut output = vec![0u8; gcm.output_len(plaintext.len()).unwrap()];
    let mut written = gcm.process_bytes(plaintext, &mut output).unwrap();
    written += gcm.do_final(&mut output[written..]).unwrap();
    assert_eq!(written, output.len());
    output
}

fn check_vector(
    key_hex: &str,
    plaintext_hex: &str,
    aad_hex: &str,
    nonce_hex: &str,
    ciphertext_hex: &str,
    tag_hex: &str,
) {
    let key = decode(key_hex);
    let plaintext = decode(plaintext_hex);
    let aad = decode(aad_hex);
    let nonce = decode(nonce_hex);
    let expected_tag = decode(tag_hex);
    let mut expected = decode(ciphertext_hex);
    expected.extend_from_slice(&expected_tag);
    let params = AeadParamsRef::new(&key, &nonce, expected_tag.len(), &aad);

    let mut encryptor = GcmBlockCipher::new(AesEngine::new());
    encryptor.init(CipherDirection::Encrypt, &params).unwrap();
    let mut encrypted = vec![0u8; encryptor.output_len(plaintext.len()).unwrap()];
    let mut written = encryptor.process_bytes(&plaintext, &mut encrypted).unwrap();
    written += encryptor.do_final(&mut encrypted[written..]).unwrap();
    assert_eq!(written, expected.len());
    assert_eq!(encrypted, expected);
    assert_eq!(encryptor.mac(), Some(expected_tag.as_slice()));

    let mut decryptor = GcmBlockCipher::new(AesEngine::new());
    decryptor.init(CipherDirection::Decrypt, &params).unwrap();
    let mut recovered = vec![0u8; decryptor.output_len(encrypted.len()).unwrap()];
    let mut recovered_len = 0;
    for chunk in encrypted.chunks(7) {
        recovered_len += decryptor
            .process_bytes(chunk, &mut recovered[recovered_len..])
            .unwrap();
    }
    recovered_len += decryptor.do_final(&mut recovered[recovered_len..]).unwrap();
    assert_eq!(recovered_len, plaintext.len());
    assert_eq!(recovered, plaintext);
    assert_eq!(decryptor.mac(), Some(expected_tag.as_slice()));
}

#[test]
fn encryption_and_chunked_decryption_match_the_nist_and_bouncy_castle_vectors() {
    check_vector(
        "00000000000000000000000000000000",
        "",
        "",
        "000000000000000000000000",
        "",
        "58e2fccefa7e3061367f1d57a4e7455a",
    );
    check_vector(
        "00000000000000000000000000000000",
        "",
        "",
        "000000000000000000000000",
        "",
        "58e2fcce",
    );
    check_vector(
        "00000000000000000000000000000000",
        "00000000000000000000000000000000",
        "",
        "000000000000000000000000",
        "0388dace60b6a392f328c2b971b2fe78",
        "ab6e47d42cec13bdf53a67b21257bddf",
    );
    check_vector(
        "feffe9928665731c6d6a8f9467308308",
        concat!(
            "d9313225f88406e5a55909c5aff5269a",
            "86a7a9531534f7da2e4c303d8a318a72",
            "1c3c0c95956809532fcf0e2449a6b525",
            "b16aedf5aa0de657ba637b391aafd255"
        ),
        "",
        "cafebabefacedbaddecaf888",
        concat!(
            "42831ec2217774244b7221b784d0d49c",
            "e3aa212f2c02a4e035c17e2329aca12e",
            "21d514b25466931c7d8f6a5aac84aa05",
            "1ba30b396a0aac973d58e091473f5985"
        ),
        "4d5c2af327cd64a62cf35abd2ba6fab4",
    );
    check_vector(
        "feffe9928665731c6d6a8f9467308308",
        concat!(
            "d9313225f88406e5a55909c5aff5269a",
            "86a7a9531534f7da2e4c303d8a318a72",
            "1c3c0c95956809532fcf0e2449a6b525",
            "b16aedf5aa0de657ba637b39"
        ),
        "feedfacedeadbeeffeedfacedeadbeefabaddad2",
        "cafebabefacedbaddecaf888",
        concat!(
            "42831ec2217774244b7221b784d0d49c",
            "e3aa212f2c02a4e035c17e2329aca12e",
            "21d514b25466931c7d8f6a5aac84aa05",
            "1ba30b396a0aac973d58e091"
        ),
        "5bc94fbc3221a5db94fae95ae7121a47",
    );
    check_vector(
        "feffe9928665731c6d6a8f9467308308",
        concat!(
            "d9313225f88406e5a55909c5aff5269a",
            "86a7a9531534f7da2e4c303d8a318a72",
            "1c3c0c95956809532fcf0e2449a6b525",
            "b16aedf5aa0de657ba637b39"
        ),
        "feedfacedeadbeeffeedfacedeadbeefabaddad2",
        "cafebabefacedbaddecaf888",
        concat!(
            "42831ec2217774244b7221b784d0d49c",
            "e3aa212f2c02a4e035c17e2329aca12e",
            "21d514b25466931c7d8f6a5aac84aa05",
            "1ba30b396a0aac973d58e091"
        ),
        "5bc94fbc3221a5db94fae95a",
    );
    // A 64-bit nonce, which GCM hashes into the initial counter block.
    check_vector(
        "feffe9928665731c6d6a8f9467308308",
        concat!(
            "d9313225f88406e5a55909c5aff5269a",
            "86a7a9531534f7da2e4c303d8a318a72",
            "1c3c0c95956809532fcf0e2449a6b525",
            "b16aedf5aa0de657ba637b39"
        ),
        "feedfacedeadbeeffeedfacedeadbeefabaddad2",
        "cafebabefacedbad",
        concat!(
            "61353b4c2806934a777ff51fa22a4755",
            "699b2a714fcdc6f83766e5f97b6c7423",
            "73806900e49f24b22b097544d4896b42",
            "4989b5e1ebac0f07c23f4598"
        ),
        "3612d2e79e3b0785561be14aaca2fccb",
    );
    // A 480-bit nonce, longer than one block.
    check_vector(
        "feffe9928665731c6d6a8f9467308308",
        concat!(
            "d9313225f88406e5a55909c5aff5269a",
            "86a7a9531534f7da2e4c303d8a318a72",
            "1c3c0c95956809532fcf0e2449a6b525",
            "b16aedf5aa0de657ba637b39"
        ),
        "feedfacedeadbeeffeedfacedeadbeefabaddad2",
        concat!(
            "9313225df88406e555909c5aff5269aa",
            "6a7a9538534f7da1e4c303d2a318a728",
            "c3c0c95156809539fcf0e2429a6b5254",
            "16aedbf5a0de6a57a637b39b"
        ),
        concat!(
            "8ce24998625615b603a033aca13fb894",
            "be9112a5c3a211a8ba262a3cca7e2ca7",
            "01e4a9a4fba43c90ccdcb281d48c7c6f",
            "d62875d2aca417034c34aee5"
        ),
        "619cc5aefffe0bfa462af43c1699d050",
    );
    check_vector(
        "000000000000000000000000000000000000000000000000",
        "",
        "",
        "000000000000000000000000",
        "",
        "cd33b28ac773f74ba00ed1f312572435",
    );
    check_vector(
        "0000000000000000000000000000000000000000000000000000000000000000",
        "",
        "",
        "000000000000000000000000",
        "",
        "530f8afbc74536b9a963b4f1c4cb738b",
    );
}

#[test]
fn chunked_aad_and_message_give_the_same_output_as_single_calls() {
    let key = [0x11u8; 16];
    let nonce = [0x22u8; 11];
    let aad = [0x33u8; 37];
    let plaintext = [0x44u8; 91];
    let params = AeadParamsRef::new(&key, &nonce, 12, &[]);

    let mut expected_engine = GcmBlockCipher::new(AesEngine::new());
    expected_engine
        .init(CipherDirection::Encrypt, &params)
        .unwrap();
    expected_engine.process_aad_bytes(&aad).unwrap();
    let mut expected = [0u8; 103];
    let mut expected_len = expected_engine
        .process_bytes(&plaintext, &mut expected)
        .unwrap();
    expected_len += expected_engine
        .do_final(&mut expected[expected_len..])
        .unwrap();

    let mut actual_engine = GcmBlockCipher::new(AesEngine::new());
    actual_engine
        .init(CipherDirection::Encrypt, &params)
        .unwrap();
    for chunk in aad.chunks(5) {
        actual_engine.process_aad_bytes(chunk).unwrap();
    }
    let mut actual = [0u8; 103];
    let mut actual_len = 0;
    for chunk in plaintext.chunks(7) {
        actual_len += actual_engine
            .process_bytes(chunk, &mut actual[actual_len..])
            .unwrap();
    }
    actual_len += actual_engine.do_final(&mut actual[actual_len..]).unwrap();

    assert_eq!(actual_len, expected_len);
    assert_eq!(actual, expected);
}

#[test]
fn initial_aad_and_streamed_aad_authenticate_the_same_data() {
    let key = [0x11u8; 16];
    let nonce = [0x22u8; 12];
    let initial = encrypt(&AeadParamsRef::new(&key, &nonce, 16, b"header"), b"message");

    let mut streamed = GcmBlockCipher::new(AesEngine::new());
    streamed
        .init(
            CipherDirection::Encrypt,
            &AeadParamsRef::new(&key, &nonce, 16, b"hea"),
        )
        .unwrap();
    streamed.process_aad_bytes(b"der").unwrap();
    let mut output = [0u8; 23];
    let written = streamed.process_bytes(b"message", &mut output).unwrap();
    streamed.do_final(&mut output[written..]).unwrap();
    assert_eq!(output.as_slice(), initial.as_slice());
}

#[test]
fn init_with_parts_matches_init_with_aead_parameters() {
    let key = [0x11u8; 16];
    let nonce = [0x22u8; 12];
    let expected = encrypt(&AeadParamsRef::new(&key, &nonce, 16, b"header"), b"message");

    let mut gcm = GcmBlockCipher::new(AesEngine::new());
    gcm.init_with_parts(
        CipherDirection::Encrypt,
        &KeyRef::new(&key),
        &nonce,
        b"header",
        16,
    )
    .unwrap();
    let mut output = [0u8; 23];
    let written = gcm.process_bytes(b"message", &mut output).unwrap();
    gcm.do_final(&mut output[written..]).unwrap();
    assert_eq!(output.as_slice(), expected.as_slice());
}

#[test]
fn an_empty_nonce_and_out_of_range_tag_sizes_are_rejected_at_initialization() {
    let key = [0x11u8; 16];
    let nonce = [0x22u8; 12];
    let mut gcm = GcmBlockCipher::new(AesEngine::new());

    assert_eq!(
        gcm.init(
            CipherDirection::Encrypt,
            &AeadParamsRef::new(&key, &[], 12, &[]),
        ),
        Err(AeadInitError::InvalidNonceLength { actual: 0 })
    );
    for mac_size in [3, 17] {
        assert_eq!(
            gcm.init(
                CipherDirection::Encrypt,
                &AeadParamsRef::new(&key, &nonce, mac_size, &[]),
            ),
            Err(AeadInitError::InvalidMacSize { actual: mac_size })
        );
    }
    assert_eq!(
        gcm.process_bytes(b"data", &mut [0; 16]),
        Err(AeadError::NotInitialized)
    );
}

#[test]
fn an_invalid_key_is_reported_by_the_cipher_through_source() {
    let mut gcm = GcmBlockCipher::new(AesEngine::new());
    let error = gcm
        .init(
            CipherDirection::Encrypt,
            &AeadParamsRef::new(&[0u8; 15], &[0u8; 12], 16, &[]),
        )
        .unwrap_err();

    assert!(matches!(error, AeadInitError::Cipher(_)));
    assert_eq!(error.to_string(), "underlying cipher initialization failed");
    assert!(error.source().is_some());
}

// A pass-through cipher whose block size is not GCM's 16 bytes.
struct EightByteCipher;

impl BlockCipher for EightByteCipher {
    type Error = BlockError;

    fn block_size(&self) -> usize {
        8
    }

    fn process_block(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, Self::Error> {
        output[..8].copy_from_slice(&input[..8]);
        Ok(8)
    }
}

impl<P: ?Sized> BlockCipherInit<P> for EightByteCipher {
    type Error = Infallible;

    fn init(&mut self, _direction: CipherDirection, _params: &P) -> Result<(), Self::Error> {
        Ok(())
    }
}

#[test]
fn a_cipher_without_16_byte_blocks_is_rejected() {
    let mut gcm = GcmBlockCipher::new(EightByteCipher);
    assert_eq!(
        gcm.init(
            CipherDirection::Encrypt,
            &AeadParamsRef::new(&[0u8; 16], &[0u8; 12], 16, &[]),
        ),
        Err(AeadInitError::InvalidBlockSize {
            actual: 8,
            required: 16,
        })
    );
}

#[test]
fn encryption_refuses_to_reuse_the_previous_key_and_nonce() {
    let key = [0x11u8; 16];
    let other_key = [0x12u8; 16];
    let nonce = [0x22u8; 12];
    let other_nonce = [0x23u8; 12];
    let long_nonce = [0x24u8; 20];
    let mut gcm = GcmBlockCipher::new(AesEngine::new());

    gcm.init(
        CipherDirection::Encrypt,
        &AeadParamsRef::new(&key, &nonce, 16, &[]),
    )
    .unwrap();
    assert_eq!(
        gcm.init(
            CipherDirection::Encrypt,
            &AeadParamsRef::new(&key, &nonce, 12, b"different aad"),
        ),
        Err(AeadInitError::NonceReuse)
    );
    gcm.init(
        CipherDirection::Encrypt,
        &AeadParamsRef::new(&key, &other_nonce, 16, &[]),
    )
    .unwrap();
    gcm.init(
        CipherDirection::Encrypt,
        &AeadParamsRef::new(&other_key, &other_nonce, 16, &[]),
    )
    .unwrap();

    // A nonce other than 96 bits is checked through the hashed initial counter.
    gcm.init(
        CipherDirection::Encrypt,
        &AeadParamsRef::new(&key, &long_nonce, 16, &[]),
    )
    .unwrap();
    assert_eq!(
        gcm.init(
            CipherDirection::Encrypt,
            &AeadParamsRef::new(&key, &long_nonce, 16, &[]),
        ),
        Err(AeadInitError::NonceReuse)
    );
}

#[test]
fn a_decryption_init_counts_toward_nonce_reuse_but_may_repeat() {
    let key = [0x11u8; 16];
    let nonce = [0x22u8; 12];
    let params = AeadParamsRef::new(&key, &nonce, 16, &[]);
    let mut gcm = GcmBlockCipher::new(AesEngine::new());

    gcm.init(CipherDirection::Decrypt, &params).unwrap();
    gcm.init(CipherDirection::Decrypt, &params).unwrap();
    assert_eq!(
        gcm.init(CipherDirection::Encrypt, &params),
        Err(AeadInitError::NonceReuse)
    );
}

#[test]
fn associated_data_after_message_data_is_rejected() {
    let mut gcm = GcmBlockCipher::new(AesEngine::new());
    gcm.init(
        CipherDirection::Encrypt,
        &AeadParamsRef::new(&[0x11; 16], &[0x22; 12], 12, b"header"),
    )
    .unwrap();

    assert_eq!(gcm.process_bytes(b"secret", &mut []), Ok(0));
    assert_eq!(gcm.process_aad_bytes(b"late"), Err(AeadError::AadAfterData));
}

#[test]
fn tampering_with_ciphertext_tag_or_aad_fails_authentication_without_writing_output() {
    let key = [0x11u8; 16];
    let nonce = [0x22u8; 12];
    let encrypted = encrypt(&AeadParamsRef::new(&key, &nonce, 16, b"header"), b"message");

    for (index, aad) in [
        (0, &b"header"[..]),
        (encrypted.len() - 1, b"header"),
        (usize::MAX, b"Header"),
    ] {
        let mut received = encrypted.clone();
        if index != usize::MAX {
            received[index] ^= 1;
        }
        let mut decryptor = GcmBlockCipher::new(AesEngine::new());
        decryptor
            .init(
                CipherDirection::Decrypt,
                &AeadParamsRef::new(&key, &nonce, 16, aad),
            )
            .unwrap();
        assert_eq!(decryptor.process_bytes(&received, &mut []), Ok(0));
        let mut output = [0xabu8; 7];
        assert_eq!(
            decryptor.do_final(&mut output),
            Err(AeadError::AuthenticationFailed)
        );
        assert_eq!(output, [0xab; 7]);
        assert_eq!(decryptor.mac(), None);
        assert_eq!(
            decryptor.do_final(&mut output),
            Err(AeadError::AlreadyFinalized)
        );
    }
}

#[test]
fn a_ciphertext_shorter_than_the_tag_is_rejected() {
    let mut gcm = GcmBlockCipher::new(AesEngine::new());
    gcm.init(
        CipherDirection::Decrypt,
        &AeadParamsRef::new(&[0x11; 16], &[0x22; 12], 16, &[]),
    )
    .unwrap();

    assert_eq!(gcm.process_bytes(&[0u8; 15], &mut []), Ok(0));
    assert_eq!(
        gcm.do_final(&mut []),
        Err(AeadError::CiphertextTooShort {
            minimum: 16,
            actual: 15,
        })
    );
}

#[test]
fn the_name_block_size_and_output_lengths_follow_the_engine_state() {
    let params = AeadParamsRef::new(&[0u8; 16], &[0u8; 12], 16, b"header");
    let mut gcm = GcmBlockCipher::new(AesEngine::new());
    assert_eq!(gcm.to_string(), "AES/GCM");
    assert_eq!(gcm.block_size(), 16);
    assert_eq!(gcm.underlying_cipher().block_size(), 16);

    gcm.init(CipherDirection::Encrypt, &params).unwrap();
    assert_eq!(gcm.update_output_len(15), Ok(0));
    assert_eq!(gcm.update_output_len(16), Ok(16));
    assert_eq!(gcm.output_len(15), Ok(31));
    assert_eq!(gcm.output_len(usize::MAX), Err(AeadError::InputTooLong));

    let mut decryptor = GcmBlockCipher::new(AesEngine::new());
    decryptor.init(CipherDirection::Decrypt, &params).unwrap();
    assert_eq!(decryptor.output_len(15), Ok(0));
    assert_eq!(decryptor.output_len(48), Ok(32));
    assert_eq!(decryptor.update_output_len(47), Ok(16));
}

#[test]
fn reset_after_encrypting_data_finalizes_the_engine() {
    let params = AeadParamsRef::new(&[0u8; 16], &[0u8; 12], 16, b"header");
    let mut gcm = GcmBlockCipher::new(AesEngine::new());
    gcm.init(CipherDirection::Encrypt, &params).unwrap();

    gcm.reset();
    assert_eq!(gcm.output_len(0), Ok(16));
    gcm.process_bytes(&[0u8; 1], &mut []).unwrap();
    gcm.reset();
    assert_eq!(
        gcm.process_bytes(&[], &mut []),
        Err(AeadError::AlreadyFinalized)
    );
}

#[test]
fn decrypt_reset_restores_initial_aad_and_discards_buffered_ciphertext() {
    let key = [0x11u8; 16];
    let nonce = [0x22u8; 12];
    let params = AeadParamsRef::new(&key, &nonce, 16, b"initial header");
    let encrypted = encrypt(&params, b"message");

    let mut decryptor = GcmBlockCipher::new(AesEngine::new());
    decryptor.init(CipherDirection::Decrypt, &params).unwrap();
    assert_eq!(decryptor.process_bytes(&encrypted[..5], &mut []), Ok(0));
    decryptor.reset();

    for _ in 0..2 {
        let mut recovered = [0u8; 7];
        let mut recovered_len = decryptor.process_bytes(&encrypted, &mut recovered).unwrap();
        recovered_len += decryptor.do_final(&mut recovered[recovered_len..]).unwrap();
        assert_eq!(recovered_len, 7);
        assert_eq!(&recovered, b"message");
        decryptor.reset();
    }
}

#[test]
fn a_short_output_buffer_is_rejected_without_consuming_input() {
    let params = AeadParamsRef::new(&[0u8; 16], &[0u8; 12], 16, &[]);
    let plaintext = [0u8; 16];
    let mut gcm = GcmBlockCipher::new(AesEngine::new());
    gcm.init(CipherDirection::Encrypt, &params).unwrap();

    assert_eq!(
        gcm.process_bytes(&plaintext, &mut [0u8; 15]),
        Err(AeadError::OutputTooShort {
            required: 16,
            available: 15,
        })
    );

    let mut encrypted = [0u8; 32];
    let mut written = gcm.process_bytes(&plaintext, &mut encrypted).unwrap();
    written += gcm.do_final(&mut encrypted[written..]).unwrap();
    assert_eq!(written, encrypted.len());
    assert_eq!(
        encrypted[..16],
        decode("0388dace60b6a392f328c2b971b2fe78")[..]
    );
    assert_eq!(
        encrypted[16..],
        decode("ab6e47d42cec13bdf53a67b21257bddf")[..]
    );
}

#[test]
fn the_parameter_debug_output_shows_only_lengths() {
    let params = AeadParamsRef::new(&[0xff; 16], &[0xee; 12], 16, b"header");
    assert_eq!(
        format!("{params:?}"),
        "AeadParamsRef { key_len: 16, nonce_len: 12, initial_aad_len: 6, mac_size: 16 }"
    );
}
