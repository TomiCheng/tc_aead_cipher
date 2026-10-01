use tc_aead_cipher::{
    AeadCipher, AeadCipherInit, AeadError, AeadInitError, AeadParamsRef, AsconAead128,
};
use tc_block_cipher::CipherDirection;

struct Kat {
    plaintext: &'static str,
    aad: &'static str,
    ciphertext_and_tag: &'static str,
}

const KEY: &str = "000102030405060708090A0B0C0D0E0F";
const NONCE: &str = "101112131415161718191A1B1C1D1E1F";

// Official ascon-c finalized Ascon-AEAD128 KATs covering empty input,
// rate-boundary lengths, and multi-block input.
const KATS: &[Kat] = &[
    Kat {
        plaintext: "",
        aad: "",
        ciphertext_and_tag: "4F9C278211BEC9316BF68F46EE8B2EC6",
    },
    Kat {
        plaintext: "",
        aad: "3031323334353637",
        ciphertext_and_tag: "865C594093A9EDEE2C1D6384CCB4939E",
    },
    Kat {
        plaintext: "",
        aad: "303132333435363738393A3B3C3D3E",
        ciphertext_and_tag: "759102A6953861627AAE1836D003A294",
    },
    Kat {
        plaintext: "",
        aad: "303132333435363738393A3B3C3D3E3F",
        ciphertext_and_tag: "E4230CDB8330EE9DC0CFD7C7B346E6DC",
    },
    Kat {
        plaintext: "",
        aad: "303132333435363738393A3B3C3D3E3F40",
        ciphertext_and_tag: "BD8851CD3AF9847844839A791DD70E8C",
    },
    Kat {
        plaintext: "20",
        aad: "30",
        ciphertext_and_tag: "962B8016836C75A7D86866588CA245D886",
    },
    Kat {
        plaintext: "2021222324252627",
        aad: "",
        ciphertext_and_tag: "E8C3DEEE246CC5EAE455EF6B33B782A3DD91ED6695373C27",
    },
    Kat {
        plaintext: "202122232425262728292A2B2C2D2E",
        aad: "",
        ciphertext_and_tag: "E8C3DEEE246CC5EAE3E872313897A283AECC1DA0834A52940EC4BFCDDB6404",
    },
    Kat {
        plaintext: "202122232425262728292A2B2C2D2E2F",
        aad: "",
        ciphertext_and_tag: "E8C3DEEE246CC5EAE3E872313897A2BB9EAA915C9DD3245D77048F24D46D27A7",
    },
    Kat {
        plaintext: "202122232425262728292A2B2C2D2E2F30",
        aad: "",
        ciphertext_and_tag: "E8C3DEEE246CC5EAE3E872313897A2BB60301002539D456275DD0B0CEAB3B23844",
    },
    Kat {
        plaintext: "202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F",
        aad: "303132333435363738393A3B3C3D3E3F404142434445464748494A4B4C4D4E4F",
        ciphertext_and_tag: "CB34D04660A66DBFBE9C856601F5B8AA51A499B55AC8F7FBEFBC331A613EE9CDFD191750A47F211C0A15ED28173D7CAA",
    },
];

fn hex(input: &str) -> Vec<u8> {
    assert_eq!(input.len() % 2, 0, "hex input must have an even length");
    input
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| u8::from_str_radix(core::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

fn key_and_nonce() -> (Vec<u8>, Vec<u8>) {
    (hex(KEY), hex(NONCE))
}

fn encrypt(plaintext: &[u8], aad: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let (key, nonce) = key_and_nonce();
    let params = AeadParamsRef::new(&key, &nonce, 16, &[]);
    let mut engine = AsconAead128::new();
    engine.init(CipherDirection::Encrypt, &params).unwrap();
    engine.process_aad_bytes(aad).unwrap();

    let mut output = vec![0xa5; engine.output_len(plaintext.len()).unwrap()];
    let mut written = engine.process_bytes(plaintext, &mut output).unwrap();
    written += engine.do_final(&mut output[written..]).unwrap();
    output.truncate(written);
    (output, engine.mac().unwrap().to_vec())
}

fn decrypt(ciphertext: &[u8], aad: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let (key, nonce) = key_and_nonce();
    let params = AeadParamsRef::new(&key, &nonce, 16, &[]);
    let mut engine = AsconAead128::new();
    engine.init(CipherDirection::Decrypt, &params).unwrap();
    engine.process_aad_bytes(aad).unwrap();

    let mut output = vec![0xa5; engine.output_len(ciphertext.len()).unwrap()];
    let mut written = engine.process_bytes(ciphertext, &mut output).unwrap();
    written += engine.do_final(&mut output[written..]).unwrap();
    output.truncate(written);
    (output, engine.mac().unwrap().to_vec())
}

#[test]
fn encryption_and_decryption_match_the_official_ascon_aead128_vectors() {
    for kat in KATS {
        let plaintext = hex(kat.plaintext);
        let aad = hex(kat.aad);
        let expected = hex(kat.ciphertext_and_tag);

        let (encrypted, generated_tag) = encrypt(&plaintext, &aad);
        assert_eq!(encrypted, expected);
        assert_eq!(generated_tag, expected[expected.len() - 16..]);

        let (decrypted, verified_tag) = decrypt(&expected, &aad);
        assert_eq!(decrypted, plaintext);
        assert_eq!(verified_tag, expected[expected.len() - 16..]);
    }
}

#[test]
fn every_message_split_and_both_aad_paths_match_the_vector() {
    let kat = KATS.last().unwrap();
    let plaintext = hex(kat.plaintext);
    let aad = hex(kat.aad);
    let expected = hex(kat.ciphertext_and_tag);
    let (key, nonce) = key_and_nonce();

    for split in 0..=plaintext.len() {
        let params = AeadParamsRef::new(&key, &nonce, 16, &aad);
        let mut engine = AsconAead128::new();
        engine.init(CipherDirection::Encrypt, &params).unwrap();
        let mut output = vec![0; expected.len()];
        let mut written = engine
            .process_bytes(&plaintext[..split], &mut output)
            .unwrap();
        written += engine
            .process_bytes(&plaintext[split..], &mut output[written..])
            .unwrap();
        written += engine.do_final(&mut output[written..]).unwrap();
        assert_eq!(&output[..written], expected);
    }

    for split in 0..=expected.len() {
        let params = AeadParamsRef::new(&key, &nonce, 16, &[]);
        let mut engine = AsconAead128::new();
        engine.init(CipherDirection::Decrypt, &params).unwrap();
        engine.process_aad_bytes(&aad[..15]).unwrap();
        engine.process_aad_bytes(&aad[15..]).unwrap();
        let mut output = vec![0; plaintext.len()];
        let mut written = engine
            .process_bytes(&expected[..split], &mut output)
            .unwrap();
        written += engine
            .process_bytes(&expected[split..], &mut output[written..])
            .unwrap();
        written += engine.do_final(&mut output[written..]).unwrap();
        assert_eq!(&output[..written], plaintext);
    }
}

#[test]
fn a_modified_tag_or_a_ciphertext_shorter_than_the_tag_is_rejected() {
    let plaintext = hex(KATS[9].plaintext);
    let aad = hex(KATS[9].aad);
    let (mut ciphertext, _) = encrypt(&plaintext, &aad);
    *ciphertext.last_mut().unwrap() ^= 1;
    let (key, nonce) = key_and_nonce();
    let params = AeadParamsRef::new(&key, &nonce, 16, &[]);
    let mut engine = AsconAead128::new();
    engine.init(CipherDirection::Decrypt, &params).unwrap();
    let mut output = vec![0xa5; plaintext.len()];
    let written = engine.process_bytes(&ciphertext, &mut output).unwrap();
    assert_eq!(
        engine.do_final(&mut output[written..]),
        Err(AeadError::AuthenticationFailed)
    );
    assert_eq!(engine.mac(), None);
    assert_eq!(
        engine.do_final(&mut output[written..]),
        Err(AeadError::AlreadyFinalized)
    );

    engine.init(CipherDirection::Decrypt, &params).unwrap();
    assert_eq!(engine.process_bytes(&[0; 15], &mut []), Ok(0));
    assert_eq!(
        engine.do_final(&mut []),
        Err(AeadError::CiphertextTooShort {
            minimum: 16,
            actual: 15,
        })
    );
}

#[test]
fn the_name_output_size_and_initialization_errors_are_reported() {
    let key = [0x11; 16];
    let nonce = [0x22; 16];
    let params = AeadParamsRef::new(&key, &nonce, 16, &[]);
    let mut concrete = AsconAead128::new();
    concrete.init(CipherDirection::Encrypt, &params).unwrap();

    assert_eq!(concrete.to_string(), "Ascon-AEAD128");
    let cipher: &mut dyn AeadCipher<Error = AeadError> = &mut concrete;
    assert_eq!(cipher.output_len(0).unwrap(), 16);

    let bad_key = [0u8; 15];
    let bad = AeadParamsRef::new(&bad_key, &nonce, 16, &[]);
    assert_eq!(
        concrete.init(CipherDirection::Encrypt, &bad),
        Err(AeadInitError::InvalidKeyLength { actual: 15 })
    );
    let bad_nonce = [0u8; 15];
    let bad = AeadParamsRef::new(&key, &bad_nonce, 16, &[]);
    assert!(matches!(
        concrete.init(CipherDirection::Encrypt, &bad),
        Err(AeadInitError::InvalidNonceLength { actual: 15 })
    ));
}

#[test]
fn truncated_tags_are_the_leftmost_bytes_of_the_full_tag() {
    let (key, nonce) = key_and_nonce();
    for kat in KATS {
        let plaintext = hex(kat.plaintext);
        let aad = hex(kat.aad);
        let full = hex(kat.ciphertext_and_tag);
        let ciphertext_len = full.len() - 16;
        for mac_size in [4, 8, 12, 15] {
            let expected = &full[..ciphertext_len + mac_size];
            let params = AeadParamsRef::new(&key, &nonce, mac_size, &aad);

            let mut encryptor = AsconAead128::new();
            encryptor.init(CipherDirection::Encrypt, &params).unwrap();
            let mut output = vec![0; encryptor.output_len(plaintext.len()).unwrap()];
            let mut written = encryptor.process_bytes(&plaintext, &mut output).unwrap();
            written += encryptor.do_final(&mut output[written..]).unwrap();
            assert_eq!(&output[..written], expected);
            assert_eq!(
                encryptor.mac(),
                Some(&full[ciphertext_len..ciphertext_len + mac_size])
            );

            let mut decryptor = AsconAead128::new();
            decryptor.init(CipherDirection::Decrypt, &params).unwrap();
            let mut recovered = vec![0; decryptor.output_len(expected.len()).unwrap()];
            let mut recovered_len = 0;
            for chunk in expected.chunks(3) {
                recovered_len += decryptor
                    .process_bytes(chunk, &mut recovered[recovered_len..])
                    .unwrap();
            }
            recovered_len += decryptor.do_final(&mut recovered[recovered_len..]).unwrap();
            assert_eq!(&recovered[..recovered_len], plaintext);

            let mut tampered = expected.to_vec();
            *tampered.last_mut().unwrap() ^= 1;
            let mut decryptor = AsconAead128::new();
            decryptor.init(CipherDirection::Decrypt, &params).unwrap();
            let mut recovered = vec![0; tampered.len()];
            let written = decryptor.process_bytes(&tampered, &mut recovered).unwrap();
            assert_eq!(
                decryptor.do_final(&mut recovered[written..]),
                Err(AeadError::AuthenticationFailed)
            );
        }
    }
}

#[test]
fn tag_sizes_outside_four_to_sixteen_bytes_are_rejected() {
    let (key, nonce) = key_and_nonce();
    let mut engine = AsconAead128::new();
    for mac_size in [0, 3, 17] {
        assert_eq!(
            engine.init(
                CipherDirection::Encrypt,
                &AeadParamsRef::new(&key, &nonce, mac_size, &[])
            ),
            Err(AeadInitError::InvalidMacSize { actual: mac_size })
        );
    }
}

#[test]
fn reset_right_after_an_encryption_init_with_initial_aad_keeps_the_engine_usable() {
    let kat = KATS.last().unwrap();
    let plaintext = hex(kat.plaintext);
    let aad = hex(kat.aad);
    let (key, nonce) = key_and_nonce();
    let mut engine = AsconAead128::new();
    engine
        .init(
            CipherDirection::Encrypt,
            &AeadParamsRef::new(&key, &nonce, 16, &aad),
        )
        .unwrap();
    engine.reset();

    let mut output = vec![0; engine.output_len(plaintext.len()).unwrap()];
    let mut written = engine.process_bytes(&plaintext, &mut output).unwrap();
    written += engine.do_final(&mut output[written..]).unwrap();
    assert_eq!(output[..written], hex(kat.ciphertext_and_tag)[..]);
}

#[test]
fn empty_aad_still_reports_the_engine_state() {
    let (key, nonce) = key_and_nonce();
    let mut engine = AsconAead128::new();
    assert_eq!(
        engine.process_aad_bytes(&[]),
        Err(AeadError::NotInitialized)
    );

    engine
        .init(
            CipherDirection::Encrypt,
            &AeadParamsRef::new(&key, &nonce, 16, &[]),
        )
        .unwrap();
    assert_eq!(engine.output_len(usize::MAX), Err(AeadError::InputTooLong));
    engine.process_bytes(b"data", &mut [0; 16]).unwrap();
    assert_eq!(engine.process_aad_bytes(&[]), Err(AeadError::AadAfterData));
    engine.do_final(&mut [0; 20]).unwrap();
    assert_eq!(
        engine.process_aad_bytes(&[]),
        Err(AeadError::AlreadyFinalized)
    );
}
