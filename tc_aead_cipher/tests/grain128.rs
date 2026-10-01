#![cfg(feature = "alloc")]

use tc_aead_cipher::{
    AeadCipher, AeadCipherInit, AeadError, AeadInitError, AeadParamsRef, FixedGrain128Aead,
    Grain128Aead,
};
use tc_block_cipher::CipherDirection;

const KEY_BYTES: usize = 16;
const NONCE_BYTES: usize = 12;
const TAG_BYTES: usize = 8;

fn algo_name(engine: &Grain128Aead) -> String {
    engine.to_string()
}

struct Kat {
    plaintext: &'static str,
    aad: &'static str,
    ciphertext_and_tag: &'static str,
}

const KEY: &str = "000102030405060708090A0B0C0D0E0F";
const NONCE: &str = "000102030405060708090A0B";

const KATS: &[Kat] = &[
    Kat {
        plaintext: "",
        aad: "",
        ciphertext_and_tag: "D51FD5D16177B434",
    },
    Kat {
        plaintext: "",
        aad: "00",
        ciphertext_and_tag: "99B7CDBF488F8DC0",
    },
    Kat {
        plaintext: "00",
        aad: "",
        ciphertext_and_tag: "21AAA5A068EA941DB3",
    },
    Kat {
        plaintext: "000102030405060708090A0B0C0D0E0F",
        aad: "",
        ciphertext_and_tag: "21678706FB8AB6369ED9B5AFA619F8B27DEA6B6B907BE8FF",
    },
    Kat {
        plaintext: "000102030405060708090A0B0C0D0E0F",
        aad: "000102030405060708090A0B0C0D0E0F",
        ciphertext_and_tag: "80B53BE28E938BAE76B64CCD53BE4DE5FB0720DE18EA8FAE",
    },
    Kat {
        plaintext: "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
        aad: "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
        ciphertext_and_tag: "D70DF45E4839CFF9A2C139C719805CFCAAB5AB651B99A751FBF4B8D75ABD6D97F543FE1CFBE56F72",
    },
    Kat {
        plaintext: "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
        aad: "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F606162636465666768696A6B6C6D6E6F707172737475767778797A7B7C7D7E7F808182838485868788898A8B8C8D8E8F909192939495969798999A9B9C9D9E9FA0A1A2A3A4A5A6A7A8A9AAABACADAEAFB0B1B2B3B4B5B6B7B8B9",
        ciphertext_and_tag: "731DAA8B1D15317A1CCB4E3DD320095FB27E5BB2A10F2C669F870538637D4F162298C70430A2B560",
    },
];

fn decode_hex(input: &str) -> Vec<u8> {
    input
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| u8::from_str_radix(core::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

fn material() -> (Vec<u8>, Vec<u8>) {
    (decode_hex(KEY), decode_hex(NONCE))
}

fn encrypt(plaintext: &[u8], aad: &[u8]) -> Vec<u8> {
    let (key, nonce) = material();
    let params = AeadParamsRef::new(&key, &nonce, 8, aad);
    let mut engine = Grain128Aead::new();
    engine.init(CipherDirection::Encrypt, &params).unwrap();
    let mut output = vec![0xA5; engine.output_len(plaintext.len()).unwrap()];
    let mut written = engine.process_bytes(plaintext, &mut output).unwrap();
    written += engine.do_final(&mut output[written..]).unwrap();
    output.truncate(written);
    output
}

fn decrypt(ciphertext: &[u8], aad: &[u8]) -> Vec<u8> {
    let (key, nonce) = material();
    let params = AeadParamsRef::new(&key, &nonce, 8, aad);
    let mut engine = Grain128Aead::new();
    engine.init(CipherDirection::Decrypt, &params).unwrap();
    let mut output = vec![0xA5; engine.output_len(ciphertext.len()).unwrap()];
    let mut written = engine.process_bytes(ciphertext, &mut output).unwrap();
    written += engine.do_final(&mut output[written..]).unwrap();
    output.truncate(written);
    output
}

#[test]
fn encryption_and_decryption_match_the_official_and_bouncy_castle_vectors() {
    for kat in KATS {
        let plaintext = decode_hex(kat.plaintext);
        let aad = decode_hex(kat.aad);
        let expected = decode_hex(kat.ciphertext_and_tag);
        assert_eq!(encrypt(&plaintext, &aad), expected);
        assert_eq!(decrypt(&expected, &aad), plaintext);
    }
}

#[test]
fn incremental_aad_and_data_match_the_vectors() {
    let kat = &KATS[5];
    let plaintext = decode_hex(kat.plaintext);
    let aad = decode_hex(kat.aad);
    let expected = decode_hex(kat.ciphertext_and_tag);
    let (key, nonce) = material();

    for split in 0..=plaintext.len() {
        let params = AeadParamsRef::new(&key, &nonce, 8, &[]);
        let mut engine = Grain128Aead::new();
        engine.init(CipherDirection::Encrypt, &params).unwrap();
        engine.process_aad_bytes(&aad[..7]).unwrap();
        engine.process_aad_bytes(&aad[7..]).unwrap();

        let mut output = vec![0_u8; expected.len()];
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
        let params = AeadParamsRef::new(&key, &nonce, 8, &[]);
        let mut engine = Grain128Aead::new();
        engine.init(CipherDirection::Decrypt, &params).unwrap();
        engine.process_aad_bytes(&aad[..15]).unwrap();
        engine.process_aad_bytes(&aad[15..]).unwrap();

        let mut output = vec![0_u8; plaintext.len()];
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
fn the_fixed_engine_enforces_its_aad_capacity() {
    let (key, nonce) = material();
    let params = AeadParamsRef::new(&key, &nonce, 8, &[]);
    let mut engine = FixedGrain128Aead::<3>::new();
    engine.init(CipherDirection::Encrypt, &params).unwrap();
    engine.process_aad_bytes(&[1, 2]).unwrap();
    assert_eq!(
        engine.process_aad_bytes(&[3, 4]),
        Err(AeadError::AadTooLong {
            maximum: 3,
            actual: 4,
        })
    );
    engine.process_aad_bytes(&[3]).unwrap();
    assert_eq!(engine.do_final(&mut [0_u8; TAG_BYTES]), Ok(TAG_BYTES));
}

#[test]
fn invalid_initialization_lengths_are_rejected() {
    let (key, nonce) = material();
    let mut engine = Grain128Aead::new();

    let params = AeadParamsRef::new(&key[..KEY_BYTES - 1], &nonce, 8, &[]);
    assert_eq!(
        engine.init(CipherDirection::Encrypt, &params),
        Err(AeadInitError::InvalidKeyLength {
            actual: KEY_BYTES - 1
        })
    );

    let params = AeadParamsRef::new(&key, &nonce[..NONCE_BYTES - 1], 8, &[]);
    assert_eq!(
        engine.init(CipherDirection::Encrypt, &params),
        Err(AeadInitError::InvalidNonceLength {
            actual: NONCE_BYTES - 1
        })
    );

    let params = AeadParamsRef::new(&key, &nonce, 8, &[1, 2]);
    let mut fixed = FixedGrain128Aead::<1>::new();
    assert_eq!(
        fixed.init(CipherDirection::Encrypt, &params),
        Err(AeadInitError::InvalidInitialAadLength { actual: 2 })
    );
}

#[test]
fn modified_tags_and_short_ciphertexts_are_rejected() {
    let kat = KATS.last().unwrap();
    let aad = decode_hex(kat.aad);
    let mut ciphertext = decode_hex(kat.ciphertext_and_tag);
    *ciphertext.last_mut().unwrap() ^= 1;
    let (key, nonce) = material();
    let params = AeadParamsRef::new(&key, &nonce, 8, &aad);
    let mut engine = Grain128Aead::new();
    engine.init(CipherDirection::Decrypt, &params).unwrap();
    let mut output = vec![0xA5; engine.output_len(ciphertext.len()).unwrap()];
    let written = engine.process_bytes(&ciphertext, &mut output).unwrap();
    assert_eq!(
        engine.do_final(&mut output[written..]),
        Err(AeadError::AuthenticationFailed)
    );
    assert_eq!(engine.mac(), None);

    let params = AeadParamsRef::new(&key, &nonce, 8, &[]);
    engine.init(CipherDirection::Decrypt, &params).unwrap();
    assert_eq!(engine.process_bytes(&[0_u8; TAG_BYTES - 1], &mut []), Ok(0));
    assert_eq!(
        engine.do_final(&mut []),
        Err(AeadError::CiphertextTooShort {
            minimum: TAG_BYTES,
            actual: TAG_BYTES - 1,
        })
    );
}

#[test]
fn the_metadata_state_rules_and_buffer_rules_are_enforced() {
    let (key, nonce) = material();
    let params = AeadParamsRef::new(&key, &nonce, 8, &[]);
    let mut engine = Grain128Aead::new();
    assert_eq!(algo_name(&engine), "Grain-128AEAD");
    assert_eq!(engine.key_bytes(), KEY_BYTES);
    assert_eq!(engine.nonce_bytes(), NONCE_BYTES);
    assert_eq!(engine.tag_bytes(), TAG_BYTES);
    assert_eq!(engine.update_output_len(5).unwrap(), 5);
    assert_eq!(engine.output_len(5).unwrap(), 5 + TAG_BYTES);
    assert_eq!(
        engine.process_bytes(&[], &mut []),
        Err(AeadError::NotInitialized)
    );

    engine.init(CipherDirection::Encrypt, &params).unwrap();
    assert_eq!(
        engine.process_bytes(&[0_u8; 5], &mut [0_u8; 4]),
        Err(AeadError::OutputTooShort {
            required: 5,
            available: 4,
        })
    );
    assert_eq!(engine.process_bytes(&[0_u8; 5], &mut [0_u8; 5]), Ok(5));
    assert_eq!(engine.process_aad_bytes(&[0]), Err(AeadError::AadAfterData));
    let mut tag = [0_u8; TAG_BYTES];
    assert_eq!(engine.do_final(&mut tag), Ok(TAG_BYTES));
    assert_eq!(engine.mac(), Some(tag.as_slice()));
    assert_eq!(engine.do_final(&mut []), Err(AeadError::AlreadyFinalized));
}

#[test]
fn a_tag_size_other_than_eight_bytes_is_rejected() {
    let (key, nonce) = material();
    let mut engine = Grain128Aead::new();
    for mac_size in [4, 16] {
        assert_eq!(
            engine.init(
                CipherDirection::Encrypt,
                &AeadParamsRef::new(&key, &nonce, mac_size, &[])
            ),
            Err(AeadInitError::InvalidMacSize { actual: mac_size })
        );
    }
}
