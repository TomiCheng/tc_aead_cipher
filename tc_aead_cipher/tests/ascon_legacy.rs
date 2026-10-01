use tc_aead_cipher::{
    AeadCipher, AeadCipherInit, AeadError, AeadInitError, AeadParamsRef, AsconLegacyEngine,
    AsconLegacyVariant,
};
use tc_block_cipher::CipherDirection;

const KEY_BYTES_128: usize = 16;
const KEY_BYTES_80PQ: usize = 20;
const NONCE_BYTES: usize = 16;
const TAG_BYTES: usize = 16;

struct Kat {
    plaintext: &'static str,
    aad: &'static str,
    ciphertext_and_tag: &'static str,
}

const KEY_128: &str = "000102030405060708090A0B0C0D0E0F";
const KEY_80PQ: &str = "000102030405060708090A0B0C0D0E0F10111213";
const NONCE: &str = "000102030405060708090A0B0C0D0E0F";

const ASCON128_KATS: &[Kat] = &[
    Kat {
        plaintext: "",
        aad: "",
        ciphertext_and_tag: "E355159F292911F794CB1432A0103A8A",
    },
    Kat {
        plaintext: "",
        aad: "00",
        ciphertext_and_tag: "944DF887CD4901614C5DEDBC42FC0DA0",
    },
    Kat {
        plaintext: "00",
        aad: "",
        ciphertext_and_tag: "BC18C3F4E39ECA7222490D967C79BFFC92",
    },
    Kat {
        plaintext: "0001020304050607",
        aad: "",
        ciphertext_and_tag: "BC820DBDF7A4631C01A8807A44254B42AC6BB490DA1E000A",
    },
    Kat {
        plaintext: "000102030405060708090A0B0C0D0E0F",
        aad: "",
        ciphertext_and_tag: "BC820DBDF7A4631C5B29884AD69175C3F58E28436DD71556D58DFA56AC890BEB",
    },
    Kat {
        plaintext: "000102030405060708090A0B0C0D0E0F",
        aad: "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
        ciphertext_and_tag: "B96C78651B6246B0C3B1A5D373B0D51656B8B02AE9C620D98ED6E1F8E5589F64",
    },
    Kat {
        plaintext: "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
        aad: "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
        ciphertext_and_tag: "B96C78651B6246B0C3B1A5D373B0D5168DCA4A96734CF0DDF5F92F8D15E30270279BF6A6CC3F2FC9350B915C292BDB8D",
    },
];

const ASCON128A_KATS: &[Kat] = &[
    Kat {
        plaintext: "",
        aad: "",
        ciphertext_and_tag: "7A834E6F09210957067B10FD831F0078",
    },
    Kat {
        plaintext: "",
        aad: "00",
        ciphertext_and_tag: "AF3031B07B129EC84153373DDCABA528",
    },
    Kat {
        plaintext: "00",
        aad: "",
        ciphertext_and_tag: "6E652B55BFDC8CAD2EC43815B1666B1A3A",
    },
    Kat {
        plaintext: "0001020304050607",
        aad: "",
        ciphertext_and_tag: "6E490CFED5B35467B89C7E12863CE5F76AFC808FFF786B9E",
    },
    Kat {
        plaintext: "000102030405060708090A0B0C0D0E0F",
        aad: "",
        ciphertext_and_tag: "6E490CFED5B3546767350CD83C4ACFBDB10F611B7D79278BD8067FC1BCDF39BE",
    },
    Kat {
        plaintext: "000102030405060708090A0B0C0D0E0F",
        aad: "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
        ciphertext_and_tag: "A55236AC020DBDA74CE6CCD10C68C4D88A95D7D97F774CB274ACBB055AF1938E",
    },
    Kat {
        plaintext: "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
        aad: "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
        ciphertext_and_tag: "A55236AC020DBDA74CE6CCD10C68C4D8514450A382BC87C68946D86A921DD88E2ADDDFBBE77D4112830E01960B9D38D5",
    },
];

const ASCON80PQ_KATS: &[Kat] = &[
    Kat {
        plaintext: "",
        aad: "",
        ciphertext_and_tag: "ABB688EFA0B9D56B33277A2C97D2146B",
    },
    Kat {
        plaintext: "",
        aad: "00",
        ciphertext_and_tag: "A259D760E87B0CA73002C3A01E69B567",
    },
    Kat {
        plaintext: "00",
        aad: "",
        ciphertext_and_tag: "28AA80FFF4CA3AF32F60EBCAF63A4CCAB7",
    },
    Kat {
        plaintext: "0001020304050607",
        aad: "",
        ciphertext_and_tag: "2846418067CE93861A484E22565F161146FB6F47913803F9",
    },
    Kat {
        plaintext: "000102030405060708090A0B0C0D0E0F",
        aad: "",
        ciphertext_and_tag: "2846418067CE9386B47F0584BF9EEE3F818CA2B264F3BBFC40B773D0EB81F594",
    },
    Kat {
        plaintext: "000102030405060708090A0B0C0D0E0F",
        aad: "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
        ciphertext_and_tag: "CC4E07E5FB13426EFFD17B0F51A6A83016F564E1D50A502B9B4FE794A806DC75",
    },
    Kat {
        plaintext: "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
        aad: "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
        ciphertext_and_tag: "CC4E07E5FB13426EFFD17B0F51A6A830BF484C9651D77679971E8EB4A8EDB5A00782A94C72B2B02D87DCF4AF75DB6996",
    },
];

const VARIANTS: [AsconLegacyVariant; 3] = [
    AsconLegacyVariant::Ascon128,
    AsconLegacyVariant::Ascon128a,
    AsconLegacyVariant::Ascon80pq,
];

fn decode_hex(input: &str) -> Vec<u8> {
    assert_eq!(input.len() % 2, 0, "hex input must have an even length");
    input
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| u8::from_str_radix(core::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

fn key(variant: AsconLegacyVariant) -> Vec<u8> {
    decode_hex(match variant {
        AsconLegacyVariant::Ascon128 | AsconLegacyVariant::Ascon128a => KEY_128,
        AsconLegacyVariant::Ascon80pq => KEY_80PQ,
    })
}

fn kats(variant: AsconLegacyVariant) -> &'static [Kat] {
    match variant {
        AsconLegacyVariant::Ascon128 => ASCON128_KATS,
        AsconLegacyVariant::Ascon128a => ASCON128A_KATS,
        AsconLegacyVariant::Ascon80pq => ASCON80PQ_KATS,
    }
}

fn algo_name(engine: &AsconLegacyEngine) -> String {
    engine.to_string()
}

fn encrypt(variant: AsconLegacyVariant, plaintext: &[u8], aad: &[u8]) -> Vec<u8> {
    let key = key(variant);
    let nonce = decode_hex(NONCE);
    let params = AeadParamsRef::new(&key, &nonce, 16, &[]);
    let mut engine = AsconLegacyEngine::new(variant);
    engine.init(CipherDirection::Encrypt, &params).unwrap();
    engine.process_aad_bytes(aad).unwrap();

    let mut output = vec![0xa5; engine.output_len(plaintext.len()).unwrap()];
    let mut written = engine.process_bytes(plaintext, &mut output).unwrap();
    written += engine.do_final(&mut output[written..]).unwrap();
    output.truncate(written);
    output
}

fn decrypt(variant: AsconLegacyVariant, ciphertext: &[u8], aad: &[u8]) -> Vec<u8> {
    let key = key(variant);
    let nonce = decode_hex(NONCE);
    let params = AeadParamsRef::new(&key, &nonce, 16, &[]);
    let mut engine = AsconLegacyEngine::new(variant);
    engine.init(CipherDirection::Decrypt, &params).unwrap();
    engine.process_aad_bytes(aad).unwrap();

    let mut output = vec![0xa5; engine.output_len(ciphertext.len()).unwrap()];
    let mut written = engine.process_bytes(ciphertext, &mut output).unwrap();
    written += engine.do_final(&mut output[written..]).unwrap();
    output.truncate(written);
    output
}

#[test]
fn every_v12_variant_matches_its_official_vectors() {
    for variant in VARIANTS {
        for kat in kats(variant) {
            let plaintext = decode_hex(kat.plaintext);
            let aad = decode_hex(kat.aad);
            let expected = decode_hex(kat.ciphertext_and_tag);

            assert_eq!(encrypt(variant, &plaintext, &aad), expected);
            assert_eq!(decrypt(variant, &expected, &aad), plaintext);
        }
    }
}

#[test]
fn every_message_split_and_both_aad_paths_match_the_v12_vectors() {
    for variant in VARIANTS {
        let kat = kats(variant).last().unwrap();
        let plaintext = decode_hex(kat.plaintext);
        let aad = decode_hex(kat.aad);
        let expected = decode_hex(kat.ciphertext_and_tag);
        let key = key(variant);
        let nonce = decode_hex(NONCE);

        for split in 0..=plaintext.len() {
            let params = AeadParamsRef::new(&key, &nonce, 16, &aad);
            let mut engine = AsconLegacyEngine::new(variant);
            engine.init(CipherDirection::Encrypt, &params).unwrap();
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
            let params = AeadParamsRef::new(&key, &nonce, 16, &[]);
            let mut engine = AsconLegacyEngine::new(variant);
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
}

#[test]
fn wrong_key_sizes_modified_tags_and_short_ciphertexts_are_rejected() {
    let nonce = decode_hex(NONCE);
    let key_128 = decode_hex(KEY_128);
    let key_80pq = decode_hex(KEY_80PQ);
    let params_128 = AeadParamsRef::new(&key_128, &nonce, 16, &[]);
    let params_80pq = AeadParamsRef::new(&key_80pq, &nonce, 16, &[]);

    let mut engine = AsconLegacyEngine::new(AsconLegacyVariant::Ascon128);
    assert_eq!(
        engine.init(CipherDirection::Encrypt, &params_80pq),
        Err(AeadInitError::InvalidKeyLength {
            actual: KEY_BYTES_80PQ
        })
    );
    let mut engine = AsconLegacyEngine::new(AsconLegacyVariant::Ascon80pq);
    assert_eq!(
        engine.init(CipherDirection::Encrypt, &params_128),
        Err(AeadInitError::InvalidKeyLength {
            actual: KEY_BYTES_128
        })
    );

    for variant in VARIANTS {
        let kat = kats(variant).last().unwrap();
        let plaintext = decode_hex(kat.plaintext);
        let aad = decode_hex(kat.aad);
        let mut ciphertext = encrypt(variant, &plaintext, &aad);
        *ciphertext.last_mut().unwrap() ^= 1;

        let key = key(variant);
        let params = AeadParamsRef::new(&key, &nonce, 16, &[]);
        let mut engine = AsconLegacyEngine::new(variant);
        engine.init(CipherDirection::Decrypt, &params).unwrap();
        engine.process_aad_bytes(&aad).unwrap();
        let mut output = vec![0xa5; plaintext.len()];
        let written = engine.process_bytes(&ciphertext, &mut output).unwrap();
        assert_eq!(
            engine.do_final(&mut output[written..]),
            Err(AeadError::AuthenticationFailed)
        );
        assert_eq!(engine.mac(), None);

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
}

#[test]
fn each_variant_reports_its_metadata_and_enforces_the_state_rules() {
    let cases = [
        (
            AsconLegacyVariant::Ascon128,
            "Ascon-128 AEAD",
            KEY_BYTES_128,
            8,
        ),
        (
            AsconLegacyVariant::Ascon128a,
            "Ascon-128a AEAD",
            KEY_BYTES_128,
            16,
        ),
        (
            AsconLegacyVariant::Ascon80pq,
            "Ascon-80pq AEAD",
            KEY_BYTES_80PQ,
            8,
        ),
    ];

    for (variant, name, key_bytes, rate) in cases {
        let key = key(variant);
        let nonce = decode_hex(NONCE);
        let params = AeadParamsRef::new(&key, &nonce, 16, &[]);
        let mut engine = AsconLegacyEngine::new(variant);

        assert_eq!(engine.variant(), variant);
        assert_eq!(algo_name(&engine), name);
        assert_eq!(engine.key_bytes(), key_bytes);
        assert_eq!(engine.nonce_bytes(), NONCE_BYTES);
        assert_eq!(engine.tag_bytes(), TAG_BYTES);
        assert_eq!(engine.update_output_len(rate).unwrap(), rate);
        assert_eq!(engine.output_len(0).unwrap(), TAG_BYTES);
        assert_eq!(
            engine.process_bytes(&[], &mut []),
            Err(AeadError::NotInitialized)
        );

        engine.init(CipherDirection::Encrypt, &params).unwrap();
        let input = [0_u8; 16];
        assert_eq!(engine.update_output_len(rate - 1).unwrap(), 0);
        assert_eq!(engine.update_output_len(rate).unwrap(), rate);
        assert_eq!(
            engine.process_bytes(&input[..rate], &mut [0_u8; 7]),
            Err(AeadError::OutputTooShort {
                required: rate,
                available: 7,
            })
        );
        assert_eq!(
            engine.process_bytes(&input[..rate], &mut [0_u8; 16]),
            Ok(rate)
        );
        assert_eq!(engine.process_aad_bytes(&[0]), Err(AeadError::AadAfterData));

        let mut tag = [0_u8; TAG_BYTES];
        assert_eq!(engine.do_final(&mut tag), Ok(TAG_BYTES));
        assert_eq!(engine.mac(), Some(tag.as_slice()));
        assert_eq!(
            engine.process_bytes(&[], &mut []),
            Err(AeadError::AlreadyFinalized)
        );
    }
}

#[test]
fn v12_accepts_only_its_fixed_sixteen_byte_tag() {
    let key = decode_hex(KEY_128);
    let nonce = decode_hex(NONCE);
    let mut engine = AsconLegacyEngine::new(AsconLegacyVariant::Ascon128);
    for mac_size in [4, 12, 15, 17] {
        assert_eq!(
            engine.init(
                CipherDirection::Encrypt,
                &AeadParamsRef::new(&key, &nonce, mac_size, &[])
            ),
            Err(AeadInitError::InvalidMacSize { actual: mac_size })
        );
    }
}
