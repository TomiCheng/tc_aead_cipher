#![cfg(feature = "alloc")]

use tc_aead_cipher::{
    AeadCipher, AeadCipherInit, AeadError, AeadInitError, AeadParamsRef, KccmBlockCipher,
};
use tc_block_cipher::CipherDirection;
use tc_dstu7624::{Dstu7624Engine128, Dstu7624Engine256, Dstu7624Engine512};

fn decode(hex: &str) -> Vec<u8> {
    hex.as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let n = |value| match value {
                b'0'..=b'9' => value - b'0',
                b'a'..=b'f' => value - b'a' + 10,
                b'A'..=b'F' => value - b'A' + 10,
                _ => panic!("invalid hexadecimal digit"),
            };
            (n(pair[0]) << 4) | n(pair[1])
        })
        .collect()
}

struct Vector<'a> {
    key: &'a str,
    nonce: &'a str,
    aad: &'a str,
    plaintext: &'a str,
    expected_mac: &'a str,
    expected: &'a str,
}

fn check<C, const NB: usize>(cipher: C, decrypt_cipher: C, vector: Vector<'_>)
where
    C: tc_block_cipher::BlockCipher<Error = tc_block_cipher::BlockError>,
    for<'a> C:
        tc_block_cipher::BlockCipherInit<AeadParamsRef<'a>, Error = tc_block_cipher::InitError>,
{
    let key = decode(vector.key);
    let nonce = decode(vector.nonce);
    let aad = decode(vector.aad);
    let plaintext = decode(vector.plaintext);
    let expected_mac = decode(vector.expected_mac);
    let expected = decode(vector.expected);
    let params = AeadParamsRef::new(&key, &nonce, expected_mac.len(), &aad);

    let mut encryptor = KccmBlockCipher::<_, NB>::with_nb(cipher);
    encryptor.init(CipherDirection::Encrypt, &params).unwrap();
    encryptor.process_bytes(&plaintext, &mut []).unwrap();
    let mut ciphertext = vec![0u8; expected.len()];
    assert_eq!(encryptor.do_final(&mut ciphertext), Ok(expected.len()));
    assert_eq!(ciphertext, expected);
    assert_eq!(encryptor.mac(), Some(expected_mac.as_slice()));

    let mut decryptor = KccmBlockCipher::<_, NB>::with_nb(decrypt_cipher);
    decryptor.init(CipherDirection::Decrypt, &params).unwrap();
    decryptor.process_bytes(&ciphertext, &mut []).unwrap();
    let mut recovered = vec![0u8; plaintext.len()];
    assert_eq!(decryptor.do_final(&mut recovered), Ok(plaintext.len()));
    assert_eq!(recovered, plaintext);
}

#[test]
fn encryption_and_decryption_match_the_bouncy_castle_dstu7624_vectors() {
    check::<_, 4>(
        Dstu7624Engine128::new(),
        Dstu7624Engine128::new(),
        Vector {
            key: "000102030405060708090a0b0c0d0e0f",
            nonce: "101112131415161718191a1b1c1d1e1f",
            aad: "202122232425262728292a2b2c2d2e2f",
            plaintext: "303132333435363738393a3b3c3d3e3f",
            expected_mac: "26a936173a4dc9160d6e3fda3a974060",
            expected: "b91a7b8790bbcfcfe65d04e5538e98e2704454c9dd39adace0b19d03f6aab07e",
        },
    );
    check::<_, 6>(
        Dstu7624Engine256::new(),
        Dstu7624Engine256::new(),
        Vector {
            key: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f",
            nonce: "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f",
            aad: "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f",
            plaintext: "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf",
            expected_mac: "924fa0326824355595c98028e84d86279cea9135fab35f22054ae3203e68ae46",
            expected: "3ebdb4584b5169a26fbeba0295b4223f58d5d8a031f2950a1d7764fab97ba058e9e2dab90ff0c519aa88435155a71b7b53bb100f5d20affac0552f5f2813dee8dd3653491737b9615a5ccd83db32f1e479bf227c050325bbbff60bca9558d7fe",
        },
    );
    check::<_, 8>(
        Dstu7624Engine512::new(),
        Dstu7624Engine512::new(),
        Vector {
            key: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f",
            nonce: "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f",
            aad: "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf",
            plaintext: "c0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
            expected_mac: "d4155ec3d888c8d32fe184ac260fd60f567705e1df362a6f1f9c287156aa96d91bc4c56f9709e72f3d79cf0a9ac8bdc2ba836be50e823ab50fb1b39080390923",
            expected: "220642d7277d104788cf97b10210984f506435512f7bf153c5cdabfecc10afb4a2e2fc51f616af80ffdd0607fad4f542b8ef0667717ce3eaaa8fbc303ce76c99bd8f80ce149143c04fc2490272a31b029ddada82f055fe4abef452a7d438b21e59c1d8b3dd4606bad66a6f36300ef3ce0e5f3bb59f11416e80b7fc5a8e8b057a",
        },
    );
}

#[test]
fn nonce_reuse_partial_blocks_and_tampering_are_rejected_without_releasing_plaintext() {
    let key = [0x11u8; 16];
    let nonce = [0x22u8; 16];
    let aad = [0x33u8; 16];
    let params = AeadParamsRef::new(&key, &nonce, 16, &aad);
    let mut encryptor = KccmBlockCipher::new(Dstu7624Engine128::new());
    encryptor.init(CipherDirection::Encrypt, &params).unwrap();
    encryptor.process_bytes(&[0x44; 16], &mut []).unwrap();
    let mut ciphertext = [0u8; 32];
    encryptor.do_final(&mut ciphertext).unwrap();
    assert!(matches!(
        encryptor.init(CipherDirection::Encrypt, &params),
        Err(AeadInitError::NonceReuse)
    ));

    let mut partial = KccmBlockCipher::new(Dstu7624Engine128::new());
    partial.init(CipherDirection::Encrypt, &params).unwrap();
    partial.process_bytes(&[0u8; 15], &mut []).unwrap();
    assert!(matches!(
        partial.do_final(&mut [0u8; 31]),
        Err(AeadError::InputNotBlockAligned {
            block_size: 16,
            actual: 15,
        })
    ));

    ciphertext[0] ^= 1;
    let mut decryptor = KccmBlockCipher::new(Dstu7624Engine128::new());
    decryptor.init(CipherDirection::Decrypt, &params).unwrap();
    decryptor.process_bytes(&ciphertext, &mut []).unwrap();
    let mut output = [0xa5u8; 16];
    assert_eq!(
        decryptor.do_final(&mut output),
        Err(AeadError::AuthenticationFailed)
    );
    assert_eq!(output, [0xa5; 16]);
}
