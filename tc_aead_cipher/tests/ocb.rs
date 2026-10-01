#![cfg(feature = "alloc")]

use tc_aead_cipher::{AeadCipher, AeadCipherInit, AeadInitError, AeadParamsRef, OcbBlockCipher};
use tc_aes::AesEngine;
use tc_block_cipher::CipherDirection;

fn decode(hex: &str) -> Vec<u8> {
    hex.as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let nibble = |value| match value {
                b'0'..=b'9' => value - b'0',
                b'a'..=b'f' => value - b'a' + 10,
                b'A'..=b'F' => value - b'A' + 10,
                _ => panic!("invalid hexadecimal digit"),
            };
            (nibble(pair[0]) << 4) | nibble(pair[1])
        })
        .collect()
}

fn check(nonce: &str, aad: &str, plaintext: &str, expected: &str, mac_size: usize) {
    let key = decode("000102030405060708090a0b0c0d0e0f");
    let nonce = decode(nonce);
    let aad = decode(aad);
    let plaintext = decode(plaintext);
    let expected = decode(expected);
    let params = AeadParamsRef::new(&key, &nonce, mac_size, &aad);

    let mut encryptor = OcbBlockCipher::new(AesEngine::new(), AesEngine::new());
    encryptor.init(CipherDirection::Encrypt, &params).unwrap();
    encryptor.process_bytes(&plaintext, &mut []).unwrap();
    let mut ciphertext = vec![0u8; expected.len()];
    assert_eq!(encryptor.do_final(&mut ciphertext), Ok(expected.len()));
    assert_eq!(ciphertext, expected);
    assert_eq!(encryptor.mac(), Some(&expected[plaintext.len()..]));

    let mut decryptor = OcbBlockCipher::new(AesEngine::new(), AesEngine::new());
    decryptor.init(CipherDirection::Decrypt, &params).unwrap();
    decryptor.process_bytes(&ciphertext, &mut []).unwrap();
    let mut recovered = vec![0u8; plaintext.len()];
    assert_eq!(decryptor.do_final(&mut recovered), Ok(plaintext.len()));
    assert_eq!(recovered, plaintext);
}

#[test]
fn encryption_and_decryption_match_the_rfc_7253_vectors() {
    check(
        "bbaa99887766554433221100",
        "",
        "",
        "785407bfffc8ad9edcc5520ac9111ee6",
        16,
    );
    check(
        "bbaa99887766554433221101",
        "0001020304050607",
        "0001020304050607",
        "6820b3657b6f615a5725bda0d3b4eb3a257c9af1f8f03009",
        16,
    );
    check(
        "bbaa99887766554433221104",
        "000102030405060708090a0b0c0d0e0f",
        "000102030405060708090a0b0c0d0e0f",
        "571d535b60b277188be5147170a9a22c3ad7a4ff3835b8c5701c1ccec8fc3358",
        16,
    );
    check(
        "bbaa99887766554433221107",
        "000102030405060708090a0b0c0d0e0f1011121314151617",
        "000102030405060708090a0b0c0d0e0f1011121314151617",
        "1ca2207308c87c010756104d8840ce1952f09673a448a122c92c62241051f57356d7f3c90bb0e07f",
        16,
    );
}

#[test]
fn nonce_reuse_and_tampering_are_rejected_without_releasing_plaintext() {
    let key = [0u8; 16];
    let nonce = [1u8; 12];
    let params = AeadParamsRef::new(&key, &nonce, 12, b"aad");
    let mut encryptor = OcbBlockCipher::new(AesEngine::new(), AesEngine::new());
    encryptor.init(CipherDirection::Encrypt, &params).unwrap();
    encryptor.process_bytes(b"message", &mut []).unwrap();
    let mut ciphertext = [0u8; 19];
    encryptor.do_final(&mut ciphertext).unwrap();
    assert!(matches!(
        encryptor.init(CipherDirection::Encrypt, &params),
        Err(AeadInitError::NonceReuse)
    ));
    ciphertext[0] ^= 1;

    let mut decryptor = OcbBlockCipher::new(AesEngine::new(), AesEngine::new());
    decryptor.init(CipherDirection::Decrypt, &params).unwrap();
    decryptor.process_bytes(&ciphertext, &mut []).unwrap();
    let mut output = [0xa5u8; 7];
    assert!(decryptor.do_final(&mut output).is_err());
    assert_eq!(output, [0xa5; 7]);
}
