use tc_aead_cipher::{AeadCipher, AeadCipherInit, AeadError, AeadParamsRef, GcmBlockCipher};
use tc_aes::AesEngine;
use tc_block_cipher::CipherDirection;

#[test]
fn aes_gcm_authenticates_a_multiblock_message_and_rejects_a_modified_tag() {
    // 固定 nonce 僅供測試；正式使用時，同一把 key 的每次加密必須使用不同 nonce。
    let key = [0x42; 32];
    let nonce = [0x24; 12];
    let aad = b"content-type: application/octet-stream";
    let plaintext = b"An authenticated message spanning several AES blocks.";
    let tag_len = 16;
    let params = AeadParamsRef::new(&key, &nonce, tag_len, aad);

    let mut encryptor = GcmBlockCipher::new(AesEngine::new());
    encryptor.init(CipherDirection::Encrypt, &params).unwrap();
    let mut ciphertext = vec![0; encryptor.output_len(plaintext.len()).unwrap()];
    let written = encryptor.process_bytes(plaintext, &mut ciphertext).unwrap();
    let written = written + encryptor.do_final(&mut ciphertext[written..]).unwrap();
    assert_eq!(written, plaintext.len() + tag_len);
    assert_eq!(written, ciphertext.len());
    assert_eq!(encryptor.mac(), Some(&ciphertext[plaintext.len()..]));

    let mut decryptor = GcmBlockCipher::new(AesEngine::new());
    decryptor.init(CipherDirection::Decrypt, &params).unwrap();
    let mut recovered = vec![0; decryptor.output_len(ciphertext.len()).unwrap()];
    let written = decryptor
        .process_bytes(&ciphertext, &mut recovered)
        .unwrap();
    let written = written + decryptor.do_final(&mut recovered[written..]).unwrap();
    // 只有 do_final 成功後，才能將解密輸出當成已驗證的明文使用。
    assert_eq!(written, plaintext.len());
    assert_eq!(recovered.as_slice(), plaintext);

    *ciphertext.last_mut().unwrap() ^= 1;
    decryptor.init(CipherDirection::Decrypt, &params).unwrap();
    let mut unauthenticated = vec![0; plaintext.len()];
    let written = decryptor
        .process_bytes(&ciphertext, &mut unauthenticated)
        .unwrap();
    assert_eq!(
        decryptor.do_final(&mut unauthenticated[written..]),
        Err(AeadError::AuthenticationFailed)
    );
    // process_bytes 可能已輸出部分明文；驗證失敗時整份輸出都必須丟棄。
    drop(unauthenticated);
    assert_eq!(decryptor.mac(), None);
}
