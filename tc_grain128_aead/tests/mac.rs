use core::fmt::Debug;

use tc_aead_cipher::{AeadCipher, AeadCipherInit, AeadParamsRef};
use tc_block_cipher::CipherDirection;
use tc_grain128_aead::FixedGrain128AeadEngine;

fn assert_mac_is_the_appended_tag<A>(mut engine: A, key: &[u8], nonce: &[u8], mac_size: usize)
where
    for<'a> A: AeadCipher + AeadCipherInit<AeadParamsRef<'a>>,
    for<'a> <A as AeadCipherInit<AeadParamsRef<'a>>>::Error: Debug,
    <A as AeadCipher>::Error: Debug,
{
    let params = AeadParamsRef::new(key, nonce, mac_size, b"associated data!");
    let plaintext = [0x44u8; 32];

    engine.init(CipherDirection::Encrypt, &params).unwrap();
    let mut ciphertext = vec![0u8; engine.output_len(plaintext.len()).unwrap()];
    let mut written = engine.process_bytes(&plaintext, &mut ciphertext).unwrap();
    written += engine.do_final(&mut ciphertext[written..]).unwrap();
    let tag = &ciphertext[written - mac_size..written];
    assert_eq!(engine.mac(), Some(tag));

    engine.init(CipherDirection::Decrypt, &params).unwrap();
    let mut recovered = vec![0u8; engine.output_len(written).unwrap()];
    let mut recovered_len = engine
        .process_bytes(&ciphertext[..written], &mut recovered)
        .unwrap();
    recovered_len += engine.do_final(&mut recovered[recovered_len..]).unwrap();
    assert_eq!(recovered[..recovered_len], plaintext);
    assert_eq!(engine.mac(), Some(tag));
}

#[test]
fn every_engine_reports_the_tag_that_ends_the_ciphertext_as_its_mac() {
    let key = [0x11; 16];
    assert_mac_is_the_appended_tag(FixedGrain128AeadEngine::<16>::new(), &key, &[1; 12], 8);
    #[cfg(feature = "alloc")]
    assert_mac_is_the_appended_tag(
        tc_grain128_aead::Grain128AeadEngine::new(),
        &key,
        &[1; 12],
        8,
    );
}
