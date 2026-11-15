#![cfg(feature = "alloc")]

use tc_aead_cipher::{
    AeadCipher, AeadCipherInit, AeadInitError, AeadParamsRef, CcmBlockCipher, EaxBlockCipher,
    GcmBlockCipher, KccmBlockCipher, OcbBlockCipher, ParamsWithAeadOwned, ParamsWithAeadRef,
};
use tc_aes::AesEngine;
use tc_block_cipher::{CipherDirection, KeyFixed, KeyRef};
use tc_rc_cipher::{Rc2Engine, Rc2ParamsRef, Rc5ParamsOwned, Rc5ParamsRef, Rc564Engine};

const KEY: [u8; 16] = [0x42; 16];
const AAD: [u8; 16] = [0x5a; 16];
// Two whole blocks, as KCCM requires
const MESSAGE: [u8; 32] = *b"two blocks of sixteen bytes each";

fn run<M, P>(mode: &mut M, direction: CipherDirection, params: &P, input: &[u8]) -> Vec<u8>
where
    M: AeadCipher + AeadCipherInit<P>,
    <M as AeadCipher>::Error: core::fmt::Debug,
    <M as AeadCipherInit<P>>::Error: core::fmt::Debug,
    P: ?Sized,
{
    mode.init(direction, params).unwrap();
    let mut output = vec![0; mode.output_len(input.len()).unwrap()];
    let written = mode.process_bytes(input, &mut output).unwrap();
    let written = written + mode.do_final(&mut output[written..]).unwrap();
    output.truncate(written);
    output
}

// Seals MESSAGE with the AEAD parameters and with both new forms around the
// same key, each on a new mode so that no encryption repeats the nonce, and
// opens each result back
fn assert_same_as_aead_params<M>(name: &str, new: impl Fn() -> M, nonce: &[u8])
where
    M: AeadCipher
        + for<'a> AeadCipherInit<AeadParamsRef<'a>>
        + for<'a, 'k> AeadCipherInit<ParamsWithAeadRef<'a, KeyRef<'k>>>
        + AeadCipherInit<ParamsWithAeadOwned<KeyFixed<16>>>,
    <M as AeadCipher>::Error: core::fmt::Debug,
    for<'a> <M as AeadCipherInit<AeadParamsRef<'a>>>::Error: core::fmt::Debug,
    for<'a, 'k> <M as AeadCipherInit<ParamsWithAeadRef<'a, KeyRef<'k>>>>::Error: core::fmt::Debug,
    <M as AeadCipherInit<ParamsWithAeadOwned<KeyFixed<16>>>>::Error: core::fmt::Debug,
{
    let expected = run(
        &mut new(),
        CipherDirection::Encrypt,
        &AeadParamsRef::new(&KEY, nonce, 16, &AAD),
        &MESSAGE,
    );

    let key = KeyRef::new(&KEY);
    let borrowed = ParamsWithAeadRef::new(&key, nonce, 16, &AAD);
    assert_eq!(
        run(&mut new(), CipherDirection::Encrypt, &borrowed, &MESSAGE),
        expected,
        "{name}"
    );
    assert_eq!(
        run(&mut new(), CipherDirection::Decrypt, &borrowed, &expected),
        MESSAGE,
        "{name}"
    );

    let owned = ParamsWithAeadOwned::new(KeyFixed::new(KEY), nonce.to_vec(), 16, AAD.to_vec());
    assert_eq!(
        run(&mut new(), CipherDirection::Encrypt, &owned, &MESSAGE),
        expected,
        "{name}"
    );
    assert_eq!(
        run(&mut new(), CipherDirection::Decrypt, &owned, &expected),
        MESSAGE,
        "{name}"
    );
}

#[test]
fn every_mode_seals_a_wrapped_key_as_it_seals_the_aead_parameters_of_that_key() {
    assert_same_as_aead_params("GCM", || GcmBlockCipher::new(AesEngine::new()), &[0x24; 12]);
    assert_same_as_aead_params("CCM", || CcmBlockCipher::new(AesEngine::new()), &[0x24; 12]);
    assert_same_as_aead_params("EAX", || EaxBlockCipher::new(AesEngine::new()), &[0x24; 12]);
    assert_same_as_aead_params(
        "OCB",
        || OcbBlockCipher::new(AesEngine::new(), AesEngine::new()),
        &[0x24; 12],
    );
    assert_same_as_aead_params(
        "KCCM",
        || KccmBlockCipher::<_, 4>::new(AesEngine::new()),
        &[0x24; 16],
    );
}

#[test]
fn the_effective_key_bits_of_rc2_reach_the_cipher_under_eax() {
    let nonce = [0x24; 8];
    let mut eax = EaxBlockCipher::new(Rc2Engine::new());
    let default_bits = Rc2ParamsRef::new(&KEY);
    let forty_bits = Rc2ParamsRef::with_effective_key_bits(&KEY, 40);

    let full = run(
        &mut eax,
        CipherDirection::Encrypt,
        &ParamsWithAeadRef::new(&default_bits, &nonce, 8, &AAD),
        &MESSAGE,
    );
    let params = ParamsWithAeadRef::new(&forty_bits, &nonce, 8, &AAD);
    let weak = run(&mut eax, CipherDirection::Encrypt, &params, &MESSAGE);
    assert_ne!(weak, full);
    assert_eq!(
        run(&mut eax, CipherDirection::Decrypt, &params, &weak),
        MESSAGE
    );
}

#[test]
fn the_rounds_of_rc5_reach_the_cipher_under_gcm() {
    let nonce = [0x24; 12];
    let mut gcm = GcmBlockCipher::new(Rc564Engine::new());

    let default_rounds = run(
        &mut gcm,
        CipherDirection::Encrypt,
        &ParamsWithAeadRef::new(&Rc5ParamsRef::with_default_rounds(&KEY), &nonce, 16, &AAD),
        &MESSAGE,
    );
    let params = ParamsWithAeadOwned::new(
        Rc5ParamsOwned::new(KEY.to_vec(), 16),
        nonce.to_vec(),
        16,
        AAD.to_vec(),
    );
    let sixteen_rounds = run(&mut gcm, CipherDirection::Encrypt, &params, &MESSAGE);
    assert_ne!(sixteen_rounds, default_rounds);
    assert_eq!(
        run(&mut gcm, CipherDirection::Decrypt, &params, &sixteen_rounds),
        MESSAGE
    );
}

#[test]
fn encryption_refuses_a_repeated_key_and_nonce_given_through_the_wrapper() {
    let key = KeyRef::new(&KEY);
    let params = ParamsWithAeadRef::new(&key, &[0x24; 12], 16, &[]);
    let mut gcm = GcmBlockCipher::new(AesEngine::new());
    gcm.init(CipherDirection::Encrypt, &params).unwrap();
    assert!(matches!(
        gcm.init(CipherDirection::Encrypt, &params),
        Err(AeadInitError::NonceReuse)
    ));
    // Through the AEAD parameters of the same key, it is the same reuse
    assert!(matches!(
        gcm.init(
            CipherDirection::Encrypt,
            &AeadParamsRef::new(&KEY, &[0x24; 12], 16, &[])
        ),
        Err(AeadInitError::NonceReuse)
    ));
}

#[test]
fn debug_writes_the_inner_parameters_and_only_the_lengths_of_the_rest() {
    let borrowed = ParamsWithAeadRef::new("inner", &[0x24; 12], 16, &[1, 2, 3]);
    assert_eq!(
        format!("{borrowed:?}"),
        "ParamsWithAeadRef { params: \"inner\", nonce_len: 12, initial_aad_len: 3, mac_size: 16 }"
    );
    let owned = ParamsWithAeadOwned::new(7u8, vec![0x24; 12], 16, vec![1, 2, 3]);
    assert_eq!(
        format!("{owned:?}"),
        "ParamsWithAeadOwned { params: 7, nonce_len: 12, initial_aad_len: 3, mac_size: 16 }"
    );
}
