#[cfg(feature = "alloc")]
mod aead_params_owned;
mod aead_params_ref;

#[cfg(feature = "alloc")]
pub use aead_params_owned::AeadParamsOwned;
pub use aead_params_ref::AeadParamsRef;
