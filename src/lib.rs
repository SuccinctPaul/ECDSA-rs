// #![deny(unused_imports)]
pub mod ecdsa;
pub mod key;
pub mod transcript;
mod utils;

pub struct Signature {
    pub(crate) s: ark_bn254::Fr,
    pub(crate) r: ark_bn254::Fr,
}
