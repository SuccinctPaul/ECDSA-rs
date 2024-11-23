use ark_bn254::{Fq, Fr, G1Affine};
use ark_ff::{BigInteger, PrimeField};
use num_bigint::BigUint;
use num_traits::{FromBytes, Num};
use std::ops::{Div, Rem};

// convert filed and point to bytes.
pub fn to_bytes(p: G1Affine, f: Fr) -> Vec<u8> {
    vec![
        p.x.into_bigint().to_bytes_be(),
        p.y.into_bigint().to_bytes_be(),
        f.into_bigint().to_bytes_be(),
    ]
    .concat()
}

pub fn point_to_bytes(p: &G1Affine) -> Vec<u8> {
    vec![
        p.x.into_bigint().to_bytes_be(),
        p.y.into_bigint().to_bytes_be(),
    ]
    .concat()
}

pub fn fr_to_bytes(f: Fr) -> Vec<u8> {
    f.into_bigint().to_bytes_be()
}

pub fn fq_to_fr(fq: Fq) -> Fr {
    // let fq_biguint = BigUint::from_be_bytes(&fq.into_bigint().to_bytes_be());
    // let fr_module = BigUint::from_be_bytes(&Fr::MODULUS.to_bytes_be());
    // let fr_biguint = fq_biguint % fr_module;
    // Fr::from_be_bytes_mod_order(&fr_biguint.to_bytes_be())
    // Should as same sa above.
    Fr::from_be_bytes_mod_order(&fq.into_bigint().to_bytes_be())
}
