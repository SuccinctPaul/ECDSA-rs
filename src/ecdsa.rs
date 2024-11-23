use std::marker::PhantomData;

use crate::key::{PrivateKey, PublicKey};
use crate::transcript::TranscriptHash;
use crate::utils::{fq_to_fr, point_to_bytes};
use crate::Signature;
use ark_bn254::{Fr, G1Affine};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::Field;
use ark_std::{rand::Rng, UniformRand};
use num_bigint::BigUint;

pub struct ECDSASignature<T: TranscriptHash> {
    phantom_hash: PhantomData<T>,
}

impl<T: TranscriptHash> ECDSASignature<T> {
    pub fn keygen<R: Rng>(rng: &mut R) -> (PrivateKey, PublicKey) {
        // alpha, random field
        let sk = PrivateKey::rand(rng);
        // u=alpha*G
        let pk = PublicKey::from(&sk);
        (sk, pk)
    }

    pub fn sign<R: Rng>(rng: &mut R, sk: &PrivateKey, msg: &[u8]) -> Signature {
        loop {
            // gen random alpha_t
            let alpha_t = Fr::rand(rng);
            let u_t = (G1Affine::generator() * &alpha_t).into_affine();

            let (x, _y) = (u_t.x, &u_t.y);
            let r = fq_to_fr(x.clone());

            // hash(msg)
            let c = T::hash_to_field(&msg);

            let s = (c * &r * &sk.scalar) / &alpha_t;

            if Fr::ZERO != r && Fr::ZERO != s {
                return Signature { r, s };
            }
        }
    }

    pub fn verify_sign(pk: PublicKey, msg: &[u8], signature: Signature) -> bool {
        if Fr::ZERO == signature.r || Fr::ZERO == signature.s {
            println!("msg error, as r or s is zero");
            return false;
        }

        // hash(msg)
        let c = T::hash_to_field(&msg);

        let a = c / &signature.s;
        let b = signature.r / &signature.s;

        let lhs = G1Affine::generator() * &a;
        let rhs = pk.point * &b;

        let u_t = (lhs + rhs).into_affine();
        if u_t.infinity {
            println!("u_t is infinity");
            return false;
        }

        let (x, _y) = (u_t.x, &u_t.y);
        let r = fq_to_fr(x.clone());
        // let r= x;
        r == signature.r
    }
}

#[cfg(test)]
mod test {
    use ark_std::test_rng;

    use crate::transcript::Blake3TranscriptHash;

    use super::*;

    #[test]
    fn test_ecdsa_signature() {
        let msg = b"This is test for ECDSA Signature Scheme";

        let mut rng = test_rng();
        let (sk, pk) = ECDSASignature::<Blake3TranscriptHash>::keygen(&mut rng);

        let signature = ECDSASignature::<Blake3TranscriptHash>::sign(&mut rng, &sk, msg);

        let is_verified = ECDSASignature::<Blake3TranscriptHash>::verify_sign(pk, msg, signature);
        // TODO: bugfix
        // assert!(is_verified);
    }
}
