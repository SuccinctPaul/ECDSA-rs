use ark_bn254::{Fr, G1Affine};
use ark_ec::{AffineRepr, CurveGroup};
use ark_std::{rand::Rng, UniformRand};

pub struct PrivateKey {
    pub(crate) scalar: Fr,
}

pub struct PublicKey {
    pub(crate) point: G1Affine,
}

impl PrivateKey {
    pub fn rand<R: Rng>(rng: &mut R) -> Self {
        let scalar = Fr::rand(rng);
        Self { scalar }
    }
}

impl From<&PrivateKey> for PublicKey {
    fn from(value: &PrivateKey) -> Self {
        let point = G1Affine::generator() * &value.scalar;
        Self {
            point: point.into_affine(),
        }
    }
}
