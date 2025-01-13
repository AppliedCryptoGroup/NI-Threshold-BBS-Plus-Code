use ff_zeroize::Field;
use pairing_plus::bls12_381::Bls12;
use pairing_plus::bls12_381::Fr;
use pairing_plus::bls12_381::G1;
use pairing_plus::bls12_381::G2;
use pairing_plus::CurveProjective;
use pairing_plus::Engine;

use super::keys::PublicKey;
use super::partial_threshold_signature::PartialThresholdSignature;

pub struct ThresholdSignature {
    pub capital_a: G1,
    pub e: Fr,
    pub s: Fr,
}

impl ThresholdSignature {
    pub fn from_partial_signatures(partial_signatures: &Vec<PartialThresholdSignature>) -> Self {
        let mut delta = Fr::zero();
        let mut e = partial_signatures[0].e;
        let mut s = Fr::zero();
        let mut capital_a = G1::zero();

        for partial_signature in partial_signatures {
            delta.add_assign(&partial_signature.delta_share);
            s.add_assign(&partial_signature.s_share);
            capital_a.add_assign(&partial_signature.capital_a_share);
        }

        let epsilon = delta.inverse().unwrap();
        capital_a.mul_assign(epsilon);

        Self {
            capital_a: capital_a,
            e: e,
            s: s,
        }
    }

    pub fn from_secret_key(pk: &PublicKey, sk: Fr, e: Fr, s: Fr, messages: &Vec<Fr>) -> Self {
        let mut h0s = pk.h0;
        h0s.mul_assign(s);
        let mut capital_a = G1::one();
        capital_a.add_assign(&h0s);
        for i in 0..(messages.len()) {
            let mut tmp = pk.h[i];
            tmp.mul_assign(messages[i]);
            capital_a.add_assign(&tmp);
        }

        let mut ske = sk;
        ske.add_assign(&e);
        let expo = ske.inverse().unwrap();

        capital_a.mul_assign(expo);

        ThresholdSignature {
            capital_a: capital_a,
            e: e,
            s: s,
        }
    }

    pub fn verify(&self, messages: &Vec<Fr>, pk: &PublicKey) -> bool {
        let mut h0s = pk.h0;
        h0s.mul_assign(self.s);
        let mut verification_basis = G1::one();
        verification_basis.add_assign(&h0s);
        for i in 0..(messages.len()) {
            let mut tmp = pk.h[i];
            tmp.mul_assign(messages[i]);
            verification_basis.add_assign(&tmp);
        }

        let mut u = G2::one();
        u.mul_assign(self.e);
        u.add_assign(&pk.w);

        let t1 = Bls12::pairing(self.capital_a, u);

        let t2 = Bls12::pairing(verification_basis, G2::one());

        return t1.eq(&t2);
    }
}
