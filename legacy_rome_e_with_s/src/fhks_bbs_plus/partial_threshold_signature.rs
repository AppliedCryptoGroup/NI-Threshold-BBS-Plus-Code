use sha2::Sha256;
use pairing_plus::hash_to_field::hash_to_field;
use pairing_plus::hash_to_field::ExpandMsgXmd;
use ff_zeroize::Field;
use crate::fhks_bbs_plus::keys::PublicKey;
use crate::fhks_bbs_plus::precomputation::LivePreSignature;
use pairing_plus::bls12_381::Fr;
use pairing_plus::bls12_381::G1;
use pairing_plus::CurveProjective;

pub struct PartialThresholdSignature {
    pub capital_a_share: G1,
    pub delta_share: Fr,
    pub e: Fr,
    pub s_share: Fr,
}

impl PartialThresholdSignature {
    pub fn new(messages: &Vec<Fr>, pk: &PublicKey, pre_signature: &LivePreSignature, nonce: String) -> Self {
        let mut basis = G1::one();
        for i in 0..(pk.h.len()) {
            let mut tmp = pk.h[i];
            tmp.mul_assign(messages[i]);
            basis.add_assign(&tmp);
        }

        let mut capital_a_share = basis;
        capital_a_share.mul_assign(pre_signature.a_share);
        let mut tmp = pk.h0;
        tmp.mul_assign(pre_signature.alpha_share);
        capital_a_share.add_assign(&tmp);

        let e = hash_to_field::<Fr, ExpandMsgXmd<Sha256>>(nonce.as_bytes(), b"asdfqwerzxcv", 1)[0];
        let mut ea = e;
        ea.mul_assign(&pre_signature.a_share);

        let mut delta_share = pre_signature.delta_share;
        delta_share.add_assign(&ea); 

        Self {
            capital_a_share: capital_a_share,
            delta_share: delta_share,
            e: e,
            s_share: pre_signature.s_share,
        }
    }
}
