use crate::fhks_bbs_plus::keys::PublicKey;
use crate::fhks_bbs_plus::precomputation::LivePreSignature;
use pairing_plus::bls12_381::Fr;
use pairing_plus::bls12_381::G1;
use pairing_plus::CurveProjective;

pub struct PartialThresholdSignature {
    pub capital_a_share: G1,
    pub delta_share: Fr,
    pub e_share: Fr
}

impl PartialThresholdSignature {
    pub fn new(messages: &Vec<Fr>, pk: &PublicKey, pre_signature: &LivePreSignature) -> Self {
        //message-dependent term
        let mut basis = G1::one();
        for i in 0..(pk.h.len()) {
            let mut tmp = pk.h[i];
            tmp.mul_assign(messages[i]);
            basis.add_assign(&tmp);
        }

        //Share of A
        let mut capital_a_share = basis;
        capital_a_share.mul_assign(pre_signature.a_share);

        Self {
            capital_a_share: capital_a_share,
            delta_share: pre_signature.delta_share,
            e_share: pre_signature.e_share
        }
    }
}
