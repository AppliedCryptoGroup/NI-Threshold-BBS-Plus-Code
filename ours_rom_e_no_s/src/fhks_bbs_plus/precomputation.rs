use crate::helpers::secret_sharing;
use ff_zeroize::Field;
use pairing_plus::bls12_381::Fr;

pub struct PerPartyPrecomputations {
    pub index: usize,
    pub sk_share: Fr,
    pub pre_signatures: Vec<PerPartyPreSignature>,
}

pub struct PerPartyPreSignature {
    pub a_share: Fr,
    pub ask_term_own: Fr,
    pub ask_terms_a: Vec<Fr>,
    pub ask_terms_sk: Vec<Fr>,
}

pub struct LivePreSignature {
    pub a_share: Fr,
    pub beta_share: Fr,
}

impl LivePreSignature {
    pub fn from_presignature(
        own_index: usize,
        indices: &Vec<usize>,
        pre_signature: &PerPartyPreSignature,
    ) -> Self {
        let lagrange_coefficients = secret_sharing::get_0_lagrange_coefficient_set_fr(&indices);

        Self::from_presignature_with_coefficients(
            own_index,
            indices,
            pre_signature,
            &lagrange_coefficients,
        )
    }

    pub fn from_presignature_with_coefficients(
        own_index: usize,
        indices: &Vec<usize>,
        pre_signature: &PerPartyPreSignature,
        lagrange_coefficients: &Vec<Fr>,
    ) -> Self {
        let mut ask_share = Fr::zero();
        let mut tmp_ask_own_coefficient = pre_signature.ask_term_own;

        let mut ind_i = 0;
        for (ind_j, &el_j) in indices.iter().enumerate() {
            if el_j != own_index {
                let mut tmp = pre_signature.ask_terms_a[el_j - 1];
                tmp.mul_assign(&lagrange_coefficients[ind_j]);

                ask_share.add_assign(&tmp);

                tmp_ask_own_coefficient.add_assign(&pre_signature.ask_terms_sk[el_j - 1]);
            } else {
                ind_i = ind_j;
            }
        }

        tmp_ask_own_coefficient.mul_assign(&lagrange_coefficients[ind_i]);
        ask_share.add_assign(&tmp_ask_own_coefficient);

        LivePreSignature {
            a_share: pre_signature.a_share,
            beta_share: ask_share,
        }
    }
}
