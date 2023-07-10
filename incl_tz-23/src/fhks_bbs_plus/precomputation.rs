use crate::helpers::secret_sharing;
use ff_zeroize::Field;
use pairing_plus::bls12_381::Fr;

pub struct PerPartyPrecomputations {
    pub index: usize, //Position at which sk-polynomial for own secret key share is evaluated
    pub sk_share: Fr, //sk_i
    pub pre_signatures: Vec<PerPartyPreSignature>,
}

pub struct PerPartyPreSignature {
    pub a_share: Fr,           //a^k_i for k in [t]
    pub e_share: Fr,           //e^k_i for k in [t]
    pub ae_term_own: Fr,       //a^k_i * e^k_i for k in [t]            //Might not be necessary
    pub ask_term_own: Fr,      // a^k_i * sk_i for k in [t]            //Might not be necessary
    pub ae_terms_a: Vec<Fr>,   //share of a^k_i * e^k_j for k in [t], j in [n] (j can also be i)
    pub ae_terms_e: Vec<Fr>, //share of a^k_j * e^k_i for k in [t], j in [n] (j can also be i -- this time other share)
    pub ask_terms_a: Vec<Fr>, //share of a^k_i * sk_j for k in [t], j in [n] (j can also be i)
    pub ask_terms_sk: Vec<Fr>, //share of  a^k_j * sk_i for k in [t], j in [n] (j can also be i -- this time other share)
}

pub struct LivePreSignature {
    pub a_share: Fr,
    pub e_share: Fr,
    pub delta_share: Fr
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
        //For ae-shares start with the multiplication of both own shares
        let mut ae_share = pre_signature.ae_term_own;

        //ASK-Share is split into a part which is to multiplied with own-index-lagrange and one which directly gets other-index-lagrange
        let mut ask_share = Fr::zero();
        let mut tmp_ask_own_coefficient = pre_signature.ask_term_own; //Own-index-lagrange starts with multiplication of both own shares

        let mut ind_i = 0;
        for (ind_j, &el_j) in indices.iter().enumerate() {
            if el_j != own_index {
                //Add shares of a_i * e_j (ae_terms_a), a_j * e_i (ae_terms_a)
                ae_share.add_assign(&pre_signature.ae_terms_a[el_j - 1]);
                ae_share.add_assign(&pre_signature.ae_terms_e[el_j - 1]);

                //Share of  a_i * sk_j (using j's lagrange coefficient) is added to share_of_ask
                let mut tmp = pre_signature.ask_terms_a[el_j - 1];
                tmp.mul_assign(&lagrange_coefficients[ind_j]);

                ask_share.add_assign(&tmp);

                //Share of a_j * sk_i (using i's lagrange coefficeint) is added to tmp_ask_own_lagrange (coefficient is applied later for all at once)
                tmp_ask_own_coefficient.add_assign(&pre_signature.ask_terms_sk[el_j - 1]);
            } else {
                ind_i = ind_j;
            }
        }

        //Apply i's lagrange coefficient to sum of share of all cross-terms incoperating sk_i and add result to share of ask
        tmp_ask_own_coefficient.mul_assign(&lagrange_coefficients[ind_i]);
        ask_share.add_assign(&tmp_ask_own_coefficient);

        //Compute delta_share
        let mut delta_share = ae_share;
        delta_share.add_assign(&ask_share);

        LivePreSignature {
            a_share: pre_signature.a_share,
            e_share: pre_signature.e_share,
            delta_share: delta_share
        }
    }
}
