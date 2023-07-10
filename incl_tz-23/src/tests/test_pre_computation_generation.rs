use crate::helpers::secret_sharing::{self, get_0_lagrange_coefficient_fr};
use crate::precomputation_mockup::precomputation_generation::create_pp_precomputation_from_all_v_ole_evaluations;
use crate::precomputation_mockup::precomputation_generation::generate_pcf_pcg_output;
use crate::{
    fhks_bbs_plus::precomputation::PerPartyPrecomputations,
    helpers::secret_sharing::get_0_lagrange_coefficient_set_fr,
};
use ff_zeroize::Field;
use pairing_plus::bls12_381::Fr;

pub fn test_all_precomputation_generation() {
    let seed_pre = [
        0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06, 0xbc,
        0xe5,
    ];
    let t = 3; //Security threshold (t-ouf-of-n)
    let n = 6; //Number of servers
    let k = 3; //Presignatures to create
    let indices = vec![vec![1, 3, 5], vec![1, 5, 2], vec![2, 4, 5]];

    let (sk, sk_shares, a_shares, e_shares, ae_terms, ask_terms) =
        generate_pcf_pcg_output(seed_pre, t, n, k);

    let per_party_precomputation = create_pp_precomputation_from_all_v_ole_evaluations(
        k, n, &sk_shares, &a_shares, &e_shares, &ae_terms, &ask_terms,
    );

    test_pcf_pcg_output_ae_as_ask(
        k, &indices, sk, &a_shares, &e_shares, &ae_terms, &ask_terms,
    );

    for i_k in 0..k {
        test_interpolation_for_sk(sk, &sk_shares, &indices[i_k]);
    }

    test_per_party_precomputations_without_coefficients(
        k,
        &indices,
        &per_party_precomputation,
        sk,
        &a_shares,
        &e_shares,
    );
}

pub fn test_pcf_pcg_output_ae_as_ask(
    k: usize,
    indices: &Vec<Vec<usize>>,
    sk: Fr,
    a_shares: &Vec<Vec<Fr>>,
    e_shares: &Vec<Vec<Fr>>,
    ae_terms: &Vec<Vec<Vec<(Fr, Fr)>>>,
    ask_terms: &Vec<Vec<Vec<(Fr, Fr)>>>,
) {
    for i_k in 0..k {
        let mut a = Fr::zero();
        let mut e = Fr::zero();
        let mut ae_direct = Fr::one();
        let mut as_direct = Fr::one();
        let mut ask_direct = Fr::one();
        let mut ae_indirect = Fr::zero();
        let mut ask_indirect = Fr::zero();

        for i_n in &indices[i_k] {
            a.add_assign(&a_shares[i_k][i_n - 1]);
            e.add_assign(&e_shares[i_k][i_n - 1]);
        }

        ae_direct.mul_assign(&a);
        ae_direct.mul_assign(&e);

        ask_direct.mul_assign(&a);
        ask_direct.mul_assign(&sk);

        for i_n in &indices[i_k] {
            for j_n in &indices[i_k] {
                let mut tmp_ae = Fr::zero();
                let mut tmp_ask = Fr::zero();
                tmp_ae.add_assign(&ae_terms[i_k][i_n - 1][j_n - 1].0);
                tmp_ae.add_assign(&ae_terms[i_k][i_n - 1][j_n - 1].1);
                tmp_ask.add_assign(&ask_terms[i_k][i_n - 1][j_n - 1].0);
                tmp_ask.add_assign(&ask_terms[i_k][i_n - 1][j_n - 1].1);
                tmp_ask.mul_assign(&secret_sharing::get_0_lagrange_coefficient_fr(
                    &indices[i_k],
                    *j_n,
                ));
                ae_indirect.add_assign(&tmp_ae);
                ask_indirect.add_assign(&tmp_ask);
            }
        }

        assert_eq!(
            ae_direct, ae_indirect,
            "Computation of AE is not consistent"
        );
        assert_eq!(
            ask_direct, ask_indirect,
            "Computation of ASK is not consistent"
        );
    }
}

pub fn test_interpolation_for_sk(sk: Fr, sk_shares: &Vec<Fr>, indices: &Vec<usize>) {
    let mut interpolation_result = Fr::zero();

    for &i in indices {
        let mut tmp = sk_shares[(i - 1) as usize];
        tmp.mul_assign(&get_0_lagrange_coefficient_fr(indices, i));
        interpolation_result.add_assign(&tmp)
    }

    assert_eq!(sk, interpolation_result, "Problems with interpolation");
}

pub fn test_per_party_precomputations_without_coefficients(
    k: usize,
    indices: &Vec<Vec<usize>>,
    precomputations: &Vec<PerPartyPrecomputations>,
    sk: Fr,
    a_shares: &Vec<Vec<Fr>>,
    e_shares: &Vec<Vec<Fr>>
) {
    let coefficients = indices
        .iter()
        .map(|indices| get_0_lagrange_coefficient_set_fr(indices))
        .collect::<Vec<Vec<Fr>>>();

    test_per_party_precomputations_with_coefficients(
        k,
        indices,
        &coefficients,
        precomputations,
        sk,
        a_shares,
        e_shares
    );
}

pub fn test_per_party_precomputations_with_coefficients(
    k: usize,
    indices: &Vec<Vec<usize>>,
    coefficients: &Vec<Vec<Fr>>,
    precomputations: &Vec<PerPartyPrecomputations>,
    sk: Fr,
    a_shares: &Vec<Vec<Fr>>,
    e_shares: &Vec<Vec<Fr>>
) {
    for i_k in 0..k {
        let mut a_direct = Fr::zero();
        let mut e_direct = Fr::zero();
        let mut a_indirect = Fr::zero();
        let mut e_indirect = Fr::zero();

        let mut ae_indirect = Fr::zero();
        let mut ask_indirect = Fr::zero();

        for &el_i in &indices[i_k] {
            a_direct.add_assign(&a_shares[i_k][el_i - 1]);
            e_direct.add_assign(&e_shares[i_k][el_i - 1]);

            a_indirect.add_assign(&precomputations[el_i - 1].pre_signatures[i_k].a_share);
            e_indirect.add_assign(&precomputations[el_i - 1].pre_signatures[i_k].e_share);
        }

        let mut ae_direct = a_direct;
        ae_direct.mul_assign(&e_direct);

        let mut ask_direct = a_direct;
        ask_direct.mul_assign(&sk);

        //Compute share of each party and add it to the total
        for (ind_i, &el_i) in indices[i_k].iter().enumerate() {
            //For (ae,as)-shares start with the multiplication of both own shares
            let mut share_of_ae = precomputations[el_i - 1].pre_signatures[i_k].ae_term_own;

            //ASK-Share is split into a part which is to multiplied with own-index-lagrange and one which directly gets other-index-lagrange
            let mut share_of_ask = Fr::zero();
            let mut tmp_ask_own_lagrange =
                precomputations[el_i - 1].pre_signatures[i_k].ask_term_own; //Own-index-lagrange starts with multiplication of both own shares

            for (ind_j, &el_j) in indices[i_k].iter().enumerate() {
                if el_j != el_i {
                    //TODO: Check if manipulation of indices-array is more efficient than repeated checks

                    //Add shares of a_i * e_j (ae_terms_a), a_j * e_i (ae_terms_a)
                    share_of_ae.add_assign(
                        &precomputations[el_i - 1].pre_signatures[i_k].ae_terms_a[el_j - 1],
                    );
                    share_of_ae.add_assign(
                        &precomputations[el_i - 1].pre_signatures[i_k].ae_terms_e[el_j - 1],
                    );

                    //Share of  a_i * sk_j (using j's lagrange coefficient) is added to share_of_ask
                    let mut tmp =
                        precomputations[el_i - 1].pre_signatures[i_k].ask_terms_a[el_j - 1];
                    tmp.mul_assign(&coefficients[i_k][ind_j]);
                    share_of_ask.add_assign(&tmp);

                    //Share of a_j * sk_i (using i's lagrange coefficeint) is added to tmp_ask_own_lagrange (coefficient is applied later for all at once)
                    tmp_ask_own_lagrange.add_assign(
                        &precomputations[el_i - 1].pre_signatures[i_k].ask_terms_sk[el_j - 1],
                    );
                }
            }

            //Apply i's lagrange coefficient to sum of share of all cross-terms incoperating sk_i and add result to share of ask
            tmp_ask_own_lagrange.mul_assign(&coefficients[i_k][ind_i]);
            share_of_ask.add_assign(&tmp_ask_own_lagrange);

            //Add computed share of ae/as/ask to the computation of ae/as/ask
            ae_indirect.add_assign(&share_of_ae);
            ask_indirect.add_assign(&share_of_ask);
        }

        assert_eq!(a_direct, a_indirect, "Computation of A is not consistent");
        assert_eq!(e_direct, e_indirect, "Computation of E is not consistent");
        assert_eq!(
            ae_direct, ae_indirect,
            "Computation of AE is not consistent"
        );
        assert_eq!(
            ask_direct, ask_indirect,
            "Computation of ASK is not consistent"
        );
    }
}
