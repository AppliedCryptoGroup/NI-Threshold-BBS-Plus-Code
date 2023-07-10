use crate::fhks_bbs_plus::precomputation::*;
use crate::helpers::*;
use ff_zeroize::Field;
use pairing_plus::bls12_381::Fr;
use rand_core::SeedableRng;

pub fn generate_pp_precomputation(
    seed_array: [u8; 16],
    t: usize,
    n: usize,
    k: usize,
) -> (Fr, Vec<PerPartyPrecomputations>) {
    let (sk, sk_shares, a_shares, e_shares, s_shares, ae_terms, as_terms, ask_terms) =
        generate_pcf_pcg_output(seed_array, t, n, k);
    (
        sk,
        create_pp_precomputation_from_all_v_ole_evaluations(
            k, n, &sk_shares, &a_shares, &e_shares, &s_shares, &ae_terms, &as_terms, &ask_terms,
        ),
    )
}

//TODO: More references, less cloning... however, this part is not evaluated, so efficiency is not that important
//Correct behavior (ska-tuples not tested, yet)
pub fn generate_pcf_pcg_output(
    seed_array: [u8; 16],
    t: usize,
    n: usize,
    k: usize,
) -> (
    Fr,
    Vec<Fr>,
    Vec<Vec<Fr>>,
    Vec<Vec<Fr>>,
    Vec<Vec<Fr>>,
    Vec<Vec<Vec<(Fr, Fr)>>>,
    Vec<Vec<Vec<(Fr, Fr)>>>,
    Vec<Vec<Vec<(Fr, Fr)>>>,
) {
    let mut rng = rand_xorshift::XorShiftRng::from_seed(seed_array);

    let (sk, sk_shares) = secret_sharing::get_shamir_shared_random_element(&mut rng, t, n);
    let a_shares = rng::get_random_elements(&mut rng, n, k);
    let e_shares = rng::get_random_elements(&mut rng, n, k);
    let s_shares = rng::get_random_elements(&mut rng, n, k);

    let ae_terms =
        ole_correlation::make_all_parties_ole(&mut rng, n, k, a_shares.clone(), e_shares.clone());
    let as_terms =
        ole_correlation::make_all_parties_ole(&mut rng, n, k, a_shares.clone(), s_shares.clone());
    let ask_terms =
        ole_correlation::make_all_parties_vole(&mut rng, n, k, a_shares.clone(), sk_shares.clone());

    return (
        sk, sk_shares, a_shares, e_shares, s_shares, ae_terms, as_terms, ask_terms,
    );
}

//TODO Make more efficient by merging iterations. However, less priority as this part is not evaluated
pub fn create_pp_precomputation_from_all_v_ole_evaluations(
    k: usize,
    n: usize,
    sk_shares: &Vec<Fr>,
    a_shares: &Vec<Vec<Fr>>,
    e_shares: &Vec<Vec<Fr>>,
    s_shares: &Vec<Vec<Fr>>,
    ae_terms: &Vec<Vec<Vec<(Fr, Fr)>>>,
    as_terms: &Vec<Vec<Vec<(Fr, Fr)>>>,
    ask_terms: &Vec<Vec<Vec<(Fr, Fr)>>>,
) -> Vec<PerPartyPrecomputations> {
    (0..n)
        .collect::<Vec<usize>>()
        .iter()
        .map(|&i_n| PerPartyPrecomputations {
            index: i_n,
            sk_share: sk_shares[i_n],
            pre_signatures: (0..k)
                .collect::<Vec<usize>>()
                .iter()
                .map(|&i_k| {
                    let mut ae_term_own = a_shares[i_k][i_n];
                    ae_term_own.mul_assign(&e_shares[i_k][i_n]);

                    let mut as_term_own = a_shares[i_k][i_n];
                    as_term_own.mul_assign(&s_shares[i_k][i_n]);

                    let mut ask_term_own = a_shares[i_k][i_n];
                    ask_term_own.mul_assign(&sk_shares[i_n]);

                    PerPartyPreSignature {
                        a_share: a_shares[i_k][i_n],
                        e_share: e_shares[i_k][i_n],
                        s_share: s_shares[i_k][i_n],
                        ae_term_own: ae_term_own,
                        as_term_own: as_term_own,
                        ask_term_own: ask_term_own,
                        ae_terms_a: (0..n)
                            .collect::<Vec<usize>>()
                            .iter()
                            .map(|&j_n| ae_terms[i_k][i_n][j_n].0)
                            .collect::<Vec<Fr>>(),
                        ae_terms_e: (0..n)
                            .collect::<Vec<usize>>()
                            .iter()
                            .map(|&j_n| ae_terms[i_k][j_n][i_n].1)
                            .collect::<Vec<Fr>>(),
                        as_terms_a: (0..n)
                            .collect::<Vec<usize>>()
                            .iter()
                            .map(|&j_n| as_terms[i_k][i_n][j_n].0)
                            .collect::<Vec<Fr>>(),
                        as_terms_s: (0..n)
                            .collect::<Vec<usize>>()
                            .iter()
                            .map(|&j_n| as_terms[i_k][j_n][i_n].1)
                            .collect::<Vec<Fr>>(),
                        ask_terms_a: (0..n)
                            .collect::<Vec<usize>>()
                            .iter()
                            .map(|&j_n| ask_terms[i_k][i_n][j_n].0)
                            .collect::<Vec<Fr>>(),
                        ask_terms_sk: (0..n)
                            .collect::<Vec<usize>>()
                            .iter()
                            .map(|&j_n| ask_terms[i_k][j_n][i_n].1)
                            .collect::<Vec<Fr>>(),
                    }
                })
                .collect::<Vec<PerPartyPreSignature>>(),
        })
        .collect::<Vec<PerPartyPrecomputations>>()
}
