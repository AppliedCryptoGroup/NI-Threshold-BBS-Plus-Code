use ff_zeroize::Field;
use ff_zeroize::PrimeField;
use pairing_plus::bls12_381::Fr;
use pairing_plus::bls12_381::FrRepr;
use rand_xorshift::XorShiftRng;

pub fn get_lagrange_coefficient_fr(
    indices: &Vec<usize>,
    evaluation_x: usize,
    interpolation_x: usize,
) -> Fr {
    let mut top = Fr::one();
    let mut bot = Fr::one();

    for &index in indices {
        if index != evaluation_x {
            let mut tmp_top = Fr::from_repr(FrRepr::from(interpolation_x as u64)).unwrap();
            tmp_top.sub_assign(&Fr::from_repr(FrRepr::from(index as u64)).unwrap());
            top.mul_assign(&tmp_top);

            let mut tmp_bot = Fr::from_repr(FrRepr::from(evaluation_x as u64)).unwrap();
            tmp_bot.sub_assign(&Fr::from_repr(FrRepr::from(index as u64)).unwrap());
            bot.mul_assign(&tmp_bot);
        }
    }

    top.mul_assign(&bot.inverse().unwrap());
    top
}

pub fn get_0_lagrange_coefficient_fr(indices: &Vec<usize>, evaluation_x: usize) -> Fr {
    get_lagrange_coefficient_fr(indices, evaluation_x, 0)
}

pub fn get_0_lagrange_coefficient_set_fr(indices: &Vec<usize>) -> Vec<Fr> {
    indices
        .iter()
        .map(|&i| get_0_lagrange_coefficient_fr(indices, i))
        .collect::<Vec<Fr>>()
}

pub fn get_shamir_shared_random_element(
    rng: &mut XorShiftRng,
    t: usize,
    n: usize,
) -> (Fr, Vec<Fr>) {
    let secret_key_element = Fr::random(rng);

    let coefficients = (0..(t - 1))
        .collect::<Vec<usize>>()
        .iter()
        .map(|_| Fr::random(rng))
        .collect::<Vec<Fr>>();

    let shares_count = (0..n).collect::<Vec<usize>>();
    let shares = shares_count
        .iter()
        .map(|i| {
            let mut share = secret_key_element;
            let mut incr_exponentiation = Fr::one();

            for j in 0..(t - 1) {
                incr_exponentiation
                    .mul_assign(&Fr::from_repr(FrRepr::from((i + 1) as u64)).unwrap());
                let mut tmp = coefficients[j];
                tmp.mul_assign(&incr_exponentiation);
                share.add_assign(&tmp);
            }
            share
        })
        .collect::<Vec<Fr>>();

    return (secret_key_element, shares);
}
