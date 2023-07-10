use ff_zeroize::Field;
use ff_zeroize::PrimeField;
use pairing_plus::bls12_381::Fr;
use pairing_plus::bls12_381::FrRepr;
use rand_xorshift::XorShiftRng;

//Computes the lagrange coefficient that is to be applied to the evaluation of the polynomial at position evaluation_x for an interpolation to position interpolation_x if the available evaluated positions are defined by indices
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

//Computes the lagrange coefficient that is to be applied to the evaluation of the polynomial at position evaluation_x for an interpolation to position 0 if the available evaluated positions are defined by indices
pub fn get_0_lagrange_coefficient_fr(indices: &Vec<usize>, evaluation_x: usize) -> Fr {
    get_lagrange_coefficient_fr(indices, evaluation_x, 0)
}

//Computes all lagrange coefficients for an interpolation to position 0 if the available evaluated positions are defined by indices
pub fn get_0_lagrange_coefficient_set_fr(indices: &Vec<usize>) -> Vec<Fr> {
    indices
        .iter()
        .map(|&i| get_0_lagrange_coefficient_fr(indices, i))
        .collect::<Vec<Fr>>()
}

//Generates a t-out-of-n shamir secret sharing of a random element
pub fn get_shamir_shared_random_element(
    rng: &mut XorShiftRng,
    t: usize,
    n: usize,
) -> (Fr, Vec<Fr>) {
    //Generate the secret key:
    let secret_key_element = Fr::random(rng);

    //Shamir Coefficients
    let coefficients = (0..(t - 1))
        .collect::<Vec<usize>>()
        .iter()
        .map(|_| Fr::random(rng))
        .collect::<Vec<Fr>>();

    //Shares
    let shares_count = (0..n).collect::<Vec<usize>>();
    let shares = shares_count
        .iter()
        .map(|i| {
            let mut share = secret_key_element;
            let mut incr_exponentiation = Fr::one();
            // println!("****");
            // println!("Computation of share {:?}", i + 1);
            // println!("**");
            // println!("0");
            // println!("Share during comp: {:?}", share);
            // println!("Incr expo during comp: {:?}", incr_exponentiation);
            for j in 0..(t - 1) {
                //t is exclusive
                // println!("**");
                // println!("{:?}",j + 1);
                incr_exponentiation
                    .mul_assign(&Fr::from_repr(FrRepr::from((i + 1) as u64)).unwrap());
                let mut tmp = coefficients[j];
                tmp.mul_assign(&incr_exponentiation);
                share.add_assign(&tmp);
                // println!("Share during comp: {:?}", share);
                // println!("Incr expo during comp: {:?}", incr_exponentiation);
            }
            share
        })
        .collect::<Vec<Fr>>();

    return (secret_key_element, shares);
}
