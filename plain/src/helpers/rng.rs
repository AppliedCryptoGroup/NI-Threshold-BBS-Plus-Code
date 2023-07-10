use ff_zeroize::Field;
use pairing_plus::bls12_381::Fr;
use rand_core::SeedableRng;
use rand_xorshift::XorShiftRng;

//Creates a k-size vector of n-size vectors of random field elements
pub fn get_random_elements(rng: &mut XorShiftRng, n: usize, k: usize) -> Vec<Vec<Fr>> {
    //k vectors with n random elements
    (0..k)
        .collect::<Vec<usize>>()
        .iter()
        .map(|_| {
            (0..n)
                .collect::<Vec<usize>>()
                .iter()
                .map(|_| Fr::random(rng))
                .collect::<Vec<Fr>>()
        })
        .collect::<Vec<Vec<Fr>>>()
}

pub fn get_random_messages_from_seed(seed_array: [u8; 16], c1: usize, c2: usize) -> Vec<Vec<Fr>> {
    let mut rng = rand_xorshift::XorShiftRng::from_seed(seed_array);

    get_random_elements(&mut rng, c1, c2)
}

pub fn get_random_messages_from_seed_one_dim(seed_array: [u8; 16], c: usize) -> Vec<Fr> {
    let mut rng = rand_xorshift::XorShiftRng::from_seed(seed_array);
    (0..c)
        .collect::<Vec<usize>>()
        .iter()
        .map(|_| Fr::random(&mut rng))
        .collect::<Vec<Fr>>()
}
