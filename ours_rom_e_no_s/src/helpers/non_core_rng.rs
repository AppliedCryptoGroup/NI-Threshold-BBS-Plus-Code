use rand::prelude::IteratorRandom;
use rand::rngs::SmallRng;
use rand::SeedableRng;

pub fn random_signer_set(seed: [u8; 16], t: usize, n: usize) -> Vec<usize> {
    let mut rng = SmallRng::from_seed(seed);
    (1..=n)
        .collect::<Vec<usize>>()
        .iter()
        .choose_multiple(&mut rng, t)
        .iter()
        .map(|&x| *x)
        .collect()
}
