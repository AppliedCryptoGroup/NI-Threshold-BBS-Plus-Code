use pairing_plus::bls12_381::Fr;
use pairing_plus::bls12_381::G1;
use pairing_plus::bls12_381::G2;
use pairing_plus::CurveProjective;
use rand_core::SeedableRng;
use rand_xorshift::XorShiftRng;

pub struct PublicKey {
    pub h0: G1,
    pub h: Vec<G1>,
    pub w: G2,
}

impl PublicKey {
    pub fn generate(seed_array: [u8; 16], sk: Fr, message_count: usize) -> Self {
        let mut rng = rand_xorshift::XorShiftRng::from_seed(seed_array);
        Self::generate_from_rng(&mut rng, sk, message_count)
    }

    pub fn generate_from_rng(rng: &mut XorShiftRng, sk: Fr, message_count: usize) -> Self {
        let mut w = G2::one();
        w.mul_assign(sk);
        let all_h = (0..=message_count)
            .collect::<Vec<usize>>()
            .iter()
            .map(|_| {
                //TODO: The Pairing-plus library always casts random G1 elements into affine. I do not fully understand why. Alternatively, we could just multiply G1::one() with a random Fr element
                G1::random(rng)
            })
            .collect::<Vec<G1>>();
        PublicKey {
            w: w,
            h0: all_h[0],
            h: all_h[1..].to_vec(),
        }
    }
}
