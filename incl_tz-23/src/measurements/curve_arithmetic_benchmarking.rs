use ff_zeroize::Field;
use pairing_plus::bls12_381::Bls12;
use pairing_plus::bls12_381::Fr;
use pairing_plus::bls12_381::G1;
use pairing_plus::bls12_381::G2;
use pairing_plus::CurveProjective;
use pairing_plus::Engine;

pub fn g1_add(mut x: G1, y: G1) {
    x.add_assign(&y)
}

pub fn g2_add(mut x: G2, y: G2) {
    x.add_assign(&y)
}

pub fn g1_mul(mut x: G1, y: Fr) {
    x.mul_assign(y)
}

pub fn g2_mul(mut x: G2, y: Fr) {
    x.mul_assign(y)
}

pub fn fr_add(mut x: Fr, y: Fr) {
    x.add_assign(&y);
}

pub fn fr_mul(mut x: Fr, y: Fr) {
    x.mul_assign(&y);
}

pub fn fr_inv(mut x: Fr) {
    x.inverse().unwrap();
}

pub fn pair(x: G1, y: G2) {
    Bls12::pairing(x, y);
}
