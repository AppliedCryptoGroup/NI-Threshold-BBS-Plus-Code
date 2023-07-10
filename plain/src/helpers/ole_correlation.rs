use ff_zeroize::Field;
use pairing_plus::bls12_381::Fr;
use rand_xorshift::XorShiftRng;

//Gets twice t elements of each party and creates the following ole correlation:
//It holds that res[i_s][i_x][i_y][0] + res[i_s][i_x][i_y][1] = x[i_s][i_x] * y[i_s][i_y] (for each i_s in k, i_x in n, i_y in n)
//Party i is supposed to own all res[i_s][i][j][0] and res[i_s][j][i][1] for all j in [n]
pub fn make_all_parties_ole(
    rng: &mut XorShiftRng,
    n: usize,
    k: usize,
    x: Vec<Vec<Fr>>,
    y: Vec<Vec<Fr>>,
) -> Vec<Vec<Vec<(Fr, Fr)>>> {
    assert_eq!(
        k,
        x.len(),
        "make_all_parties_ole got ill-structured input format x.len() != k"
    );
    assert_eq!(
        k,
        y.len(),
        "make_all_parties_ole got ill-structured input format y.len() != k"
    );
    (0..k)
        .collect::<Vec<usize>>()
        .iter()
        .cloned()
        .map(|i_k| {
            assert_eq!(
                n,
                x[i_k].len(),
                "make_all_parties_ole got ill-structured input format x[i_k].len() != n"
            );
            assert_eq!(
                n,
                y[i_k].len(),
                "make_all_parties_ole got ill-structured input format y[i_k].len() != n"
            );
            (0..n)
                .collect::<Vec<usize>>()
                .iter()
                .cloned()
                .map(|i_x| {
                    (0..n)
                        .collect::<Vec<usize>>()
                        .iter()
                        .cloned()
                        .map(|i_y| make_ole_single(rng, x[i_k][i_x], y[i_k][i_y]))
                        .collect::<Vec<(Fr, Fr)>>()
                })
                .collect::<Vec<Vec<(Fr, Fr)>>>()
        })
        .collect::<Vec<Vec<Vec<(Fr, Fr)>>>>()
}

//Gets t elements and one scalar of each party (x[i_k][i]: element i_k of party i, y[i]: scalar of party i)
pub fn make_all_parties_vole(
    rng: &mut XorShiftRng,
    n: usize,
    k: usize,
    x: Vec<Vec<Fr>>,
    y: Vec<Fr>,
) -> Vec<Vec<Vec<(Fr, Fr)>>> {
    assert_eq!(
        k,
        x.len(),
        "make_all_parties_vole got ill-structured input format x.len() != k"
    );
    assert_eq!(
        n,
        y.len(),
        "make_all_parties_vole got ill-structured input format y.len() != n"
    );

    (0..k)
        .collect::<Vec<usize>>()
        .iter()
        .cloned()
        .map(|i_k| {
            assert_eq!(
                n,
                x[i_k].len(),
                "make_all_parties_vole got ill-structured input format x[i_k].len() != n"
            );
            (0..n)
                .collect::<Vec<usize>>()
                .iter()
                .cloned()
                .map(|i_x| {
                    (0..n)
                        .collect::<Vec<usize>>()
                        .iter()
                        .cloned()
                        .map(|i_y| make_ole_single(rng, x[i_k][i_x], y[i_y]))
                        .collect::<Vec<(Fr, Fr)>>()
                })
                .collect::<Vec<Vec<(Fr, Fr)>>>()
        })
        .collect::<Vec<Vec<Vec<(Fr, Fr)>>>>()
}

//Gets inputs x and y and generates u,v such that x*y = u+ v
pub fn make_ole_single(rng: &mut XorShiftRng, x: Fr, y: Fr) -> (Fr, Fr) {
    //Gets inputs x and y and generates u, v such that x*y = u + v
    let u = Fr::random(rng);
    let mut v = x; //v = x
    v.mul_assign(&y); //v = xy
    v.sub_assign(&u); //v = xy - u
    (u, v)
}
