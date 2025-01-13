use crate::threshold_signature::ThresholdSignature;
use criterion::BenchmarkId;
use criterion::{criterion_group, criterion_main, Criterion};
use ff_zeroize::Field;
use pairing_plus::bls12_381::{Fr, G1, G2};
use pairing_plus::hash_to_field::hash_to_field;
use pairing_plus::hash_to_field::ExpandMsgXmd;
use pairing_plus::CurveProjective;
use rand_core::RngCore;
use rand_core::SeedableRng;
use rand_xorshift::XorShiftRng;
use sha2::Sha256;
use optimized_bbs_without_s::fhks_bbs_plus::keys::PublicKey;
use optimized_bbs_without_s::fhks_bbs_plus::partial_threshold_signature::PartialThresholdSignature;
use optimized_bbs_without_s::fhks_bbs_plus::precomputation::LivePreSignature;
use optimized_bbs_without_s::fhks_bbs_plus::precomputation::PerPartyPrecomputations;
use optimized_bbs_without_s::fhks_bbs_plus::*;
use optimized_bbs_without_s::helpers;
use optimized_bbs_without_s::helpers::non_core_rng;
use optimized_bbs_without_s::helpers::secret_sharing;
use optimized_bbs_without_s::measurements::*;
use optimized_bbs_without_s::precomputation_mockup::*;

static MESSAGE_COUNTS: [usize; 11] = [1, 2, 5, 10, 20, 25, 30, 35, 40, 45, 50];
static T_N_TUPLES: [(usize, usize); 9] = [
    (2, 2),
    (2, 3),
    (3, 3),
    (3, 5),
    (5, 5),
    (5, 10),
    (8, 10),
    (10, 10),
    (30, 50),
];
static DIFFERENT_T: [usize; 9] = [2, 3, 5, 8, 10, 15, 20, 25, 30];
static SAMPLE_SIZE: usize = 100;

criterion_group! {
    name = curve_arithmetic;
    config = Criterion::default().sample_size(SAMPLE_SIZE);
    targets = random_curve_arithmetic_evaluation
}

criterion_group! {
    name = bbs_make_live_eval;
    config = Criterion::default().sample_size(SAMPLE_SIZE);
    targets = bbs_make_live
}

criterion_group! {
    name = bbs_make_live_pre_lg_eval;
    config = Criterion::default().sample_size(SAMPLE_SIZE);
    targets = bbs_make_live_precomputed_lagrance
}

criterion_group! {
    name = bbs_sign_eval;
    config = Criterion::default().sample_size(SAMPLE_SIZE);
    targets = bbs_threshold_sign
}

criterion_group! {
    name = bbs_reconstruct_eval;
    config = Criterion::default().sample_size(SAMPLE_SIZE);
    targets = bbs_reconstruct
}

criterion_group! {
    name = bbs_direct_sign_eval;
    config = Criterion::default().sample_size(SAMPLE_SIZE);
    targets = bbs_direct_sign
}

criterion_group! {
    name = bbs_verify_eval;
    config = Criterion::default().sample_size(SAMPLE_SIZE);
    targets = bbs_verify
}

criterion_group! {
    name = all_bbs_in_one_group;
    config = Criterion::default().sample_size(SAMPLE_SIZE);
    targets = all_bbs
}

criterion_group! {
    name = hash_overhead;
    config = Criterion::default().sample_size(SAMPLE_SIZE);
    targets = eval_hashing_oberhead
}

criterion_group! {
    name = string_concat_overhead;
    config = Criterion::default().sample_size(SAMPLE_SIZE);
    targets = eval_string_concat_overhead
}

criterion_main!(
    curve_arithmetic,
    bbs_make_live_eval,
    bbs_make_live_pre_lg_eval,
    bbs_sign_eval,
    bbs_reconstruct_eval,
    bbs_direct_sign_eval,
    bbs_verify_eval,
    hash_overhead,
    string_concat_overhead
);

pub fn bbs_reconstruct(c: &mut Criterion) {
    let running_seed: &mut [u8] = &mut [
        0x59, 0x62, 0xbe, 0x5d, 0x76, 0xaa, 0x31, 0x8d, 0x17, 0x14, 0x37, 0x32, 0x37, 0x06, 0xac,
        0xe5,
    ];
    let mut rng = rand_xorshift::XorShiftRng::from_seed(running_seed.try_into().unwrap());
    let ts = DIFFERENT_T.to_vec();

    let mut group = c.benchmark_group("BBS_Plus_Operations/reconstruct-dep-t");

    for t in ts {
        group.bench_with_input(BenchmarkId::from_parameter(t), &t, |b, &t| {
            let (pk, _, pre_computation, signer_set, messages, messages_as_string) =
                get_bbs_setup(&mut rng, running_seed, t, t, 1);

            let mut partial_signatures = vec![];

            for i_t in 0..t {
                let own_index = signer_set[i_t];
                let live_pre_signature = LivePreSignature::from_presignature(
                    own_index,
                    &signer_set,
                    &pre_computation[own_index - 1].pre_signatures[0],
                );
                let ro_input = "ssid=1234".to_string()
                    + "_messages="
                    + &messages_as_string
                    + "_signerSet="
                    + &signer_set
                        .iter()
                        .map(|num| num.to_string())
                        .collect::<Vec<String>>()
                        .join(",");
                let partial_threshold_signature =
                    PartialThresholdSignature::new(&messages, &pk, &live_pre_signature, ro_input);
                partial_signatures.push(partial_threshold_signature);
            }

            b.iter(|| ThresholdSignature::from_partial_signatures(&partial_signatures));
        });
    }
}

pub fn bbs_make_live(c: &mut Criterion) {
    let running_seed: &mut [u8] = &mut [
        0x59, 0x62, 0xbe, 0x5d, 0x76, 0xaa, 0x31, 0x8d, 0x17, 0x14, 0x37, 0x32, 0x37, 0x06, 0xac,
        0xe5,
    ];
    let mut rng = rand_xorshift::XorShiftRng::from_seed(running_seed.try_into().unwrap());
    let ts = DIFFERENT_T.to_vec();

    let mut group = c.benchmark_group("BBS_Plus_Operations/make-live-dep-t");

    for t in ts {
        group.bench_with_input(BenchmarkId::from_parameter(t), &t, |b, &t| {
            let (_, _, pre_computation, signer_set, _, _) =
                get_bbs_setup(&mut rng, running_seed, t, t + 2, 1);
            let own_index = signer_set[0];
            let own_pre_computation_instance = &pre_computation[own_index - 1].pre_signatures[0];

            b.iter(|| {
                LivePreSignature::from_presignature(
                    own_index,
                    &signer_set,
                    own_pre_computation_instance,
                )
            });
        });
    }
}

pub fn bbs_make_live_precomputed_lagrance(c: &mut Criterion) {
    let running_seed: &mut [u8] = &mut [
        0x59, 0x62, 0xbe, 0x5d, 0x76, 0xaa, 0x31, 0x8d, 0x17, 0x14, 0x37, 0x32, 0x37, 0x06, 0xac,
        0xe5,
    ];
    let mut rng = rand_xorshift::XorShiftRng::from_seed(running_seed.try_into().unwrap());
    let ts = DIFFERENT_T.to_vec();

    let mut group = c.benchmark_group("BBS_Plus_Operations/make-live-dep-t-pre-lg");

    for t in ts {
        group.bench_with_input(BenchmarkId::from_parameter(t), &t, |b, &t| {
            let (_, _, pre_computation, signer_set, _, _) =
                get_bbs_setup(&mut rng, running_seed, t, t + 2, 1);
            let own_index = signer_set[0];
            let own_pre_computation_instance = &pre_computation[own_index - 1].pre_signatures[0];

            let lagrange_coefficients =
                secret_sharing::get_0_lagrange_coefficient_set_fr(&signer_set);

            b.iter(|| {
                LivePreSignature::from_presignature_with_coefficients(
                    own_index,
                    &signer_set,
                    own_pre_computation_instance,
                    &lagrange_coefficients,
                )
            });
        });
    }
}

pub fn bbs_threshold_sign(c: &mut Criterion) {
    let running_seed: &mut [u8] = &mut [
        0x59, 0x62, 0xbe, 0x5d, 0x76, 0xaa, 0x31, 0x8d, 0x17, 0x14, 0x37, 0x32, 0x37, 0x06, 0xac,
        0xe5,
    ];
    let mut rng = rand_xorshift::XorShiftRng::from_seed(running_seed.try_into().unwrap());
    let message_counts = MESSAGE_COUNTS.to_vec();

    let mut group = c.benchmark_group("BBS_Plus_Operations/threshold-sign-dep-m");

    for message_count in message_counts {
        group.bench_with_input(
            BenchmarkId::from_parameter(message_count),
            &message_count,
            |b, &m| {
                let (pk, _, pre_computation, signer_set, messages, messages_as_string) =
                    get_bbs_setup(&mut rng, running_seed, 3, 4, m);
                let own_index = signer_set[0];
                let live_pre_signature = LivePreSignature::from_presignature(
                    own_index,
                    &signer_set,
                    &pre_computation[own_index - 1].pre_signatures[0],
                );
                b.iter(|| {
                    PartialThresholdSignature::new(
                        &messages,
                        &pk,
                        &live_pre_signature,
                        "ssid=1234".to_string()
                            + "_messages="
                            + &messages_as_string
                            + "_signerSet="
                            + &signer_set
                                .iter()
                                .map(|num| num.to_string())
                                .collect::<Vec<String>>()
                                .join(","),
                    )
                });
            },
        );
    }
}

pub fn bbs_direct_sign(c: &mut Criterion) {
    let running_seed: &mut [u8] = &mut [
        0x59, 0x62, 0xbe, 0x5d, 0x76, 0xaa, 0x31, 0x8d, 0x17, 0x14, 0x37, 0x32, 0x37, 0x06, 0xac,
        0xe5,
    ];
    let mut rng = rand_xorshift::XorShiftRng::from_seed(running_seed.try_into().unwrap());
    let message_counts = MESSAGE_COUNTS.to_vec();

    let mut group = c.benchmark_group("BBS_Plus_Operations/direct_sign-dep-m");

    for message_count in message_counts {
        group.bench_with_input(
            BenchmarkId::from_parameter(message_count),
            &message_count,
            |b, &m| {
                let (pk, sk, pre_computation, _, messages, _) =
                    get_bbs_setup(&mut rng, running_seed, 3, 3, m);
                let e = pre_computation[0].sk_share;

                b.iter(|| ThresholdSignature::from_secret_key(&pk, sk, e, &messages));
            },
        );
    }
}

pub fn bbs_verify(c: &mut Criterion) {
    let running_seed: &mut [u8] = &mut [
        0x59, 0x62, 0xbe, 0x5d, 0x76, 0xaa, 0x31, 0x8d, 0x17, 0x14, 0x37, 0x32, 0x37, 0x06, 0xac,
        0xe5,
    ];
    let mut rng = rand_xorshift::XorShiftRng::from_seed(running_seed.try_into().unwrap());
    let message_counts = MESSAGE_COUNTS.to_vec();

    let mut group = c.benchmark_group("BBS_Plus_Operations/verify-dep-m");

    for message_count in message_counts {
        group.bench_with_input(
            BenchmarkId::from_parameter(message_count),
            &message_count,
            |b, &m| {
                let (pk, sk, pre_computation, _, messages, _) =
                    get_bbs_setup(&mut rng, running_seed, 3, 3, m);
                let e = pre_computation[0].sk_share;
                let signature = ThresholdSignature::from_secret_key(&pk, sk, e, &messages);

                b.iter(|| signature.verify(&messages, &pk));

                if !signature.verify(&messages, &pk) {
                    println!("Problem with signature verification in evaluation");
                }
            },
        );
    }
}

pub fn all_bbs(c: &mut Criterion) {
    let running_seed: &mut [u8] = &mut [
        0x59, 0x62, 0xbe, 0x5d, 0x76, 0xaa, 0x31, 0x8d, 0x17, 0x14, 0x37, 0x32, 0x37, 0x06, 0xac,
        0xe5,
    ];
    let mut rng = rand_xorshift::XorShiftRng::from_seed(running_seed.try_into().unwrap());

    let t_n_tuples = T_N_TUPLES.to_vec();
    let message_counts = MESSAGE_COUNTS.to_vec();
    let ts = DIFFERENT_T.to_vec();

    let mut group = c.benchmark_group("All_BBS_Plus_Operations");

    for message_count in message_counts {
        for t_n_tuple in &t_n_tuples {
            group.bench_with_input(
                format!(
                    "make-live/{}-out-of-{}/{}",
                    t_n_tuple.0, t_n_tuple.1, message_count
                ),
                &(t_n_tuple, message_count),
                |b, &((t, n), m)| {
                    let (_, _, pre_computation, signer_set, _, _) =
                        get_bbs_setup(&mut rng, running_seed, *t, *n, m);
                    let own_index = signer_set[0];
                    let own_pre_computation_instance =
                        &pre_computation[own_index - 1].pre_signatures[0];

                    b.iter(|| {
                        LivePreSignature::from_presignature(
                            own_index,
                            &signer_set,
                            own_pre_computation_instance,
                        )
                    });
                },
            );

            group.bench_with_input(
                format!(
                    "make-live-precomputed-lg/{}-out-of-{}/{}",
                    t_n_tuple.0, t_n_tuple.1, message_count
                ),
                &(t_n_tuple, message_count),
                |b, &((t, n), m)| {
                    let (_, _, pre_computation, signer_set, _, _) =
                        get_bbs_setup(&mut rng, running_seed, *t, *n, m);
                    let own_index = signer_set[0];
                    let own_pre_computation_instance =
                        &pre_computation[own_index - 1].pre_signatures[0];

                    let lagrange_coefficients =
                        secret_sharing::get_0_lagrange_coefficient_set_fr(&signer_set);

                    b.iter(|| {
                        LivePreSignature::from_presignature_with_coefficients(
                            own_index,
                            &signer_set,
                            own_pre_computation_instance,
                            &lagrange_coefficients,
                        )
                    });
                },
            );
        }

        for t in &ts {
            group.bench_with_input(
                format!("reconstruct/{}-shares/{}", t, message_count),
                &(t, message_count),
                |b, &(t, m)| {
                    let (pk, _, pre_computation, signer_set, messages, messages_as_string) =
                        get_bbs_setup(&mut rng, running_seed, *t, *t, m);

                    let mut partial_signatures = vec![];

                    for i_t in 0..*t {
                        let own_index = signer_set[i_t];
                        let live_pre_signature = LivePreSignature::from_presignature(
                            own_index,
                            &signer_set,
                            &pre_computation[own_index - 1].pre_signatures[0],
                        );
                        let ro_input = "ssid=1234".to_string()
                            + "_messages="
                            + &messages_as_string
                            + "_signerSet="
                            + &signer_set
                                .iter()
                                .map(|num| num.to_string())
                                .collect::<Vec<String>>()
                                .join(",");
                        let partial_threshold_signature = PartialThresholdSignature::new(
                            &messages,
                            &pk,
                            &live_pre_signature,
                            ro_input,
                        );
                        partial_signatures.push(partial_threshold_signature);
                    }

                    b.iter(|| ThresholdSignature::from_partial_signatures(&partial_signatures));
                },
            );
        }

        group.bench_with_input(
            format!("threshold-sign/{}", message_count),
            &message_count,
            |b, &m| {
                let (pk, _, pre_computation, signer_set, messages, messages_as_string) =
                    get_bbs_setup(&mut rng, running_seed, 3, 4, m);
                let own_index = signer_set[0];
                let live_pre_signature = LivePreSignature::from_presignature(
                    own_index,
                    &signer_set,
                    &pre_computation[own_index - 1].pre_signatures[0],
                );

                b.iter(|| {
                    PartialThresholdSignature::new(
                        &messages,
                        &pk,
                        &live_pre_signature,
                        "ssid=1234".to_string()
                            + "_messages="
                            + &messages_as_string
                            + "_signerSet="
                            + &signer_set
                                .iter()
                                .map(|num| num.to_string())
                                .collect::<Vec<String>>()
                                .join(","),
                    )
                });
            },
        );

        group.bench_with_input(
            format!("direct_sign/{}", message_count),
            &message_count,
            |b, &m| {
                let (pk, sk, pre_computation, _, messages, _) =
                    get_bbs_setup(&mut rng, running_seed, 3, 3, m);
                let e = pre_computation[0].sk_share;

                b.iter(|| ThresholdSignature::from_secret_key(&pk, sk, e, &messages));
            },
        );

        group.bench_with_input(
            format!("verify/{}", message_count),
            &message_count,
            |b, &m| {
                let (pk, sk, pre_computation, _, messages, _) =
                    get_bbs_setup(&mut rng, running_seed, 3, 3, m);
                let e = pre_computation[0].sk_share;
                let signature = ThresholdSignature::from_secret_key(&pk, sk, e, &messages);

                b.iter(|| signature.verify(&messages, &pk));

                if !signature.verify(&messages, &pk) {
                    println!("Problem with signature verification ine valuation");
                }
            },
        );
    }
}

pub fn eval_hashing_oberhead(c: &mut Criterion) {
    let running_seed: &mut [u8] = &mut [
        0x59, 0x62, 0xbe, 0x5d, 0x76, 0xaa, 0x31, 0x8d, 0x17, 0x14, 0x37, 0x32, 0x37, 0x06, 0xac,
        0xe5,
    ];
    let mut rng = rand_xorshift::XorShiftRng::from_seed(running_seed.try_into().unwrap());
    let ts = DIFFERENT_T.to_vec();

    let mut group = c.benchmark_group("Aux_Operations/hash-dep-m");
    let message_counts = MESSAGE_COUNTS.to_vec();

    for message_count in message_counts {
        group.bench_with_input(
            BenchmarkId::from_parameter(message_count),
            &message_count,
            |b, &m| {
                let signer_set =
                    non_core_rng::random_signer_set(running_seed.try_into().unwrap(), m, m);
                let messages = helpers::rng::get_random_messages_from_seed_one_dim(
                    running_seed.try_into().unwrap(),
                    message_count,
                );
                let messages_as_string = messages
                    .iter()
                    .map(|m| m.to_string())
                    .collect::<Vec<String>>()
                    .join(",");
                let ro_input = "ssid=1234".to_string()
                    + "_messages="
                    + &messages_as_string
                    + "_signerSet="
                    + &signer_set
                        .iter()
                        .map(|num| num.to_string())
                        .collect::<Vec<String>>()
                        .join(",");

                b.iter(|| {
                    let e = hash_to_field::<Fr, ExpandMsgXmd<Sha256>>(
                        ro_input.as_bytes(),
                        b"asdfqwerzxcv",
                        1,
                    )[0];
                });
            },
        );
    }
}

pub fn eval_string_concat_overhead(c: &mut Criterion) {
    let running_seed: &mut [u8] = &mut [
        0x59, 0x62, 0xbe, 0x5d, 0x76, 0xaa, 0x31, 0x8d, 0x17, 0x14, 0x37, 0x32, 0x37, 0x06, 0xac,
        0xe5,
    ];
    let mut rng = rand_xorshift::XorShiftRng::from_seed(running_seed.try_into().unwrap());
    let ts = DIFFERENT_T.to_vec();

    let mut group = c.benchmark_group("Aux_Operations/oracle-input-dep-t");

    for t in ts {
        group.bench_with_input(BenchmarkId::from_parameter(t), &t, |b, &t| {
            let signer_set =
                non_core_rng::random_signer_set(running_seed.try_into().unwrap(), t, t);

            b.iter(|| {
                let ro_input = "ssid=1234".to_string()
                    + "_signerSet="
                    + &signer_set
                        .iter()
                        .map(|num| num.to_string())
                        .collect::<Vec<String>>()
                        .join(",");
            });
        });
    }
}

pub fn random_curve_arithmetic_evaluation(c: &mut Criterion) {
    let seed = [
        0x59, 0x62, 0xbe, 0x5d, 0x76, 0xaa, 0x31, 0x8d, 0x17, 0x14, 0x37, 0x32, 0x37, 0x06, 0xac,
        0xe5,
    ];
    let mut rng = rand_xorshift::XorShiftRng::from_seed(seed);

    let mut group = c.benchmark_group("Curve_Operations");

    group.bench_function("G1Addition", |b| {
        let x = G1::random(&mut rng);
        let y = G1::random(&mut rng);
        b.iter(|| curve_arithmetic_benchmarking::g1_add(x, y))
    });

    group.bench_function("G1Multiplication", |b| {
        let x = G1::random(&mut rng);
        let y = Fr::random(&mut rng);
        b.iter(|| curve_arithmetic_benchmarking::g1_mul(x, y))
    });

    group.bench_function("G2Addition", |b| {
        let x = G2::random(&mut rng);
        let y = G2::random(&mut rng);
        b.iter(|| curve_arithmetic_benchmarking::g2_add(x, y))
    });

    group.bench_function("G2Multiplication", |b| {
        let x = G2::random(&mut rng);
        let y = Fr::random(&mut rng);
        b.iter(|| curve_arithmetic_benchmarking::g2_mul(x, y))
    });

    group.bench_function("FrAddition", |b| {
        let x = Fr::random(&mut rng);
        let y = Fr::random(&mut rng);
        b.iter(|| curve_arithmetic_benchmarking::fr_add(x, y))
    });

    group.bench_function("FrMultiplication", |b| {
        let x = Fr::random(&mut rng);
        let y = Fr::random(&mut rng);
        b.iter(|| curve_arithmetic_benchmarking::fr_mul(x, y))
    });

    group.bench_function("FrInverse", |b| {
        let x = Fr::random(&mut rng);
        b.iter(|| curve_arithmetic_benchmarking::fr_inv(x))
    });

    group.bench_function("Pairing", |b| {
        let x = G1::random(&mut rng);
        let y = G2::random(&mut rng);
        b.iter(|| curve_arithmetic_benchmarking::pair(x, y))
    });
}

pub fn get_bbs_setup(
    rng: &mut XorShiftRng,
    running_seed: &mut [u8],
    t: usize,
    n: usize,
    message_count: usize,
) -> (
    PublicKey,
    Fr,
    Vec<PerPartyPrecomputations>,
    Vec<usize>,
    Vec<Fr>,
    String,
) {
    rng.fill_bytes(running_seed);
    let (sk, pre_computation) = precomputation_generation::generate_pp_precomputation(
        running_seed.try_into().unwrap(),
        t,
        n,
        1,
    );
    rng.fill_bytes(running_seed);
    let pk = PublicKey::generate(running_seed.try_into().unwrap(), sk, message_count);
    rng.fill_bytes(running_seed);
    let signer_set = non_core_rng::random_signer_set(running_seed.try_into().unwrap(), t, n);
    rng.fill_bytes(running_seed);
    let messages = helpers::rng::get_random_messages_from_seed_one_dim(
        running_seed.try_into().unwrap(),
        message_count,
    );
    let messages_as_string = messages
        .iter()
        .map(|m| m.to_string())
        .collect::<Vec<String>>()
        .join(",");
    (
        pk,
        sk,
        pre_computation,
        signer_set,
        messages,
        messages_as_string,
    )
}
