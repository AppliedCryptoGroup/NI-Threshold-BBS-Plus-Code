// use crate::threshold_signature::ThresholdSignature;
// use criterion::BenchmarkId;
// use criterion::Throughput;
// use criterion::{criterion_group, criterion_main, BatchSize, Criterion};
// use ff_zeroize::Field;
// use pairing_plus::bls12_381::{Fr, G1, G2};
// use pairing_plus::CurveProjective;
// use rand_core::RngCore;
// use rand_core::SeedableRng;
// use rand_xorshift::XorShiftRng;
// use structured_no_s::fhks_bbs_plus::keys::PublicKey;
// use structured_no_s::fhks_bbs_plus::partial_threshold_signature::PartialThresholdSignature;
// use structured_no_s::fhks_bbs_plus::precomputation::LivePreSignature;
// use structured_no_s::fhks_bbs_plus::precomputation::PerPartyPrecomputations;
// use structured_no_s::fhks_bbs_plus::*;
// use structured_no_s::helpers;
// use structured_no_s::helpers::non_core_rng;
// use structured_no_s::measurements::*;
// use structured_no_s::precomputation_mockup::*;

// static MESSAGE_COUNTS: [usize; 4] = [1, 2, 5, 10]; //TODO: Increase
// static T_N_TUPLES: [(usize, usize); 8] = [
//     (2, 2),
//     (3, 3),
//     (5, 5),
//     (10, 10),
//     (2, 3),
//     (3, 5),
//     (5, 10),
//     (8, 10),
// ];

// //TODO: I only get a line chart if I use BenchmarkId::from_parameter(size)

// criterion_group! {
//     name = curve_arithmetic;
//     config = Criterion::default().sample_size(10);
//     targets = random_curve_arithmetic_evaluation
// }

// criterion_group! {
//     name = bbs_operations;
//     config = Criterion::default().sample_size(10);
//     targets = random_bbs_evaluation
// }

// criterion_group! {
//     name = test_line_chart;
//     config = Criterion::default().sample_size(10);
//     targets = bbs_make_live
// }

// //criterion_main!(curve_arithmetic, bbs_operations);
// criterion_main!(test_line_chart);

// pub fn get_bbs_setup(
//     rng: &mut XorShiftRng,
//     running_seed: &mut [u8],
//     t: usize,
//     n: usize,
//     message_count: usize,
// ) -> (
//     PublicKey,
//     Fr,
//     Vec<PerPartyPrecomputations>,
//     Vec<usize>,
//     Vec<Fr>,
// ) {
//     rng.fill_bytes(running_seed);
//     let (sk, pre_computation) = precomputation_generation::generate_pp_precomputation(
//         running_seed.try_into().unwrap(),
//         t,
//         n,
//         1,
//     );
//     rng.fill_bytes(running_seed);
//     let pk = PublicKey::generate(running_seed.try_into().unwrap(), sk, message_count);
//     rng.fill_bytes(running_seed);
//     let signer_set = non_core_rng::random_signer_set(running_seed.try_into().unwrap(), t, n);
//     rng.fill_bytes(running_seed);
//     let messages = helpers::rng::get_random_messages_from_seed_one_dim(
//         running_seed.try_into().unwrap(),
//         message_count,
//     );
//     (pk, sk, pre_computation, signer_set, messages)
// }

// //This works!
// pub fn bbs_make_live(c: &mut Criterion) {
//     let running_seed: &mut [u8] = &mut [
//         0x59, 0x62, 0xbe, 0x5d, 0x76, 0xaa, 0x31, 0x8d, 0x17, 0x14, 0x37, 0x32, 0x37, 0x06, 0xac,
//         0xe5,
//     ];
//     let mut rng = rand_xorshift::XorShiftRng::from_seed(running_seed.try_into().unwrap());
//     let t_n_tuples = T_N_TUPLES.to_vec();
//     let message_counts = MESSAGE_COUNTS.to_vec();

//     for t_n_tuple in t_n_tuples {
//         {
//             let mut group = c.benchmark_group(format!(
//                 "BBS_Plus_Operations/make_live/{}-out-of-{}",
//                 t_n_tuple.0, t_n_tuple.1
//             ));
//             for message_count in &message_counts {
//                 group.bench_with_input(
//                     BenchmarkId::from_parameter(message_count),
//                     &(t_n_tuple, message_count),
//                     |b, &((t, n), m)| {
//                         let (_, _, pre_computation, signer_set, _) =
//                             get_bbs_setup(&mut rng, running_seed, t, n, *m);
//                         let own_index = signer_set[0];
//                         let own_pre_computation_instance =
//                             &pre_computation[own_index - 1].pre_signatures[0];

//                         b.iter(|| {
//                             LivePreSignature::from_presignature(
//                                 own_index,
//                                 &signer_set,
//                                 own_pre_computation_instance,
//                             )
//                         });
//                     },
//                 );
//             }
//         }
//     }
// }

// pub fn bbs_threshold_sign(c: &mut Criterion) {
//     let running_seed: &mut [u8] = &mut [
//         0x59, 0x62, 0xbe, 0x5d, 0x76, 0xaa, 0x31, 0x8d, 0x17, 0x14, 0x37, 0x32, 0x37, 0x06, 0xac,
//         0xe5,
//     ];
//     let mut rng = rand_xorshift::XorShiftRng::from_seed(running_seed.try_into().unwrap());
//     let t_n_tuples = T_N_TUPLES.to_vec();
//     let message_counts = MESSAGE_COUNTS.to_vec();

//     for t_n_tuple in t_n_tuples {
//         {
//             let mut group = c.benchmark_group(format!(
//                 "BBS_Plus_Operations/threshold-sign/{}-out-of-{}",
//                 t_n_tuple.0, t_n_tuple.1
//             ));
//             for message_count in &message_counts {
//                 group.bench_with_input(
//                     BenchmarkId::from_parameter(message_count),
//                     &(t_n_tuple, message_count),
//                     |b, &((t, n), m)| {
//                         let (pk, _, pre_computation, signer_set, messages) =
//                             get_bbs_setup(&mut rng, running_seed, t, n, *m);
//                         let own_index = signer_set[0];
//                         let live_pre_signature = LivePreSignature::from_presignature(
//                             own_index,
//                             &signer_set,
//                             &pre_computation[own_index - 1].pre_signatures[0],
//                         );

//                         b.iter(|| {
//                             PartialThresholdSignature::new(&messages, &pk, &live_pre_signature)
//                         });
//                     },
//                 );
//             }
//         }
//     }
// }

// pub fn bbs_reconstruct(c: &mut Criterion) {
//     let running_seed: &mut [u8] = &mut [
//         0x59, 0x62, 0xbe, 0x5d, 0x76, 0xaa, 0x31, 0x8d, 0x17, 0x14, 0x37, 0x32, 0x37, 0x06, 0xac,
//         0xe5,
//     ];
//     let mut rng = rand_xorshift::XorShiftRng::from_seed(running_seed.try_into().unwrap());
//     let t_n_tuples = T_N_TUPLES.to_vec();
//     let message_counts = MESSAGE_COUNTS.to_vec();

//     for t_n_tuple in t_n_tuples {
//         {
//             let mut group = c.benchmark_group(format!(
//                 "BBS_Plus_Operations/reconstruct/{}-out-of-{}",
//                 t_n_tuple.0, t_n_tuple.1
//             ));
//             for message_count in &message_counts {
//                 group.bench_with_input(
//                     BenchmarkId::from_parameter(message_count),
//                     &(t_n_tuple, message_count),
//                     |b, &((t, n), m)| {
//                         let (pk, _, pre_computation, signer_set, messages) =
//                             get_bbs_setup(&mut rng, running_seed, t, n, *m);

//                         let mut partial_signatures = vec![];

//                         for i_t in 0..t {
//                             let own_index = signer_set[i_t];
//                             let live_pre_signature = LivePreSignature::from_presignature(
//                                 own_index,
//                                 &signer_set,
//                                 &pre_computation[own_index - 1].pre_signatures[0],
//                             );
//                             let partial_threshold_signature =
//                                 PartialThresholdSignature::new(&messages, &pk, &live_pre_signature);
//                             partial_signatures.push(partial_threshold_signature);
//                         }

//                         b.iter(|| ThresholdSignature::from_partial_signatures(&partial_signatures));
//                     },
//                 );
//             }
//         }
//     }
// }

// pub fn bbs_direct_sign(c: &mut Criterion) {
//     let running_seed: &mut [u8] = &mut [
//         0x59, 0x62, 0xbe, 0x5d, 0x76, 0xaa, 0x31, 0x8d, 0x17, 0x14, 0x37, 0x32, 0x37, 0x06, 0xac,
//         0xe5,
//     ];
//     let mut rng = rand_xorshift::XorShiftRng::from_seed(running_seed.try_into().unwrap());
//     let message_counts = MESSAGE_COUNTS.to_vec();

//     let mut group = c.benchmark_group("BBS_Plus_Operations/direct_sign");

//     for message_count in message_counts {
//         group.bench_with_input(
//             BenchmarkId::from_parameter(message_count),
//             &message_count,
//             |b, &m| {
//                 let (pk, sk, pre_computation, _, messages) =
//                     get_bbs_setup(&mut rng, running_seed, 3, 3, m);
//                 let e = pre_computation[0].sk_share;
//                 let s = pre_computation[1].sk_share;

//                 b.iter(|| ThresholdSignature::from_secret_key(&pk, sk, e, s, &messages));
//             },
//         );
//     }
// }

// pub fn bbs_verify(c: &mut Criterion) {
//     let running_seed: &mut [u8] = &mut [
//         0x59, 0x62, 0xbe, 0x5d, 0x76, 0xaa, 0x31, 0x8d, 0x17, 0x14, 0x37, 0x32, 0x37, 0x06, 0xac,
//         0xe5,
//     ];
//     let mut rng = rand_xorshift::XorShiftRng::from_seed(running_seed.try_into().unwrap());
//     let message_counts = MESSAGE_COUNTS.to_vec();

//     let mut group = c.benchmark_group("BBS_Plus_Operations/verify");

//     for message_count in message_counts {
//         group.bench_with_input(
//             BenchmarkId::from_parameter(message_count),
//             &message_count,
//             |b, &m| {
//                 let (pk, sk, pre_computation, _, messages) =
//                     get_bbs_setup(&mut rng, running_seed, 3, 3, m);
//                 let e = pre_computation[0].sk_share;
//                 let s = pre_computation[1].sk_share;
//                 let signature = ThresholdSignature::from_secret_key(&pk, sk, e, s, &messages);

//                 b.iter(|| signature.verify(&messages, &pk));

//                 if !signature.verify(&messages, &pk) {
//                     println!("Problem with signature verification ine valuation");
//                 }
//             },
//         );
//     }
// }

// pub fn random_bbs_evaluation(c: &mut Criterion) {
//     let running_seed: &mut [u8] = &mut [
//         0x59, 0x62, 0xbe, 0x5d, 0x76, 0xaa, 0x31, 0x8d, 0x17, 0x14, 0x37, 0x32, 0x37, 0x06, 0xac,
//         0xe5,
//     ];
//     let mut rng = rand_xorshift::XorShiftRng::from_seed(running_seed.try_into().unwrap());

//     let t_n_tuples = T_N_TUPLES.to_vec();
//     let message_counts = MESSAGE_COUNTS.to_vec();

//     let mut group = c.benchmark_group("BBS_Plus_Operations");

//     for message_count in message_counts {
//         for t_n_tuple in &t_n_tuples {
//             group.bench_with_input(
//                 format!(
//                     "make-live/{}-out-of-{}/{}-messages",
//                     t_n_tuple.0, t_n_tuple.1, message_count
//                 ),
//                 &(t_n_tuple, message_count),
//                 |b, &((t, n), m)| {
//                     let (_, _, pre_computation, signer_set, _) =
//                         get_bbs_setup(&mut rng, running_seed, *t, *n, m);
//                     let own_index = signer_set[0];
//                     let own_pre_computation_instance =
//                         &pre_computation[own_index - 1].pre_signatures[0];

//                     b.iter(|| {
//                         LivePreSignature::from_presignature(
//                             own_index,
//                             &signer_set,
//                             own_pre_computation_instance,
//                         )
//                     });
//                 },
//             );

//             group.bench_with_input(
//                 format!(
//                     "threshold-sign/{}-out-of-{}/{}-messages",
//                     t_n_tuple.0, t_n_tuple.1, message_count
//                 ),
//                 &(t_n_tuple, message_count),
//                 |b, &((t, n), m)| {
//                     let (pk, _, pre_computation, signer_set, messages) =
//                         get_bbs_setup(&mut rng, running_seed, *t, *n, m);
//                     let own_index = signer_set[0];
//                     let live_pre_signature = LivePreSignature::from_presignature(
//                         own_index,
//                         &signer_set,
//                         &pre_computation[own_index - 1].pre_signatures[0],
//                     );

//                     b.iter(|| PartialThresholdSignature::new(&messages, &pk, &live_pre_signature));
//                 },
//             );

//             group.bench_with_input(
//                 format!(
//                     "reconstruct/{}-out-of-{}/{}-messages",
//                     t_n_tuple.0, t_n_tuple.1, message_count
//                 ),
//                 &(t_n_tuple, message_count),
//                 |b, &((t, n), m)| {
//                     let (pk, _, pre_computation, signer_set, messages) =
//                         get_bbs_setup(&mut rng, running_seed, *t, *n, m);

//                     let mut partial_signatures = vec![];

//                     for i_t in 0..*t {
//                         let own_index = signer_set[i_t];
//                         let live_pre_signature = LivePreSignature::from_presignature(
//                             own_index,
//                             &signer_set,
//                             &pre_computation[own_index - 1].pre_signatures[0],
//                         );
//                         let partial_threshold_signature =
//                             PartialThresholdSignature::new(&messages, &pk, &live_pre_signature);
//                         partial_signatures.push(partial_threshold_signature);
//                     }

//                     b.iter(|| ThresholdSignature::from_partial_signatures(&partial_signatures));
//                 },
//             );
//         }

//         group.bench_with_input(
//             format!("direct_sign/{}-messages", message_count),
//             &message_count,
//             |b, &m| {
//                 let (pk, sk, pre_computation, _, messages) =
//                     get_bbs_setup(&mut rng, running_seed, 3, 3, m);
//                 let e = pre_computation[0].sk_share;
//                 let s = pre_computation[1].sk_share;

//                 b.iter(|| ThresholdSignature::from_secret_key(&pk, sk, e, s, &messages));
//             },
//         );

//         group.bench_with_input(
//             format!("verify/{}-messages", message_count),
//             &message_count,
//             |b, &m| {
//                 let (pk, sk, pre_computation, _, messages) =
//                     get_bbs_setup(&mut rng, running_seed, 3, 3, m);
//                 let e = pre_computation[0].sk_share;
//                 let s = pre_computation[1].sk_share;
//                 let signature = ThresholdSignature::from_secret_key(&pk, sk, e, s, &messages);

//                 b.iter(|| signature.verify(&messages, &pk));

//                 if !signature.verify(&messages, &pk) {
//                     println!("Problem with signature verification ine valuation");
//                 }
//             },
//         );
//     }
// }

// pub fn random_curve_arithmetic_evaluation(c: &mut Criterion) {
//     //RNG
//     let seed = [
//         0x59, 0x62, 0xbe, 0x5d, 0x76, 0xaa, 0x31, 0x8d, 0x17, 0x14, 0x37, 0x32, 0x37, 0x06, 0xac,
//         0xe5,
//     ];
//     let mut rng = rand_xorshift::XorShiftRng::from_seed(seed);

//     c.bench_function("Curve_Operations/G1Addition", |b| {
//         let x = G1::random(&mut rng);
//         let y = G1::random(&mut rng);
//         b.iter(|| curve_arithmetic_benchmarking::g1_add(x, y))
//     });

//     c.bench_function("Curve_Operations/G1Multiplication", |b| {
//         let x = G1::random(&mut rng);
//         let y = Fr::random(&mut rng);
//         b.iter(|| curve_arithmetic_benchmarking::g1_mul(x, y))
//     });

//     c.bench_function("Curve_Operations/G2Addition", |b| {
//         let x = G2::random(&mut rng);
//         let y = G2::random(&mut rng);
//         b.iter(|| curve_arithmetic_benchmarking::g2_add(x, y))
//     });

//     c.bench_function("Curve_Operations/G2Multiplication", |b| {
//         let x = G2::random(&mut rng);
//         let y = Fr::random(&mut rng);
//         b.iter(|| curve_arithmetic_benchmarking::g2_mul(x, y))
//     });

//     c.bench_function("Curve_Operations/FrAddition", |b| {
//         let x = Fr::random(&mut rng);
//         let y = Fr::random(&mut rng);
//         b.iter(|| curve_arithmetic_benchmarking::fr_add(x, y))
//     });

//     c.bench_function("Curve_Operations/FrMultiplication", |b| {
//         let x = Fr::random(&mut rng);
//         let y = Fr::random(&mut rng);
//         b.iter(|| curve_arithmetic_benchmarking::fr_mul(x, y))
//     });

//     c.bench_function("Curve_Operations/FrInverse", |b| {
//         let x = Fr::random(&mut rng);
//         b.iter(|| curve_arithmetic_benchmarking::fr_inv(x))
//     });

//     c.bench_function("Curve_Operations/Pairing", |b| {
//         let x = G1::random(&mut rng);
//         let y = G2::random(&mut rng);
//         b.iter(|| curve_arithmetic_benchmarking::pair(x, y))
//     });
// }
