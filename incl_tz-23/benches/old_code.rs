// //***********************************
// //****** Just tests to check behavior

// pub fn curve_arithmetic_evaluation(c: &mut Criterion) {
//     //RNG
//     let seed = [
//         0x59, 0x62, 0xbe, 0x5d, 0x76, 0xaa, 0x31, 0x8d, 0x17, 0x14, 0x37, 0x32, 0x37, 0x06, 0xac,
//         0xe5,
//     ];
//     let mut rng = rand_xorshift::XorShiftRng::from_seed(seed);

//     let mut group = c.benchmark_group("Curve_Operations");
//     for i in 1..4 {
//         let x_1_in = G1::random(&mut rng);
//         let y_1_in = G1::random(&mut rng);
//         let x_2_in = G2::random(&mut rng);
//         let y_2_in = G2::random(&mut rng);
//         let p_in = Fr::random(&mut rng);
//         let q_in = Fr::random(&mut rng);
//         group.bench_with_input(
//             "Curve_Operations/G1Addition/Random-Values-".to_owned() + &i.to_string(),
//             &(x_1_in, y_1_in),
//             |b, &(x_1, y_1)| {
//                 b.iter(|| curve_arithmetic_benchmarking::g1_add(x_1, y_1));
//             },
//         );
//         group.bench_with_input(
//             "Curve_Operations/G1Multiplication/Random-Values-".to_owned() + &i.to_string(),
//             &(x_1_in, p_in),
//             |b, &(x_1, p)| {
//                 b.iter(|| curve_arithmetic_benchmarking::g1_mul(x_1, p));
//             },
//         );
//         group.bench_with_input(
//             "Curve_Operations/G2Addition/Random-Values-".to_owned() + &i.to_string(),
//             &(x_2_in, y_2_in),
//             |b, &(x_2, y_2)| {
//                 b.iter(|| curve_arithmetic_benchmarking::g2_add(x_2, y_2));
//             },
//         );
//         group.bench_with_input(
//             "Curve_Operations/G2Multiplication/Random-Values-".to_owned() + &i.to_string(),
//             &(x_2_in, p_in),
//             |b, &(x_2, p)| {
//                 b.iter(|| curve_arithmetic_benchmarking::g2_mul(x_2, p));
//             },
//         );
//         group.bench_with_input(
//             "Curve_Operations/FrAddition/Random-Values-".to_owned() + &i.to_string(),
//             &(p_in, q_in),
//             |b, &(p, q)| {
//                 b.iter(|| curve_arithmetic_benchmarking::fr_add(p, q));
//             },
//         );
//         group.bench_with_input(
//             "Curve_Operations/FrMultiplication/Random-Values-".to_owned() + &i.to_string(),
//             &(p_in, q_in),
//             |b, &(p, q)| {
//                 b.iter(|| curve_arithmetic_benchmarking::fr_mul(p, q));
//             },
//         );
//         group.bench_with_input(
//             "Curve_Operations/FrInverse/Random-Values-".to_owned() + &i.to_string(),
//             &p_in,
//             |b, &p| {
//                 b.iter(|| curve_arithmetic_benchmarking::fr_inv(p));
//             },
//         );
//         group.bench_with_input(
//             "Curve_Operations/Pairing/Random-Values-".to_owned() + &i.to_string(),
//             &(x_1_in, x_2_in),
//             |b, &(x_1, x_2)| {
//                 b.iter(|| curve_arithmetic_benchmarking::pair(x_1, x_2));
//             },
//         );
//     }
//     group.finish();
// }

// //This is just to test the different ways of writing a test
// pub fn test_behavior(c: &mut Criterion) {
//     //RNG
//     let seed = [
//         0x59, 0x62, 0xbe, 0x5d, 0x76, 0xaa, 0x31, 0x8d, 0x17, 0x14, 0x37, 0x32, 0x37, 0x06, 0xac,
//         0xe5,
//     ];
//     let mut rng = rand_xorshift::XorShiftRng::from_seed(seed);

//     //println!("[1:] This is executed just once?"); //Yes

//     let mut group = c.benchmark_group("Curve_Operations");
//     for i in 1..2 {
//         let x_1_in = G1::random(&mut rng);
//         let y_1_in = G1::random(&mut rng);

//         //TODO: What is the difference between writing the setup before the b.iter or using b.iter_batched?

//         group.bench_with_input("Test", &(x_1_in, y_1_in), |b, &(x_1, y_1)| {
//             //thread::sleep(time::Duration::from_secs(1)); // Is this measured? //No
//             //println!("[2:] This is executed just once?"); //3seconds warmup + 10 samples
//             b.iter(|| curve_arithmetic_benchmarking::g1_add(x_1, y_1));
//         });

//         group.bench_with_input("Test-2", &(x_1_in, y_1_in), |b, &(x_1, y_1)| {
//             b.iter_batched(
//                 || {
//                     let x = G1::random(&mut rng);
//                     let y = G1::random(&mut rng);
//                     //thread::sleep(time::Duration::from_secs(1)); // Is this measured? //No
//                     (x, y)
//                 },
//                 |(x, y)| curve_arithmetic_benchmarking::g1_add(x, y),
//                 BatchSize::SmallInput,
//             );
//         });

//         group.bench_with_input("Test-3", &(x_1_in, y_1_in), |b, &(x_1, y_1)| {
//             b.iter(|| {
//                 //thread::sleep(time::Duration::from_secs(1)); // Is this measured? //Yes
//                 curve_arithmetic_benchmarking::g1_add(x_1, y_1)
//             });
//         });
//     }
//     group.finish();
// }

// //How to get a line chart?!

// fn from_elem_2(c: &mut Criterion) {
//     static KB: usize = 1024;

//     let mut group = c.benchmark_group("Do I get a line chart? - 1"); //Yes
//     for size in [KB, 2 * KB, 4 * KB, 8 * KB, 16 * KB].iter() {
//         group.throughput(Throughput::Bytes(*size as u64));
//         group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, &size| {
//             b.iter(|| (0..size).collect::<Vec<usize>>());
//         });
//     }
//     group.finish();
// }

// fn from_elem_3(c: &mut Criterion) {
//     static KB: usize = 1024;

//     let mut group = c.benchmark_group("Do I get a line chart? - 2"); // Yes
//     for size in [KB, 2 * KB, 4 * KB, 8 * KB, 16 * KB].iter() {
//         //group.throughput(Throughput::Bytes(*size as u64));
//         group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, &size| {
//             b.iter(|| (0..size).collect::<Vec<usize>>());
//         });
//     }
//     group.finish();
// }

// fn from_elem(c: &mut Criterion) {
//     static KB: usize = 1024;

//     let mut group = c.benchmark_group("Do I get a line chart? - 3");
//     for size in [KB, 2 * KB, 4 * KB, 8 * KB].iter() {
//         //group.throughput(Throughput::Bytes(*size as u64));
//         group.bench_with_input(format!("Do I get a line chart? - 3/{}", size), size, |b, &size| {
//             b.iter(|| (0..size).collect::<Vec<usize>>());
//         });
//     }
//     group.finish();
// }

// //This works!
// pub fn bbs_make_live_2_2(c: &mut Criterion) {
//     let running_seed: &mut [u8] = &mut [
//         0x59, 0x62, 0xbe, 0x5d, 0x76, 0xaa, 0x31, 0x8d, 0x17, 0x14, 0x37, 0x32, 0x37, 0x06, 0xac,
//         0xe5,
//     ];
//     let mut rng = rand_xorshift::XorShiftRng::from_seed(running_seed.try_into().unwrap());
//     let message_counts = MESSAGE_COUNTS.to_vec();

//     let mut group = c.benchmark_group("BBS_Plus_Operations/make_live/2-out-of-2");

//     for message_count in message_counts {
//         let t_n_tuple = (2,2);
//         group.bench_with_input(
//                 BenchmarkId::from_parameter(message_count),
//                 &(t_n_tuple, message_count),
//                 |b, &((t, n), m)| {
//                     let (_, _, pre_computation, signer_set, _) =
//                         get_bbs_setup(&mut rng, running_seed, t, n, m);
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
//     }
// }
