use crate::fhks_bbs_plus::keys::PublicKey;
use crate::fhks_bbs_plus::partial_threshold_signature::PartialThresholdSignature;
use crate::fhks_bbs_plus::precomputation::LivePreSignature;
use crate::fhks_bbs_plus::threshold_signature::ThresholdSignature;
use crate::helpers::rng;
use crate::precomputation_mockup::precomputation_generation;
use ff_zeroize::Field;
use pairing_plus::bls12_381::Fr;
use std::time::Instant;

pub fn simple_measurement_with_coefficient_computation() {
    let seed_presignatures = [
        0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06, 0xbc,
        0xe5,
    ];
    let seed_messages = [
        0x59, 0x62, 0xbe, 0x5d, 0x76, 0xaa, 0x31, 0x8d, 0x17, 0x14, 0x37, 0x32, 0x37, 0x06, 0xac,
        0xe5,
    ];
    let seed_keys = [
        0x59, 0x62, 0xaa, 0x5d, 0x76, 0xaa, 0xbb, 0x8d, 0x17, 0x14, 0x37, 0x32, 0x37, 0xcc, 0xac,
        0xe5,
    ];

    let mut make_live_durations = vec![];
    let mut threshold_sign_durations = vec![];
    let mut reconstruct_durations = vec![];
    let mut verify_durations = vec![];
    let mut direct_sign_durations = vec![];

    let t = 8; //Security threshold (t-ouf-of-n)
    let n = 10; //Number of servers
    let k = 3; //Presignatures to create
    let message_count = 1; //number of messages to be created
    let indices = vec![
        vec![1, 4, 3, 5, 7, 6, 8, 10],
        vec![1, 3, 8, 9, 4, 10, 5, 2],
        vec![2, 4, 5, 1, 3, 6, 7, 8],
    ];
    let messages = rng::get_random_messages_from_seed(seed_messages, message_count, k);
    let direct_e_s = rng::get_random_messages_from_seed(seed_keys, 2, k);

    let (sk, pre_computation) =
        precomputation_generation::generate_pp_precomputation(seed_presignatures, t, n, k);

    let pk = PublicKey::generate(seed_keys, sk, message_count);

    for i_k in 0..k {
        let mut partial_signatures = vec![];

        for i_t in 0..t {
            let own_index = indices[i_k][i_t];
            let start = Instant::now();
            let live_pre_signature = LivePreSignature::from_presignature(
                own_index,
                &indices[i_k],
                &pre_computation[own_index - 1].pre_signatures[i_k],
            );
            make_live_durations.push(start.elapsed());
            let start = Instant::now();
            let partial_threshold_signature =
                PartialThresholdSignature::new(&messages[i_k], &pk, &live_pre_signature);
            threshold_sign_durations.push(start.elapsed());
            partial_signatures.push(partial_threshold_signature);
        }

        let start = Instant::now();
        let signature = ThresholdSignature::from_partial_signatures(&partial_signatures);
        reconstruct_durations.push(start.elapsed());

        let start = Instant::now();
        ThresholdSignature::verify(&signature, &messages[i_k], &pk);
        verify_durations.push(start.elapsed());

        assert!(
            ThresholdSignature::verify(&signature, &messages[i_k], &pk),
            "Signature verification failed"
        );

        let start = Instant::now();
        let signature = ThresholdSignature::from_secret_key(
            &pk,
            sk,
            direct_e_s[i_k][0],
            direct_e_s[i_k][1],
            &messages[i_k],
        );
        direct_sign_durations.push(start.elapsed());

        let start = Instant::now();
        ThresholdSignature::verify(&signature, &messages[i_k], &pk);
        verify_durations.push(start.elapsed());

        assert!(
            ThresholdSignature::verify(&signature, &messages[i_k], &pk),
            "Directly generated signature verification failed"
        );
    }

    println!("make_live_durations: {:?}", make_live_durations);
    println!("threshold_sign_durations: {:?}", threshold_sign_durations);
    println!("reconstruct_durations: {:?}", reconstruct_durations);
    println!("verify_durations: {:?}", verify_durations);
    println!("direct_sign_durations: {:?}", direct_sign_durations);
}
