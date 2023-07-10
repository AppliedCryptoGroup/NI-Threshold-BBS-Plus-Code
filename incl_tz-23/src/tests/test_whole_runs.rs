use crate::fhks_bbs_plus::keys::PublicKey;
use crate::fhks_bbs_plus::partial_threshold_signature::PartialThresholdSignature;
use crate::fhks_bbs_plus::precomputation::LivePreSignature;
use crate::fhks_bbs_plus::threshold_signature::ThresholdSignature;
use crate::helpers::rng;
use crate::precomputation_mockup::precomputation_generation;

pub fn simple_signing() {
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

    let t = 3; //Security threshold (t-ouf-of-n)
    let n = 6; //Number of servers
    let k = 3; //Presignatures to create
    let message_count = 5; //number of messages to be created
    let indices = vec![vec![1, 3, 5], vec![1, 5, 2], vec![2, 4, 5]];
    let messages = rng::get_random_messages_from_seed(seed_messages, message_count, k);

    let (sk, pre_computation) =
        precomputation_generation::generate_pp_precomputation(seed_presignatures, t, n, k);

    //Only to test that it can fail
    //let sk = messages[0][3];

    let pk = PublicKey::generate(seed_keys, sk, message_count);

    //Only to test that it can fail
    //pre_computation[0].pre_signatures[0].a_share = messages[0][3];

    for i_k in 0..k {
        let signature = ThresholdSignature::from_partial_signatures(
            &(0..t)
                .collect::<Vec<usize>>()
                .iter()
                .map(|&i_t| {
                    let own_index = indices[i_k][i_t];
                    let x = PartialThresholdSignature::new(
                        &messages[i_k],
                        &pk,
                        &LivePreSignature::from_presignature(
                            own_index,
                            &indices[i_k],
                            &pre_computation[own_index - 1].pre_signatures[i_k],
                        ),
                    );
                    x
                })
                .collect::<Vec<PartialThresholdSignature>>(),
        );

        assert!(
            ThresholdSignature::verify(&signature, &messages[i_k], &pk),
            "Signature verification failed"
        );
    }
}
