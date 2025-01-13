mod fhks_bbs_plus;
mod helpers;
mod measurements;
mod precomputation_mockup;
mod tests;

use crate::measurements::simple_measurement;
use crate::tests::test_pre_computation_generation;
use crate::tests::test_whole_runs;

fn main() {
    test_pre_computation_generation::test_all_precomputation_generation();
    test_whole_runs::simple_signing();
    simple_measurement::simple_measurement_with_coefficient_computation();
    println!("Success!");
}
