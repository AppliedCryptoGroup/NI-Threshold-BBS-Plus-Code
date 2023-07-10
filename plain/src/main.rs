mod fhks_bbs_plus;
mod helpers;
mod measurements;
mod precomputation_mockup;
mod tests;

use crate::tests::test_pre_computation_generation;
use crate::tests::test_whole_runs;

fn main() {
    test_pre_computation_generation::test_all_precomputation_generation();
    test_whole_runs::simple_signing();
    println!("Success!");
}
