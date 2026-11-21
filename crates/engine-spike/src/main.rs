//! Engine spike: link `stateless::stateless_validation` (reth stateless block
//! validation: witness verification + revm execution) into a Xous app and time it.
//!
//! Stage 1 (this file): empty input, which is expected to fail validation; the
//! point is that the whole engine is linked, so we can measure binary size.
//! Stage 2: a real block + `ExecutionWitness` containing an ERC-20 transfer.

mod chainspec;

use std::time::Instant;

use reth_evm_ethereum::EthEvmConfig;
use stateless::StatelessInput;

fn main() {
    log_server::init_wait().unwrap();
    log::set_max_level(log::LevelFilter::Info);
    log::info!("engine-spike, PID {}", xous::process::id());

    let input = StatelessInput::default();
    let spec = chainspec::mainnet_no_alloc();
    let evm_config = EthEvmConfig::new(spec.clone());

    let start = Instant::now();
    let result = stateless::stateless_validation(input.block, input.witness, spec, evm_config);
    let elapsed = start.elapsed();

    match result {
        Ok(out) => log::info!("validation OK in {elapsed:?}: {out:?}"),
        Err(e) => log::info!("validation error in {elapsed:?} (expected for empty input): {e}"),
    }
}
