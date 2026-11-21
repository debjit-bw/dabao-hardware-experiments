//! Which revm spec the device picks per chain and time (guards against stale fork schedules).
use xous_evm::chainspec::spec_for;

#[test]
fn print_specs() {
    for (name, chain, ts, n) in [("sepolia now", 11155111u64, 1_795_275_240u64, 12_182_729u64), ("mainnet now", 1, 1_795_275_240, 26_464_100)] {
        let spec = spec_for(chain).unwrap();
        let id = alloy_evm::spec_by_timestamp_and_block_number(&*spec, ts, n);
        eprintln!("{name}: {id:?}");
    }
}
