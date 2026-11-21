//! Witness-verified simulation of one Ethereum transaction, for a memory- and
//! storage-constrained device. No Xous dependencies (builds and tests on the host).
//!
//! * [`sim::simulate`]: RLP `sim_types::SimInput` in, `sim_types::SimResult` out.
//! * [`chainspec::mainnet_no_alloc`]: mainnet fork schedule without the 690 KB genesis.

pub mod chainspec;
pub mod sim;
