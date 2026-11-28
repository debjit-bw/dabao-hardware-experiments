//! Witness-verified simulation of one Ethereum transaction, for a memory- and
//! storage-constrained device. No Xous dependencies (builds and tests on the host).
//!
//! * [`sim::simulate`]: RLP `sim_types::SimInput` in, `sim_types::SimResult` out.
//! * [`effects::effects`]: logs + state changes -> normalised effects (filled into SimResult).
//! * [`chainspec::mainnet_no_alloc`]: mainnet fork schedule without the 690 KB genesis.

pub mod chainspec;
pub mod effects;
pub mod postcondition;
pub mod sim;
pub mod vaults;
