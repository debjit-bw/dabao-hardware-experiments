//! ERC-7730 clear signing on the device.
//!
//! * [`model`]: descriptors compiled by the host (`dabao-host compile-descriptors`) from
//!   registry JSON into a compact RLP [`model::DescriptorSet`], embedded in the verifier.
//!   Named paths (`params.amountIn`, `path.[-1]`, `@.value`) are resolved to index paths at
//!   compile time, so the device never parses names or JSON.
//! * [`check`]: decode the calldata with the matched function format, collect what the user is
//!   shown, and require every effect of the simulation to be explained by it (our "expected
//!   effects" extension; ERC-7730 itself only defines display). See docs/clear-signing.md.

pub mod check;
pub mod model;

pub use check::check;

/// The descriptors compiled into the firmware (`descriptors/`, built with
/// `scripts/compile-descriptors.sh`).
pub fn builtin() -> model::DescriptorSet {
    alloy_rlp::Decodable::decode(&mut &include_bytes!("../descriptors.bin")[..]).expect("embedded descriptors")
}
