//! Mainnet chain spec without the genesis allocation.
//!
//! `reth_chainspec::MAINNET` embeds `mainnet.json` (~690 KB of genesis alloc)
//! plus the serde_json code to parse it at first use. Stateless validation of
//! a recent block never reads the genesis state, only the fork schedule, the
//! blob schedule and a few constants, so this is `MAINNET` with an empty
//! genesis. The genesis *hash* is kept (hard-coded) so the spec still
//! identifies as mainnet.
//!
//! Mirrors `reth_chainspec::spec::MAINNET` at reth rev db702b5; keep in sync
//! if the reth pin moves.

use std::sync::Arc;

use alloy_consensus::constants::{MAINNET_GENESIS_HASH, SEPOLIA_GENESIS_HASH};
use alloy_eips::{eip6110::MAINNET_DEPOSIT_CONTRACT_ADDRESS, eip7840::BlobParams, eip7892::BlobScheduleBlobParams};
use alloy_genesis::Genesis;
use alloy_primitives::{address, b256, U256};
use reth_chainspec::{
    make_genesis_header, mainnet, sepolia, BaseFeeParams, BaseFeeParamsKind, Chain, ChainHardforks, ChainSpec,
    DepositContract, EthereumHardfork, MAINNET_PRUNE_DELETE_LIMIT,
};
use reth_primitives_traits::SealedHeader;

pub fn mainnet_no_alloc() -> Arc<ChainSpec> {
    let mut genesis = Genesis::default();
    genesis.config.chain_id = 1;
    genesis.config.dao_fork_support = true;
    let hardforks: ChainHardforks = EthereumHardfork::mainnet().into();
    Arc::new(ChainSpec {
        chain: Chain::mainnet(),
        genesis_header: SealedHeader::new(make_genesis_header(&genesis, &hardforks), MAINNET_GENESIS_HASH),
        genesis,
        paris_block_and_final_difficulty: Some((
            mainnet::MAINNET_PARIS_BLOCK,
            U256::from(58_750_003_716_598_352_816_469u128),
        )),
        hardforks,
        // reth_chainspec's MAINNET_DEPOSIT_CONTRACT is pub(crate); same values.
        deposit_contract: Some(DepositContract::new(
            MAINNET_DEPOSIT_CONTRACT_ADDRESS,
            11052984,
            b256!("0x649bbc62d0e31342afea4e5cd82d4049e7e1ee912fc0889aa790803be39038c5"),
        )),
        base_fee_params: BaseFeeParamsKind::Constant(BaseFeeParams::ethereum()),
        prune_delete_limit: MAINNET_PRUNE_DELETE_LIMIT,
        blob_params: BlobScheduleBlobParams::default().with_scheduled([
            (mainnet::MAINNET_BPO1_TIMESTAMP, BlobParams::bpo1()),
            (mainnet::MAINNET_BPO2_TIMESTAMP, BlobParams::bpo2()),
        ]),
    })
}

/// Sepolia, likewise without the genesis allocation. Mirrors `reth_chainspec::spec::SEPOLIA` at
/// reth rev db702b5.
pub fn sepolia_no_alloc() -> Arc<ChainSpec> {
    let mut genesis = Genesis::default();
    genesis.config.chain_id = 11155111;
    genesis.config.dao_fork_support = true;
    let hardforks: ChainHardforks = EthereumHardfork::sepolia().into();
    Arc::new(ChainSpec {
        chain: Chain::sepolia(),
        genesis_header: SealedHeader::new(make_genesis_header(&genesis, &hardforks), SEPOLIA_GENESIS_HASH),
        genesis,
        paris_block_and_final_difficulty: Some((sepolia::SEPOLIA_PARIS_BLOCK, U256::from(17_000_018_015_853_232u128))),
        hardforks,
        deposit_contract: Some(DepositContract::new(
            address!("0x7f02c3e3c98b133055b8b348b2ac625669ed295d"),
            1273020,
            b256!("0x649bbc62d0e31342afea4e5cd82d4049e7e1ee912fc0889aa790803be39038c5"),
        )),
        base_fee_params: BaseFeeParamsKind::Constant(BaseFeeParams::ethereum()),
        prune_delete_limit: 10000,
        blob_params: BlobScheduleBlobParams::default().with_scheduled([
            (sepolia::SEPOLIA_BPO1_TIMESTAMP, BlobParams::bpo1()),
            (sepolia::SEPOLIA_BPO2_TIMESTAMP, BlobParams::bpo2()),
        ]),
    })
}

/// The chain spec for `chain_id`, if supported (mainnet, Sepolia).
pub fn spec_for(chain_id: u64) -> Option<Arc<ChainSpec>> {
    match chain_id {
        1 => Some(mainnet_no_alloc()),
        11155111 => Some(sepolia_no_alloc()),
        _ => None,
    }
}
