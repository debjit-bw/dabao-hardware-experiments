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

use alloy_consensus::constants::MAINNET_GENESIS_HASH;
use alloy_eips::{eip6110::MAINNET_DEPOSIT_CONTRACT_ADDRESS, eip7840::BlobParams, eip7892::BlobScheduleBlobParams};
use alloy_genesis::Genesis;
use alloy_primitives::{b256, U256};
use reth_chainspec::{
    make_genesis_header, mainnet, BaseFeeParams, BaseFeeParamsKind, Chain, ChainHardforks, ChainSpec,
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
