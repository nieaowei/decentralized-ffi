use crate::bitcoin::{Address, Amount, OutPoint, Script, Transaction, TxOut};
use crate::error::RequestBuilderError;


use bdk_core::spk_client::SyncItem;
use bdk_wallet::bitcoin::Transaction as BdkTransaction;
use bdk_wallet::chain::spk_client::FullScanRequest as BdkFullScanRequest;
use bdk_wallet::chain::spk_client::FullScanRequestBuilder as BdkFullScanRequestBuilder;
use bdk_wallet::chain::spk_client::SyncRequest as BdkSyncRequest;
use bdk_wallet::chain::spk_client::SyncRequestBuilder as BdkSyncRequestBuilder;
use bdk_wallet::chain::tx_graph::CanonicalTx as BdkCanonicalTx;
use bdk_wallet::chain::{ChainPosition as BdkChainPosition, ConfirmationBlockTime as BdkConfirmationBlockTime, ConfirmationTime as BdkConfirmationTime};
use bdk_wallet::AddressInfo as BdkAddressInfo;
use bdk_wallet::Balance as BdkBalance;
use bdk_wallet::LocalOutput as BdkLocalOutput;
use bdk_wallet::Update as BdkUpdate;
use bdk_wallet::KeychainKind as BdkKeychainKind;

use std::sync::{Arc, Mutex};
use bdk_wallet::bitcoin::consensus::encode::serialize_hex;
use crate::wallet::KeychainKind;

#[derive(uniffi::Enum, Debug, Clone, PartialEq, Eq, Hash)]
pub enum ChainPosition {
    Confirmed {
        confirmation_block_time: ConfirmationBlockTime,
    },
    Unconfirmed {
        timestamp: u64,
    },
}

#[derive(uniffi::Record, Debug, Clone, PartialEq, Eq, Hash)]
pub struct ConfirmationBlockTime {
    pub block_id: BlockId,
    pub confirmation_time: u64,
}

#[derive(uniffi::Record, Debug, Clone, PartialEq, Eq, Hash)]
pub struct BlockId {
    pub height: u32,
    pub hash: String,
}

#[derive(uniffi::Record, Debug, Clone, PartialEq, Eq, Hash)]
pub struct CanonicalTx {
    pub transaction: Arc<Transaction>,
    pub chain_position: ChainPosition,
}

impl From<BdkCanonicalTx<'_, Arc<BdkTransaction>, BdkConfirmationBlockTime>> for CanonicalTx {
    fn from(tx: BdkCanonicalTx<'_, Arc<BdkTransaction>, BdkConfirmationBlockTime>) -> Self {
        let chain_position = match tx.chain_position {
            BdkChainPosition::Confirmed(anchor) => {
                let block_id = BlockId {
                    height: anchor.block_id.height,
                    hash: anchor.block_id.hash.to_string(),
                };
                ChainPosition::Confirmed {
                    confirmation_block_time: ConfirmationBlockTime {
                        block_id,
                        confirmation_time: anchor.confirmation_time,
                    },
                }
            }
            BdkChainPosition::Unconfirmed(timestamp) => ChainPosition::Unconfirmed { timestamp },
        };

        CanonicalTx {
            transaction: Arc::new(Transaction::from(tx.tx_node.tx.as_ref().clone())),
            chain_position,
        }
    }
}

#[derive(uniffi::Record, Debug, Clone, PartialEq, Eq, Hash)]
pub struct ScriptAmount {
    pub script: Arc<Script>,
    pub amount: Arc<Amount>,
}

#[derive(uniffi::Record, Debug, Clone, PartialEq, Eq, Hash)]
pub struct AddressInfo {
    pub index: u32,
    pub address: Arc<Address>,
    pub keychain: KeychainKind,
}

impl From<BdkAddressInfo> for AddressInfo {
    fn from(address_info: BdkAddressInfo) -> Self {
        AddressInfo {
            index: address_info.index,
            address: Arc::new(address_info.address.into()),
            keychain: address_info.keychain.into(),
        }
    }
}

#[derive(uniffi::Record, Debug, Clone, PartialEq, Eq, Hash)]
pub struct Balance {
    pub immature: Arc<Amount>,
    pub trusted_pending: Arc<Amount>,
    pub untrusted_pending: Arc<Amount>,
    pub confirmed: Arc<Amount>,
    pub trusted_spendable: Arc<Amount>,
    pub total: Arc<Amount>,
}

impl From<BdkBalance> for Balance {
    fn from(bdk_balance: BdkBalance) -> Self {
        Balance {
            immature: Arc::new(bdk_balance.immature.into()),
            trusted_pending: Arc::new(bdk_balance.trusted_pending.into()),
            untrusted_pending: Arc::new(bdk_balance.untrusted_pending.into()),
            confirmed: Arc::new(bdk_balance.confirmed.into()),
            trusted_spendable: Arc::new(bdk_balance.trusted_spendable().into()),
            total: Arc::new(bdk_balance.total().into()),
        }
    }
}

#[derive(uniffi::Record, Debug, Clone, PartialEq, Eq, Hash)]
pub struct LocalOutput {
    pub outpoint: OutPoint,
    pub txout: TxOut,
    pub keychain: KeychainKind,
    pub is_spent: bool,
    pub confirmation_time: ConfirmationTime,
}

impl From<BdkLocalOutput> for LocalOutput {
    fn from(local_utxo: BdkLocalOutput) -> Self {
        let serialize_hex = serialize_hex(&local_utxo.txout);
        LocalOutput {
            outpoint: OutPoint {
                txid: Arc::new(local_utxo.outpoint.txid.into()),
                vout: local_utxo.outpoint.vout,
            },
            txout: TxOut {
                value: Arc::new(Amount(local_utxo.txout.value)),
                script_pubkey: Arc::new(Script(local_utxo.txout.script_pubkey)),
                serialize_hex: serialize_hex,
            },
            keychain: local_utxo.keychain.into(),
            is_spent: local_utxo.is_spent,
            confirmation_time: local_utxo.confirmation_time.into(),
        }
    }
}

#[derive(uniffi::Enum, Debug, Clone, PartialEq, Eq, Hash)]
pub enum ConfirmationTime {
    Confirmed {
        height: u32,
        time: u64,
    },
    Unconfirmed {
        /// The last-seen timestamp in unix seconds.
        last_seen: u64,
    },
}

impl From<BdkConfirmationTime> for ConfirmationTime {
    fn from(value: BdkConfirmationTime) -> Self {
        match value {
            BdkConfirmationTime::Confirmed { height, time } => {
                ConfirmationTime::Confirmed { height, time }
            }
            BdkConfirmationTime::Unconfirmed { last_seen } => {
                ConfirmationTime::Unconfirmed { last_seen }
            }
        }
    }
}

// Callback for the FullScanRequest
#[uniffi::export]
pub trait FullScanScriptInspector: Sync + Send {
    fn inspect(&self, keychain: KeychainKind, index: u32, script: Arc<Script>);
}

// Callback for the SyncRequest
#[uniffi::export]
pub trait SyncScriptInspector: Sync + Send {
    fn inspect(&self, script: Arc<Script>, total: u64);
}

#[derive(uniffi::Object)]
pub struct FullScanRequestBuilder(
    pub(crate) Mutex<Option<BdkFullScanRequestBuilder<BdkKeychainKind>>>,
);

#[derive(uniffi::Object)]
pub struct SyncRequestBuilder(pub(crate) Mutex<Option<BdkSyncRequestBuilder<(BdkKeychainKind, u32)>>>);

#[derive(uniffi::Object)]
pub struct FullScanRequest(pub(crate) Mutex<Option<BdkFullScanRequest<BdkKeychainKind>>>);
#[derive(uniffi::Object)]
pub struct SyncRequest(pub(crate) Mutex<Option<BdkSyncRequest<(BdkKeychainKind, u32)>>>);

#[uniffi::export]
impl SyncRequestBuilder {
    pub fn inspect_spks(
        &self,
        inspector: Arc<dyn SyncScriptInspector>,
    ) -> Result<Arc<Self>, RequestBuilderError> {
        let guard = self
            .0
            .lock()
            .unwrap()
            .take()
            .ok_or(RequestBuilderError::RequestAlreadyConsumed)?;
        let sync_request_builder = guard.inspect({
            move |script, progress| {
                if let SyncItem::Spk(_, spk) = script {
                    inspector.inspect(Arc::new(Script(spk.to_owned())), progress.total() as u64)
                }
            }
        });
        Ok(Arc::new(SyncRequestBuilder(Mutex::new(Some(
            sync_request_builder,
        )))))
    }

    pub fn build(&self) -> Result<Arc<SyncRequest>, RequestBuilderError> {
        let guard = self
            .0
            .lock()
            .unwrap()
            .take()
            .ok_or(RequestBuilderError::RequestAlreadyConsumed)?;
        Ok(Arc::new(SyncRequest(Mutex::new(Some(guard.build())))))
    }
}

#[uniffi::export]
impl FullScanRequestBuilder {
    pub fn inspect_spks_for_all_keychains(
        &self,
        inspector: Arc<dyn FullScanScriptInspector>,
    ) -> Result<Arc<Self>, RequestBuilderError> {
        let guard = self
            .0
            .lock()
            .unwrap()
            .take()
            .ok_or(RequestBuilderError::RequestAlreadyConsumed)?;
        let full_scan_request_builder = guard.inspect(move |keychain, index, script| {
            inspector.inspect(keychain.into(), index, Arc::new(Script(script.to_owned())))
        });
        Ok(Arc::new(FullScanRequestBuilder(Mutex::new(Some(
            full_scan_request_builder,
        )))))
    }

    pub fn build(&self) -> Result<Arc<FullScanRequest>, RequestBuilderError> {
        let guard = self
            .0
            .lock()
            .unwrap()
            .take()
            .ok_or(RequestBuilderError::RequestAlreadyConsumed)?;
        Ok(Arc::new(FullScanRequest(Mutex::new(Some(guard.build())))))
    }
}

#[derive(uniffi::Object)]
pub struct Update(pub(crate) BdkUpdate);

#[derive(uniffi::Record, Debug, Clone, PartialEq, Eq, Hash)]
pub struct SentAndReceivedValues {
    pub sent: Arc<Amount>,
    pub received: Arc<Amount>,
}

#[derive(Clone, Debug, uniffi::Enum)]
pub enum RbfValue {
    Default,
    Value(u32),
}


#[derive(uniffi::Record, Debug, Clone, PartialEq, Eq, Hash)]
pub struct TransactionAndLastSeen {
    pub tx: Arc<Transaction>,
    pub last_seen: u64,
}

#[derive(uniffi::Enum, Debug, Clone, PartialEq, Eq, Hash)]
pub enum TxOrdering {
    Shuffle,
    Untouched,
}

