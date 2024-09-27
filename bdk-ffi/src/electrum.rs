use crate::bitcoin::Transaction;
use crate::error::{ElectrumError};
use crate::types::{Update};
use crate::types::{FullScanRequest, SyncRequest};

use bdk_core::spk_client::FullScanRequest as BdkFullScanRequest;
use bdk_core::spk_client::FullScanResult as BdkFullScanResult;
use bdk_core::spk_client::SyncRequest as BdkSyncRequest;
use bdk_core::spk_client::SyncResult as BdkSyncResult;
use bdk_electrum::BdkElectrumClient as BdkBdkElectrumClient;
use bdk_wallet::bitcoin::Transaction as BdkTransaction;
use bdk_wallet::KeychainKind;
use bdk_wallet::Update as BdkUpdate;

use std::collections::BTreeMap;
use std::ops::Deref;
use std::str::FromStr;
use std::sync::Arc;
use bdk_bitcoind_rpc::bitcoincore_rpc::bitcoin::Txid;

// NOTE: We are keeping our naming convention where the alias of the inner type is the Rust type
//       prefixed with `Bdk`. In this case the inner type is `BdkElectrumClient`, so the alias is
//       funnily enough named `BdkBdkElectrumClient`.
pub struct ElectrumClient(BdkBdkElectrumClient<bdk_electrum::electrum_client::Client>);

impl ElectrumClient {
    pub fn new(url: String) -> Result<Self, ElectrumError> {
        let inner_client: bdk_electrum::electrum_client::Client =
            bdk_electrum::electrum_client::Client::new(url.as_str())?;
        let client = BdkBdkElectrumClient::new(inner_client);
        Ok(Self(client))
    }

    pub fn full_scan(
        &self,
        request: Arc<FullScanRequest>,
        stop_gap: u64,
        batch_size: u64,
        fetch_prev_txouts: bool,
    ) -> Result<Arc<Update>, ElectrumError> {
        // using option and take is not ideal but the only way to take full ownership of the request
        let request: BdkFullScanRequest<KeychainKind> = request
            .0
            .lock()
            .unwrap()
            .take()
            .ok_or(ElectrumError::RequestAlreadyConsumed)?;

        let full_scan_result: BdkFullScanResult<KeychainKind> = self.0.full_scan(
            request,
            stop_gap as usize,
            batch_size as usize,
            fetch_prev_txouts,
        )?;

        let update = BdkUpdate {
            last_active_indices: full_scan_result.last_active_indices,
            tx_update: full_scan_result.tx_update,
            chain: full_scan_result.chain_update,
        };

        Ok(Arc::new(Update(update)))
    }

    pub fn sync(
        &self,
        request: Arc<SyncRequest>,
        batch_size: u64,
        fetch_prev_txouts: bool,
    ) -> Result<Arc<Update>, ElectrumError> {
        // using option and take is not ideal but the only way to take full ownership of the request
        let request: BdkSyncRequest<(KeychainKind, u32)> = request
            .0
            .lock()
            .unwrap()
            .take()
            .ok_or(ElectrumError::RequestAlreadyConsumed)?;

        let sync_result: BdkSyncResult =
            self.0
                .sync(request, batch_size as usize, fetch_prev_txouts)?;

        let update = BdkUpdate {
            last_active_indices: BTreeMap::default(),
            tx_update: sync_result.tx_update,
            chain: sync_result.chain_update,
        };

        Ok(Arc::new(Update(update)))
    }

    pub fn broadcast(&self, transaction: &Transaction) -> Result<String, ElectrumError> {
        let bdk_transaction: BdkTransaction = transaction.into();
        self.0
            .transaction_broadcast(&bdk_transaction)
            .map_err(ElectrumError::from)
            .map(|txid| txid.to_string())
    }

    pub fn get_tx(&self, txid: String) -> Result<Arc<Transaction>, ElectrumError> {
        let txid = Txid::from_str(&txid).map_err(|e| ElectrumError::Hex { error_message: e.to_string() })?;
        let tx = self.0.fetch_tx(txid).map_err(ElectrumError::from)?.deref().clone();
        Ok(Arc::new(tx.into()))
    }
    //
    // pub fn get_canonical_tx(&self, txid: String) -> Result<Arc<CanonicalTx>, ElectrumError> {
    //     let tx = self.get_tx(txid.clone())?;
    //
    //     let spk = tx.output().first().expect("must be one output").clone();
    //     let his = self.0
    //         .inner.script_get_history(spk.script_pubkey.0.as_script())?;
    //
    //     let height = his.iter().find(|e| e.tx_hash.to_string() == txid).unwrap().height;
    //     let block = self.0.inner.block_header(height as usize)?;
    //
    //     let tx = if height != 0 {
    //         CanonicalTx {
    //             transaction: tx,
    //             chain_position: ChainPosition::Confirmed {
    //                 confirmation_block_time: ConfirmationBlockTime {
    //                     block_id: BlockId { height: height as u32, hash: block.block_hash().to_string() },
    //                     confirmation_time: block.time as u64,
    //                 }
    //             },
    //         }
    //     } else {
    //         CanonicalTx {
    //             transaction: tx,
    //             chain_position: ChainPosition::Unconfirmed { timestamp: block.time as u64 },
    //         }
    //     };
    //     Ok(Arc::new(tx.into()))
    // }
    //
    // pub fn get_output_status(&self, txid: String, index: u64) -> Result<OutputStatus, ElectrumError> {
    //     // let txid = Txid::from_str(&txid).map_err(|e| ElectrumError::Parsing { error_message: e.to_string() })?;
    //     let tx = self.get_tx(txid)?;
    //     let spk = tx.output()[index as usize].clone();
    //     let utxo = self.0.inner
    //         .script_list_unspent(spk.script_pubkey.0.as_script())?
    //         .iter().find(|e| e.tx_hash.to_string() == txid && e.tx_pos == index as usize);
    //
    //     let Some(utxo) = utxo else {
    //         //
    //         return Ok(OutputStatus {
    //             spent: true,
    //             txid: None,
    //             vin: None,
    //             status: None,
    //         })
    //     };
    //
    //     Ok(OutputStatus {
    //         spent: false,
    //         txid: None,
    //         vin: None,
    //         status: None,
    //     })
    // }
}
