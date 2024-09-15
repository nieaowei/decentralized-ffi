use crate::bitcoin::{BlockHash, Transaction};
use crate::error::EsploraError;
use crate::types::Update;
use crate::types::{FullScanRequest, SyncRequest};

use bitcoin_ffi::Script;

use bdk_esplora::esplora_client::{BlockingClient, Builder};
use bdk_esplora::EsploraExt;
use bdk_esplora::esplora_client::Tx as EsploraTx;
use bdk_esplora::esplora_client::Vin as EsploraVin;
use bdk_esplora::esplora_client::Vout as EsploraVout;
use bdk_esplora::esplora_client::TxStatus as EsploraTxStatus;
use bdk_esplora::esplora_client::PrevOut as EsploraPrevOut;


use bdk_wallet::bitcoin::{Transaction as BdkTransaction, Txid};
use bdk_wallet::chain::spk_client::FullScanRequest as BdkFullScanRequest;
use bdk_wallet::chain::spk_client::FullScanResult as BdkFullScanResult;
use bdk_wallet::chain::spk_client::SyncRequest as BdkSyncRequest;
use bdk_wallet::chain::spk_client::SyncResult as BdkSyncResult;
use bdk_wallet::KeychainKind;
use bdk_wallet::Update as BdkUpdate;

use std::collections::BTreeMap;
use std::str::FromStr;
use std::sync::Arc;

pub struct EsploraClient(BlockingClient);

impl EsploraClient {
    pub fn new(url: String) -> Self {
        let client = Builder::new(url.as_str()).build_blocking();
        Self(client)
    }

    pub fn full_scan(
        &self,
        request: Arc<FullScanRequest>,
        stop_gap: u64,
        parallel_requests: u64,
    ) -> Result<Arc<Update>, EsploraError> {
        // using option and take is not ideal but the only way to take full ownership of the request
        let request: BdkFullScanRequest<KeychainKind> = request
            .0
            .lock()
            .unwrap()
            .take()
            .ok_or(EsploraError::RequestAlreadyConsumed)?;

        let result: BdkFullScanResult<KeychainKind> =
            self.0
                .full_scan(request, stop_gap as usize, parallel_requests as usize)?;

        let update = BdkUpdate {
            last_active_indices: result.last_active_indices,
            tx_update: result.tx_update,
            chain: result.chain_update,
        };

        Ok(Arc::new(Update(update)))
    }

    pub fn sync(
        &self,
        request: Arc<SyncRequest>,
        parallel_requests: u64,
    ) -> Result<Arc<Update>, EsploraError> {
        // using option and take is not ideal but the only way to take full ownership of the request
        let request: BdkSyncRequest<(KeychainKind, u32)> = request
            .0
            .lock()
            .unwrap()
            .take()
            .ok_or(EsploraError::RequestAlreadyConsumed)?;

        let result: BdkSyncResult = self.0.sync(request, parallel_requests as usize)?;

        let update = BdkUpdate {
            last_active_indices: BTreeMap::default(),
            tx_update: result.tx_update,
            chain: result.chain_update,
        };

        Ok(Arc::new(Update(update)))
    }

    pub fn broadcast(&self, transaction: &Transaction) -> Result<(), EsploraError> {
        let bdk_transaction: BdkTransaction = transaction.into();
        self.0
            .broadcast(&bdk_transaction)
            .map_err(EsploraError::from)
    }

    pub fn get_tx(&self, txid: String) -> Result<Arc<Transaction>, EsploraError> {
        let txid = Txid::from_str(&txid).map_err(|e| EsploraError::Parsing { error_message: e.to_string() })?;
        Ok(Arc::new(self.0.get_tx_no_opt(&txid).map_err(EsploraError::from)?.into()))
    }

    pub fn get_tx_info(&self, txid: String) -> Result<Tx, EsploraError> {
        let txid = Txid::from_str(&txid).map_err(|e| EsploraError::Parsing { error_message: e.to_string() })?;
        Ok(self.0.get_tx_info(&txid).map_err(EsploraError::from)?.ok_or(EsploraError::TransactionNotFound)?.into())
    }
}


#[derive(Debug, Clone)]
pub struct Tx {
    pub txid: String,
    pub version: i32,
    pub locktime: u32,
    pub vin: Vec<Vin>,
    pub vout: Vec<Vout>,
    pub size: u64,
    pub weight: u64,
    pub status: TxStatus,
    pub fee: u64,
}

impl From<EsploraTx> for Tx {
    fn from(value: EsploraTx) -> Self {
        Self {
            txid: value.txid.to_string(),
            version: value.version,
            locktime: value.locktime,
            vin: value.vin.into_iter().map(Vin::from).collect(),
            vout: value.vout.into_iter().map(Vout::from).collect(),
            size: value.size as u64,
            weight: value.weight,
            status: value.status.into(),
            fee: value.fee,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Vin {
    pub txid: String,
    pub vout: u32,
    // None if coinbase
    pub prevout: Option<PrevOut>,
    pub scriptsig: Arc<Script>,
    pub witness: Vec<Vec<u8>>,
    pub sequence: u32,
    pub is_coinbase: bool,
}

impl From<EsploraVin> for Vin {
    fn from(value: EsploraVin) -> Self {
        Self {
            txid: value.txid.to_string(),
            vout: value.vout,
            prevout: value.prevout.map(Into::into),
            scriptsig: Arc::new(value.scriptsig.into()),
            witness: value.witness,
            sequence: value.sequence,
            is_coinbase: value.is_coinbase,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Vout {
    pub value: u64,
    pub scriptpubkey: Arc<Script>,
}

impl From<EsploraVout> for Vout {
    fn from(value: EsploraVout) -> Self {
        Self {
            value: value.value,
            scriptpubkey: Arc::new(value.scriptpubkey.into()),
        }
    }
}

#[derive(Debug, Clone)]
pub struct TxStatus {
    pub confirmed: bool,
    pub block_height: Option<u32>,
    pub block_hash: Option<Arc<BlockHash>>,
    pub block_time: Option<u64>,
}

impl From<EsploraTxStatus> for TxStatus {
    fn from(value: EsploraTxStatus) -> Self {
        Self {
            confirmed: value.confirmed,
            block_height: value.block_height,
            block_hash: value.block_hash.map(|e| Arc::new(e.into())),
            block_time: value.block_time,
        }
    }
}

#[derive(Debug, Clone)]
pub struct PrevOut {
    pub value: u64,
    pub scriptpubkey: Arc<Script>,
}
impl From<EsploraPrevOut> for PrevOut {
    fn from(value: EsploraPrevOut) -> Self {
        Self { value: value.value, scriptpubkey: Arc::new(value.scriptpubkey.into()) }
    }
}

// mod test {
//     use std::str::FromStr;
//     use super::*;
//
//     #[test]
//     fn it_works() {
//         let c = EsploraClient::new("https://mempool.space/api".to_string());
//         let txid = Txid::from_str("96ae181640193fcb667553224560c1eaa9a8e524d94e9fd37fb65c97b9034178").unwrap();
//         let resp = c.get_tx_info(txid).unwrap();
//         println!("{:?}", resp);
//     }
// }