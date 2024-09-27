use crate::bitcoin::{Psbt, Transaction, TxOut};
use crate::descriptor::Descriptor;
use crate::error::{CalculateFeeError, CannotConnectError, CreateWithPersistError, LoadWithPersistError, SignerError, SqliteError, TxidParseError};
use crate::store::Connection;
use crate::types::{AddressInfo, Balance, CanonicalTx, FullScanRequestBuilder, LocalOutput, SentAndReceivedValues, SyncRequestBuilder, TransactionAndLastSeen, Update};
use crate::testnet4::{testnet4_genesis_block, CustomNetwork};

use bitcoin_ffi::{Amount, FeeRate, OutPoint, Script};

use bdk_wallet::bitcoin::{Network, Txid, Transaction as BdkTransaction};
use bdk_wallet::rusqlite::Connection as BdkConnection;
use bdk_wallet::{KeychainKind, PersistedWallet, SignOptions, Wallet as BdkWallet};

use std::borrow::BorrowMut;
use std::str::FromStr;
use std::sync::{Arc, Mutex, MutexGuard};

pub struct Wallet {
    inner_mutex: Mutex<PersistedWallet<BdkConnection>>,
}

impl Wallet {
    pub fn new(
        descriptor: Arc<Descriptor>,
        change_descriptor: Arc<Descriptor>,
        network: CustomNetwork,
        connection: Arc<Connection>,
    ) -> Result<Self, CreateWithPersistError> {
        let descriptor = descriptor.to_string_with_secret();
        let change_descriptor = change_descriptor.to_string_with_secret();
        let mut binding = connection.get_store();
        let db: &mut BdkConnection = binding.borrow_mut();

        let mut create_params =
            BdkWallet::create(descriptor, change_descriptor).network(network.to_bitcoin_network());

        if network == CustomNetwork::Testnet4 {
            create_params = create_params.genesis_hash(testnet4_genesis_block().block_hash())
        }
        let wallet: PersistedWallet<BdkConnection> = create_params.create_wallet(db)?;

        Ok(Wallet {
            inner_mutex: Mutex::new(wallet),
        })
    }

    pub fn create_single(
        descriptor: Arc<Descriptor>,
        network: CustomNetwork,
        connection: Arc<Connection>,
    ) -> Result<Self, CreateWithPersistError> {
        let descriptor = descriptor.to_string_with_secret();
        let mut binding = connection.get_store();
        let db: &mut BdkConnection = binding.borrow_mut();

        let mut create_params =
            BdkWallet::create_single(descriptor).network(network.to_bitcoin_network());

        if network == CustomNetwork::Testnet4 {
            create_params = create_params.genesis_hash(testnet4_genesis_block().block_hash())
        }
        let wallet: PersistedWallet<BdkConnection> = create_params.create_wallet(db)?;

        Ok(Wallet {
            inner_mutex: Mutex::new(wallet),
        })
    }

    pub fn load(
        descriptor: Arc<Descriptor>,
        change_descriptor: Option<Arc<Descriptor>>,
        connection: Arc<Connection>,
    ) -> Result<Wallet, LoadWithPersistError> {
        let descriptor = descriptor.to_string_with_secret();
        let change_descriptor = change_descriptor.map_or(None, |e| Some(e.to_string_with_secret()));
        let mut binding = connection.get_store();
        let db: &mut BdkConnection = binding.borrow_mut();

        let wallet: PersistedWallet<BdkConnection> = BdkWallet::load()
            .descriptor(KeychainKind::External, Some(descriptor))
            .descriptor(KeychainKind::Internal, change_descriptor)
            .extract_keys()
            .load_wallet(db)?
            .ok_or(LoadWithPersistError::CouldNotLoad)?;

        Ok(Wallet {
            inner_mutex: Mutex::new(wallet),
        })
    }

    pub(crate) fn get_wallet(&self) -> MutexGuard<PersistedWallet<BdkConnection>> {
        self.inner_mutex.lock().expect("wallet")
    }

    pub fn reveal_next_address(&self, keychain_kind: KeychainKind) -> AddressInfo {
        self.get_wallet().reveal_next_address(keychain_kind).into()
    }

    pub fn reveal_addresses_to(&self, keychain_kind: KeychainKind, index: u32) -> Vec<AddressInfo> {
        self.get_wallet().reveal_addresses_to(keychain_kind, index).map(|e| e.into()).collect::<Vec<AddressInfo>>()
    }

    pub fn peek_address(&self, keychain_kind: KeychainKind, index: u32) -> AddressInfo {
        self.get_wallet().peek_address(keychain_kind, index).into()
    }


    pub fn apply_update(&self, update: Arc<Update>) -> Result<(), CannotConnectError> {
        self.get_wallet()
            .apply_update(update.0.clone())
            .map_err(CannotConnectError::from)
    }

    pub(crate) fn derivation_index(&self, keychain: KeychainKind) -> Option<u32> {
        self.get_wallet().derivation_index(keychain)
    }

    pub fn network(&self) -> Network {
        self.get_wallet().network()
    }

    pub fn balance(&self) -> Balance {
        let bdk_balance = self.get_wallet().balance();
        Balance::from(bdk_balance)
    }

    pub fn is_mine(&self, script: Arc<Script>) -> bool {
        self.get_wallet().is_mine(script.0.clone())
    }

    pub(crate) fn sign(
        &self,
        psbt: Arc<Psbt>,
        // sign_options: Option<SignOptions>,
    ) -> Result<bool, SignerError> {
        let mut psbt = psbt.0.lock().unwrap();
        self.get_wallet()
            .sign(&mut psbt, SignOptions::default())
            .map_err(SignerError::from)
    }

    pub fn sent_and_received(&self, tx: &Transaction) -> SentAndReceivedValues {
        let (sent, received) = self.get_wallet().sent_and_received(&tx.into());
        SentAndReceivedValues {
            sent: Arc::new(sent.into()),
            received: Arc::new(received.into()),
        }
    }

    pub fn transactions(&self) -> Vec<CanonicalTx> {
        self.get_wallet()
            .transactions()
            .map(|tx| tx.into())
            .collect()
    }

    pub fn get_tx(&self, txid: String) -> Result<Option<CanonicalTx>, TxidParseError> {
        let txid =
            Txid::from_str(txid.as_str()).map_err(|_| TxidParseError::InvalidTxid { txid })?;
        Ok(self.get_wallet().get_tx(txid).map(|tx| tx.into()))
    }

    pub fn get_utxo(&self, outpoint: OutPoint) -> Option<LocalOutput> {
        self.get_wallet()
            .get_utxo(outpoint)
            .map(|lo| lo.into())
    }

    pub fn get_txout(&self, outpoint: OutPoint) -> Option<TxOut> {
        self.get_wallet()
            .tx_graph()
            .get_txout(outpoint)
            .map(|txout| txout.into())
    }

    pub fn insert_tx(&self, tx: &Transaction) -> bool {
        self.get_wallet()
            .insert_tx(tx)
    }

    pub fn apply_unconfirmed_txs(&self, tx_and_last_seens: Vec<TransactionAndLastSeen>) {
        let txs = tx_and_last_seens.into_iter().map(|e| ((&*e.tx).into(), e.last_seen)).collect::<Vec<(BdkTransaction, u64)>>();
        self.get_wallet()
            .apply_unconfirmed_txs(txs.into_iter().map(|e| (e.0, e.1)));
    }

    pub fn insert_txout(&self, outpoint: OutPoint, txout: TxOut) {
        self.get_wallet()
            .insert_txout(outpoint, txout.into())
    }

    pub fn calculate_fee(&self, tx: &Transaction) -> Result<Arc<Amount>, CalculateFeeError> {
        self.get_wallet()
            .calculate_fee(&tx.into())
            .map(Amount::from)
            .map(Arc::new)
            .map_err(|e| e.into())
    }

    pub fn calculate_fee_rate(&self, tx: &Transaction) -> Result<Arc<FeeRate>, CalculateFeeError> {
        self.get_wallet()
            .calculate_fee_rate(&tx.into())
            .map(|bdk_fee_rate| Arc::new(FeeRate(bdk_fee_rate)))
            .map_err(|e| e.into())
    }

    pub fn list_unspent(&self) -> Vec<LocalOutput> {
        self.get_wallet().list_unspent().map(|o| o.into()).collect()
    }

    pub fn list_output(&self) -> Vec<LocalOutput> {
        self.get_wallet().list_output().map(|o| o.into()).collect()
    }

    pub fn start_full_scan(&self) -> Arc<FullScanRequestBuilder> {
        let builder = self.get_wallet().start_full_scan();
        Arc::new(FullScanRequestBuilder(Mutex::new(Some(builder))))
    }

    pub fn start_sync_with_revealed_spks(&self) -> Arc<SyncRequestBuilder> {
        let builder = self.get_wallet().start_sync_with_revealed_spks();
        Arc::new(SyncRequestBuilder(Mutex::new(Some(builder))))
    }

    // pub fn persist(&self, connection: Connection) -> Result<bool, FfiGenericError> {
    pub fn persist(&self, connection: Arc<Connection>) -> Result<bool, SqliteError> {
        let mut binding = connection.get_store();
        let db: &mut BdkConnection = binding.borrow_mut();
        self.get_wallet()
            .persist(db)
            .map_err(|e| SqliteError::Sqlite {
                rusqlite_error: e.to_string(),
            })
    }
}



