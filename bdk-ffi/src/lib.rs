mod bitcoin;
mod descriptor;
mod electrum;
mod error;
mod esplora;
mod keys;
mod store;
mod types;
mod wallet;
mod testnet4;
mod rune;

use crate::bitcoin::Address;
use crate::bitcoin::Psbt;
use crate::bitcoin::BlockHash;
use crate::bitcoin::Transaction;
use crate::bitcoin::TxIn;
use crate::bitcoin::TxOut;
use crate::testnet4::CustomNetwork;
use crate::descriptor::Descriptor;
use crate::electrum::ElectrumClient;
use crate::error::AddressParseError;
use crate::error::Bip32Error;
use crate::error::Bip39Error;
use crate::error::CalculateFeeError;
use crate::error::CannotConnectError;
use crate::error::CreateTxError;
use crate::error::CreateWithPersistError;
use crate::error::DescriptorError;
use crate::error::DescriptorKeyError;
use crate::error::ElectrumError;
use crate::error::EsploraError;
use crate::error::ExtractTxError;
use crate::error::FromScriptError;
use crate::error::LoadWithPersistError;
use crate::error::PersistenceError;
use crate::error::PsbtError;
use crate::error::PsbtParseError;
use crate::error::RequestBuilderError;
use crate::error::SignerError;
use crate::error::SqliteError;
use crate::error::TransactionError;
use crate::error::TxidParseError;
use crate::esplora::EsploraClient;
use crate::esplora::Tx;
use crate::esplora::PrevOut;
use crate::esplora::TxStatus;
use crate::esplora::Vin;
use crate::esplora::Vout;
use crate::keys::DerivationPath;
use crate::keys::DescriptorPublicKey;
use crate::keys::DescriptorSecretKey;
use crate::keys::Mnemonic;
use crate::store::Connection;
use crate::types::AddressInfo;
use crate::types::Balance;
use crate::types::BlockId;
use crate::types::CanonicalTx;
use crate::types::ChainPosition;
use crate::types::ConfirmationBlockTime;
use crate::types::FullScanRequest;
use crate::types::FullScanRequestBuilder;
use crate::types::FullScanScriptInspector;
use crate::types::LocalOutput;
use crate::types::ScriptAmount;
use crate::types::SyncRequest;
use crate::types::SyncRequestBuilder;
use crate::types::SyncScriptInspector;
use crate::types::Update;
use crate::wallet::BumpFeeTxBuilder;
use crate::wallet::SentAndReceivedValues;
use crate::wallet::TxBuilder;
use crate::wallet::Wallet;
use crate::wallet::TransactionAndLastSeen;
use crate::wallet::TxOrdering;

use bitcoin_ffi::Amount;
use bitcoin_ffi::FeeRate;
use bitcoin_ffi::Network;
use bitcoin_ffi::OutPoint;
use bitcoin_ffi::Script;
use bdk_wallet::chain::ConfirmationTime;

use bdk_wallet::keys::bip39::WordCount;
use bdk_wallet::tx_builder::ChangeSpendPolicy;
use bdk_wallet::ChangeSet;
use bdk_wallet::KeychainKind;

uniffi::include_scaffolding!("bdk");
