#![allow(unused_imports)]
mod bitcoin;
mod descriptor;
mod electrum;
mod error;
pub mod esplora;
mod keys;
mod store;
mod tx_builder;
mod types;
mod wallet;
mod testnet4;
mod ordinal;

mod utils;

#[macro_use]
mod macros;

use crate::bitcoin::Address;
use crate::bitcoin::Psbt;
use crate::bitcoin::BlockHash;
use crate::bitcoin::Transaction;
use crate::bitcoin::TxIn;
use crate::bitcoin::TxOut;
use crate::bitcoin::Amount;
use crate::bitcoin::FeeRate;
use crate::bitcoin::OutPoint;
use crate::bitcoin::Script;
use crate::bitcoin::Txid;
use crate::testnet4::Network;
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
use crate::esplora::OutputStatus;
use crate::keys::DerivationPath;
use crate::keys::DescriptorPublicKey;
use crate::keys::DescriptorSecretKey;
use crate::keys::Mnemonic;
use crate::store::Connection;
use crate::tx_builder::BumpFeeTxBuilder;
use crate::tx_builder::TxBuilder;
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
use crate::types::SentAndReceivedValues;
use crate::types::TransactionAndLastSeen;
use crate::types::SyncRequest;
use crate::types::SyncRequestBuilder;
use crate::types::SyncScriptInspector;
use crate::types::Update;
use crate::types::TxOrdering;
use crate::types::ConfirmationTime;
use crate::wallet::Wallet;
use crate::keys::WordCount;
use crate::wallet::ChangeSpendPolicy;
// use bdk_wallet::ChangeSet;
use crate::wallet::KeychainKind;

use crate::utils::script_to_asm_string;
use crate::utils::new_txin_from_hex;
use crate::utils::new_txout_from_hex;
use crate::utils::get_json_info_from_url;
use crate::utils::UtilsError;

use crate::ordinal::rune::RuneParseError;
use crate::ordinal::rune::Rune;
use crate::ordinal::rune::Edict;
use crate::ordinal::rune::RuneId;
use crate::ordinal::rune::extract_rune_from_script;

use crate::ordinal::get_single_anyone_pay_tx_pair;
use crate::ordinal::build_rune_snipe_psbt;
use crate::ordinal::TxInAndTxOut;
use crate::ordinal::SnipeRuneUtxoPair;
use crate::ordinal::SnipePsbtPair;
use crate::ordinal::SnipeInscriptionPair;
use crate::ordinal::snipe::SnipeError;

// uniffi::include_scaffolding!("bdk");

uniffi::setup_scaffolding!();
