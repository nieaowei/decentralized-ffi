use crate::error::{AddressParseError, ExtractTxError, FeeRateError, FromScriptError, ParseAmountError, PsbtError, PsbtParseError, TransactionError, TxidParseError};

use bdk_wallet::bitcoin::Amount as BitcoinAmount;
use bdk_wallet::bitcoin::FeeRate as BitcoinFeeRate;
use bdk_wallet::bitcoin::ScriptBuf as BitcoinScriptBuf;
use bdk_wallet::bitcoin::OutPoint as BitcoinOutPoint;

use bdk_wallet::bitcoin::address::{NetworkChecked, NetworkUnchecked};
use bdk_wallet::bitcoin::consensus::encode::{serialize, serialize_hex};
use bdk_wallet::bitcoin::consensus::Decodable;
use bdk_wallet::bitcoin::io::Cursor;
use bdk_wallet::bitcoin::{Address as BdkAddress, Amount as BdkAmount, ScriptBuf as BdkScriptBuf, Sequence};
use bdk_wallet::bitcoin::Psbt as BdkPsbt;
use bdk_wallet::bitcoin::Transaction as BdkTransaction;
use bdk_wallet::bitcoin::TxIn as BdkTxIn;
use bdk_wallet::bitcoin::TxOut as BdkTxOut;
use bdk_wallet::bitcoin::BlockHash as BdkBlockHash;
use bdk_wallet::bitcoin::Txid as BdkTxid;

use std::fmt::{write, Display, Formatter};
use std::ops::Deref;
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use bdk_core::bitcoin::hex::FromHex;
use bdk_core::bitcoin::Witness;
use bdk_wallet::bitcoin::hashes::Hash;
use bdk_wallet::bitcoin::hex::HexToArrayError;
use bdk_wallet::psbt::PsbtUtils;
use bdk_wallet::serde_json;
use crate::testnet4::Network;

macro_rules! impl_from_core_type {
    ($ffi_type:ident, $core_type:ident) => {
        impl From<$core_type> for $ffi_type {
            fn from(core_type: $core_type) -> Self {
                $ffi_type(core_type)
            }
        }
    };
}

macro_rules! impl_from_ffi_type {
    ($ffi_type:ident, $core_type:ident) => {
        impl From<$ffi_type> for $core_type {
            fn from(ffi_type: $ffi_type) -> Self {
                ffi_type.0
            }
        }
    };
}

#[derive(uniffi::Object, Debug, Clone, PartialEq, Eq, Hash)]
#[uniffi::export(Debug, Display, Eq, Hash)]
pub struct Address(pub BdkAddress<NetworkChecked>);

#[uniffi::export]
impl Address {
    #[uniffi::constructor]
    pub fn new(address: String, network: Network) -> Result<Self, AddressParseError> {
        let parsed_address = address.parse::<bdk_wallet::bitcoin::Address<NetworkUnchecked>>()?;
        let network_checked_address = parsed_address.require_network(network.to_bitcoin_network())?;

        Ok(Address(network_checked_address))
    }
    #[uniffi::constructor]
    pub fn from_script(script: Arc<Script>, network: Network) -> Result<Self, FromScriptError> {
        let address = BdkAddress::from_script(&script.0.clone(), network.to_bitcoin_network())?;

        Ok(Address(address))
    }

    pub fn script_pubkey(&self) -> Arc<Script> {
        Arc::new(Script(self.0.script_pubkey()))
    }

    pub fn to_qr_uri(&self) -> String {
        self.0.to_qr_uri()
    }

    pub fn is_valid_for_network(&self, network: Network) -> bool {
        let address_str = self.0.to_string();
        if let Ok(unchecked_address) = address_str.parse::<BdkAddress<NetworkUnchecked>>() {
            unchecked_address.is_valid_for_network(network.to_bitcoin_network())
        } else {
            false
        }
    }

    pub fn minimal_non_dust(&self) -> Amount {
        self.0.script_pubkey().minimal_non_dust().into()
    }
}


impl Display for Address {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<Address> for BdkAddress {
    fn from(address: Address) -> Self {
        address.0
    }
}

impl From<BdkAddress> for Address {
    fn from(address: BdkAddress) -> Self {
        Address(address)
    }
}

#[derive(uniffi::Object, Debug, Clone, PartialEq, Eq, Hash)]
#[uniffi::export(Debug, Display, Eq, Hash)]
pub struct BlockHash(pub(crate) BdkBlockHash);

#[uniffi::export]
impl BlockHash {
    #[uniffi::constructor]
    pub fn new(str: String) -> Self {
        let hash = BdkBlockHash::from_str(&str).unwrap();
        BlockHash(hash)
    }
    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.to_byte_array().to_vec()
    }
}

impl Display for BlockHash {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", serialize_hex(&self.0))
    }
}

impl From<BdkBlockHash> for BlockHash {
    fn from(hash: BdkBlockHash) -> Self {
        BlockHash(hash)
    }
}

#[derive(uniffi::Object, Debug, Clone, PartialEq, Eq, Hash)]
#[uniffi::export(Debug, Display, Eq, Hash)]
pub struct Transaction(BdkTransaction);

#[uniffi::export]
impl Transaction {
    #[uniffi::constructor]
    pub fn new(transaction_bytes: Vec<u8>) -> Result<Self, TransactionError> {
        let mut decoder = Cursor::new(transaction_bytes);
        let tx: BdkTransaction = BdkTransaction::consensus_decode(&mut decoder)?;
        Ok(Transaction(tx))
    }

    pub fn compute_txid(&self) -> String {
        self.0.compute_txid().to_string()
    }

    pub fn weight(&self) -> u64 {
        self.0.weight().to_wu()
    }

    pub fn total_size(&self) -> u64 {
        self.0.total_size() as u64
    }

    pub fn vsize(&self) -> u64 {
        self.0.vsize() as u64
    }

    pub fn is_coinbase(&self) -> bool {
        self.0.is_coinbase()
    }

    pub fn is_explicitly_rbf(&self) -> bool {
        self.0.is_explicitly_rbf()
    }

    pub fn is_lock_time_enabled(&self) -> bool {
        self.0.is_lock_time_enabled()
    }

    pub fn version(&self) -> i32 {
        self.0.version.0
    }

    pub fn serialize(&self) -> Vec<u8> {
        serialize(&self.0)
    }

    pub fn input(&self) -> Vec<TxIn> {
        self.0.input.iter().map(|tx_in| tx_in.into()).collect()
    }

    pub fn output(&self) -> Vec<TxOut> {
        self.0.output.iter().map(|tx_out| tx_out.into()).collect()
    }

    pub fn lock_time(&self) -> u32 {
        self.0.lock_time.to_consensus_u32()
    }
}

impl Display for Transaction {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", serialize_hex(&self.0))
    }
}

impl From<BdkTransaction> for Transaction {
    fn from(tx: BdkTransaction) -> Self {
        Transaction(tx)
    }
}

impl From<&BdkTransaction> for Transaction {
    fn from(tx: &BdkTransaction) -> Self {
        Transaction(tx.clone())
    }
}

impl From<&Transaction> for BdkTransaction {
    fn from(tx: &Transaction) -> Self {
        tx.0.clone()
    }
}

impl From<&Transaction> for Arc<BdkTransaction> {
    fn from(tx: &Transaction) -> Self {
        Arc::new(tx.0.clone())
    }
}

#[derive(uniffi::Object, Debug)]
pub struct Psbt(pub(crate) Mutex<BdkPsbt>);

#[uniffi::export]
impl Psbt {
    #[uniffi::constructor]
    pub(crate) fn new(psbt_base64: String) -> Result<Self, PsbtParseError> {
        let psbt: BdkPsbt = BdkPsbt::from_str(&psbt_base64)?;
        Ok(Psbt(Mutex::new(psbt)))
    }

    #[uniffi::constructor]
    pub(crate) fn from_hex(psbt_hex: String) -> Result<Self, PsbtParseError> {
        let bs = Vec::<u8>::from_hex(&psbt_hex).map_err(|e| PsbtParseError::PsbtEncoding { error_message: e.to_string() })?;
        let psbt: BdkPsbt = BdkPsbt::deserialize(bs.as_slice()).map_err(|e| PsbtParseError::PsbtEncoding { error_message: e.to_string() })?;

        Ok(Psbt(Mutex::new(psbt)))
    }

    pub(crate) fn serialize(&self) -> String {
        let psbt = self.0.lock().unwrap().clone();
        psbt.to_string()
    }

    pub(crate) fn extract_tx(&self) -> Result<Arc<Transaction>, ExtractTxError> {
        let tx: BdkTransaction = self.0.lock().unwrap().clone().extract_tx()?;
        let transaction: Transaction = tx.into();
        Ok(Arc::new(transaction))
    }

    pub(crate) fn extract_tx_unchecked_fee_rate(&self) -> Arc<Transaction> {
        let tx: BdkTransaction = self.0.lock().unwrap().clone().extract_tx_unchecked_fee_rate();
        let transaction: Transaction = tx.into();
        Arc::new(transaction)
    }


    pub(crate) fn fee(&self) -> Result<Arc<Amount>, PsbtError> {
        self.0
            .lock()
            .unwrap()
            .fee()
            .map(|fee| Arc::new(fee.into()))
            .map_err(PsbtError::from)
    }


    pub(crate) fn fee_rate(&self) -> Result<Arc<FeeRate>, PsbtError> {
        self.0
            .lock()
            .unwrap()
            .fee_rate()
            .map(|fee| Arc::new(fee.into()))
            .ok_or(PsbtError::OtherPsbtErr)
    }

    pub(crate) fn combine(&self, other: Arc<Psbt>) -> Result<Arc<Psbt>, PsbtError> {
        let mut original_psbt = self.0.lock().unwrap().clone();
        let other_psbt = other.0.lock().unwrap().clone();
        original_psbt.combine(other_psbt)?;
        Ok(Arc::new(Psbt(Mutex::new(original_psbt))))
    }

    pub(crate) fn json_serialize(&self) -> String {
        let psbt = self.0.lock().unwrap();
        serde_json::to_string(psbt.deref()).unwrap()
    }

    pub fn serialize_hex(&self) -> String {
        let psbt = self.0.lock().unwrap();
        psbt.serialize_hex()
    }
}

impl From<BdkPsbt> for Psbt {
    fn from(psbt: BdkPsbt) -> Self {
        Psbt(Mutex::new(psbt))
    }
}

#[derive(uniffi::Record, Debug, Clone, PartialEq, Eq, Hash)]
pub struct TxIn {
    pub previous_output: OutPoint,
    pub script_sig: Arc<Script>,
    pub sequence: u32,
    pub witness: Vec<Vec<u8>>,
    pub serialize_hex: String,
    pub witness_hex: String,
}

impl From<&BdkTxIn> for TxIn {
    fn from(tx_in: &BdkTxIn) -> Self {
        TxIn {
            previous_output: OutPoint {
                txid: Arc::new(tx_in.previous_output.txid.into()),
                vout: tx_in.previous_output.vout,
            },
            script_sig: Arc::new(Script(tx_in.script_sig.clone())),
            sequence: tx_in.sequence.to_consensus_u32(),
            witness: tx_in.witness.to_vec(),
            serialize_hex: serialize_hex(tx_in),
            witness_hex: serialize_hex(&tx_in.witness),
        }
    }
}

impl From<&TxIn> for BdkTxIn {
    fn from(tx_in: &TxIn) -> Self {
        BdkTxIn {
            previous_output: BitcoinOutPoint {
                txid: tx_in.previous_output.txid.0,
                vout: tx_in.previous_output.vout,
            },
            script_sig: tx_in.script_sig.0.clone(),
            sequence: Sequence::from_consensus(tx_in.sequence),
            witness: Witness::from(tx_in.witness.clone()),
        }
    }
}

#[derive(uniffi::Record, Debug, Clone, PartialEq, Eq, Hash)]
pub struct TxOut {
    pub value: Arc<Amount>,
    pub script_pubkey: Arc<Script>,
    pub serialize_hex: String,
}


impl From<&BdkTxOut> for TxOut {
    fn from(tx_out: &BdkTxOut) -> Self {
        TxOut {
            value: Arc::new(Amount(tx_out.value)),
            script_pubkey: Arc::new(Script(tx_out.script_pubkey.clone())),
            serialize_hex: serialize_hex(tx_out),
        }
    }
}

impl From<&TxOut> for BdkTxOut {
    fn from(tx_out: &TxOut) -> Self {
        BdkTxOut {
            value: BdkAmount::from(tx_out.value.0),
            script_pubkey: BdkScriptBuf::from(tx_out.script_pubkey.deref().clone()),
        }
    }
}


#[derive(uniffi::Object, Debug, Clone, PartialEq, Eq, Hash)]
#[uniffi::export(Debug, Display, Eq, Hash)]
pub struct FeeRate(pub BitcoinFeeRate);

#[uniffi::export]
impl FeeRate {
    #[uniffi::constructor]
    pub fn from_sat_per_vb(sat_per_vb: u64) -> Result<Self, FeeRateError> {
        let fee_rate: Option<BitcoinFeeRate> = BitcoinFeeRate::from_sat_per_vb(sat_per_vb);
        match fee_rate {
            Some(fee_rate) => Ok(FeeRate(fee_rate)),
            None => Err(FeeRateError::ArithmeticOverflow),
        }
    }

    #[uniffi::constructor]
    pub fn from_sat_per_kwu(sat_per_kwu: u64) -> Self {
        FeeRate(BitcoinFeeRate::from_sat_per_kwu(sat_per_kwu))
    }

    pub fn to_sat_per_vb_ceil(&self) -> u64 {
        self.0.to_sat_per_vb_ceil()
    }

    pub fn to_sat_per_vb_floor(&self) -> u64 {
        self.0.to_sat_per_vb_floor()
    }

    pub fn to_sat_per_kwu(&self) -> u64 {
        self.0.to_sat_per_kwu()
    }
}

impl Display for FeeRate {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl_from_core_type!(FeeRate, BitcoinFeeRate);
impl_from_ffi_type!(FeeRate, BitcoinFeeRate);

#[derive(uniffi::Object, Debug, Clone, PartialEq, Eq, Hash)]
#[uniffi::export(Debug, Display, Eq, Hash)]
pub struct Script(pub BitcoinScriptBuf);

#[uniffi::export]
impl Script {
    #[uniffi::constructor]
    pub fn new(raw_output_script: Vec<u8>) -> Self {
        let script: BitcoinScriptBuf = raw_output_script.into();
        Script(script)
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.to_bytes()
    }

    pub fn to_asm_string(&self) -> String {
        self.0.to_asm_string()
    }
}

impl Display for Script {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl_from_core_type!(Script, BitcoinScriptBuf);
impl_from_ffi_type!(Script, BitcoinScriptBuf);

#[derive(uniffi::Object, Debug, Clone, PartialEq, Eq, Hash)]
#[uniffi::export(Debug, Display, Eq, Hash)]
pub struct Amount(pub BitcoinAmount);

#[uniffi::export]
impl Amount {
    #[uniffi::constructor]
    pub fn from_sat(sat: u64) -> Self {
        Amount(BitcoinAmount::from_sat(sat))
    }

    #[uniffi::constructor]
    pub fn from_btc(btc: f64) -> Result<Self, ParseAmountError> {
        let bitcoin_amount = BitcoinAmount::from_btc(btc).map_err(ParseAmountError::from)?;
        Ok(Amount(bitcoin_amount))
    }

    pub fn to_sat(&self) -> u64 {
        self.0.to_sat()
    }

    pub fn to_btc(&self) -> f64 {
        self.0.to_btc()
    }
}

impl Display for Amount {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl_from_core_type!(Amount, BitcoinAmount);
impl_from_ffi_type!(Amount, BitcoinAmount);


#[derive(uniffi::Object, Debug, Clone, Copy, Eq, PartialEq, Hash)]
#[uniffi::export(Debug, Display, Eq, Hash)]
pub struct Txid(pub BdkTxid);

impl_from_core_type!(Txid, BdkTxid);
impl_from_ffi_type!(Txid, BdkTxid);

#[uniffi::export]
impl Txid {
    #[uniffi::constructor]
    pub fn from_string(s: String) -> Result<Self, TxidParseError> {
        Txid::from_str(&s).map_err(|e| TxidParseError::InvalidTxid { txid: s })
    }
}

impl Display for Txid {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl FromStr for Txid {
    type Err = HexToArrayError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        BdkTxid::from_str(s).map(Txid)
    }
}

#[derive(uniffi::Record, Debug, Clone, PartialEq, Eq, Hash)]
pub struct OutPoint {
    pub txid: Arc<Txid>,
    pub vout: u32,
}

impl From<BitcoinOutPoint> for OutPoint {
    fn from(value: BitcoinOutPoint) -> Self {
        Self { txid: Arc::new(value.txid.into()), vout: value.vout }
    }
}

impl From<OutPoint> for BitcoinOutPoint {
    fn from(value: OutPoint) -> Self {
        Self { txid: value.txid.0, vout: value.vout }
    }
}

#[cfg(test)]
mod tests {
    use crate::bitcoin::{Address, Psbt};
    use crate::bitcoin::Network;

    #[test]
    fn test_psbt() {
        // let c = electrum_client::Client::new("ssl://mempool.space:40002").unwrap();
        // c.ping().unwrap();
        // let res = c.server_features().unwrap();
        // println!("{:?}", res);
    }

    #[test]
    fn test_is_valid_for_network() {
        // ====Docs tests====
        // https://docs.rs/bitcoin/0.29.2/src/bitcoin/util/address.rs.html#798-802

        let docs_address_testnet_str = "2N83imGV3gPwBzKJQvWJ7cRUY2SpUyU6A5e";
        let docs_address_testnet =
            Address::new(docs_address_testnet_str.to_string(), Network::Testnet).unwrap();
        assert!(
            docs_address_testnet.is_valid_for_network(Network::Testnet),
            "Address should be valid for Testnet"
        );
        assert!(
            docs_address_testnet.is_valid_for_network(Network::Signet),
            "Address should be valid for Signet"
        );
        assert!(
            docs_address_testnet.is_valid_for_network(Network::Regtest),
            "Address should be valid for Regtest"
        );

        let docs_address_mainnet_str = "32iVBEu4dxkUQk9dJbZUiBiQdmypcEyJRf";
        let docs_address_mainnet =
            Address::new(docs_address_mainnet_str.to_string(), Network::Bitcoin).unwrap();
        assert!(
            docs_address_mainnet.is_valid_for_network(Network::Bitcoin),
            "Address should be valid for Bitcoin"
        );

        // ====Bech32====

        //     | Network         | Prefix  | Address Type |
        //     |-----------------|---------|--------------|
        //     | Bitcoin Mainnet | `bc1`   | Bech32       |
        //     | Bitcoin Testnet | `tb1`   | Bech32       |
        //     | Bitcoin Signet  | `tb1`   | Bech32       |
        //     | Bitcoin Regtest | `bcrt1` | Bech32       |

        // Bech32 - Bitcoin
        // Valid for:
        // - Bitcoin
        // Not valid for:
        // - Testnet
        // - Signet
        // - Regtest
        let bitcoin_mainnet_bech32_address_str = "bc1qxhmdufsvnuaaaer4ynz88fspdsxq2h9e9cetdj";
        let bitcoin_mainnet_bech32_address = Address::new(
            bitcoin_mainnet_bech32_address_str.to_string(),
            Network::Bitcoin,
        )
            .unwrap();
        assert!(
            bitcoin_mainnet_bech32_address.is_valid_for_network(Network::Bitcoin),
            "Address should be valid for Bitcoin"
        );
        assert!(
            !bitcoin_mainnet_bech32_address.is_valid_for_network(Network::Testnet),
            "Address should not be valid for Testnet"
        );
        assert!(
            !bitcoin_mainnet_bech32_address.is_valid_for_network(Network::Signet),
            "Address should not be valid for Signet"
        );
        assert!(
            !bitcoin_mainnet_bech32_address.is_valid_for_network(Network::Regtest),
            "Address should not be valid for Regtest"
        );

        // Bech32 - Testnet
        // Valid for:
        // - Testnet
        // - Regtest
        // Not valid for:
        // - Bitcoin
        // - Regtest
        let bitcoin_testnet_bech32_address_str =
            "tb1p4nel7wkc34raczk8c4jwk5cf9d47u2284rxn98rsjrs4w3p2sheqvjmfdh";
        let bitcoin_testnet_bech32_address = Address::new(
            bitcoin_testnet_bech32_address_str.to_string(),
            Network::Testnet,
        )
            .unwrap();
        assert!(
            !bitcoin_testnet_bech32_address.is_valid_for_network(Network::Bitcoin),
            "Address should not be valid for Bitcoin"
        );
        assert!(
            bitcoin_testnet_bech32_address.is_valid_for_network(Network::Testnet),
            "Address should be valid for Testnet"
        );
        assert!(
            bitcoin_testnet_bech32_address.is_valid_for_network(Network::Signet),
            "Address should be valid for Signet"
        );
        assert!(
            !bitcoin_testnet_bech32_address.is_valid_for_network(Network::Regtest),
            "Address should not not be valid for Regtest"
        );

        // Bech32 - Signet
        // Valid for:
        // - Signet
        // - Testnet
        // Not valid for:
        // - Bitcoin
        // - Regtest
        let bitcoin_signet_bech32_address_str =
            "tb1pwzv7fv35yl7ypwj8w7al2t8apd6yf4568cs772qjwper74xqc99sk8x7tk";
        let bitcoin_signet_bech32_address = Address::new(
            bitcoin_signet_bech32_address_str.to_string(),
            Network::Signet,
        )
            .unwrap();
        assert!(
            !bitcoin_signet_bech32_address.is_valid_for_network(Network::Bitcoin),
            "Address should not be valid for Bitcoin"
        );
        assert!(
            bitcoin_signet_bech32_address.is_valid_for_network(Network::Testnet),
            "Address should be valid for Testnet"
        );
        assert!(
            bitcoin_signet_bech32_address.is_valid_for_network(Network::Signet),
            "Address should be valid for Signet"
        );
        assert!(
            !bitcoin_signet_bech32_address.is_valid_for_network(Network::Regtest),
            "Address should not not be valid for Regtest"
        );

        // Bech32 - Regtest
        // Valid for:
        // - Regtest
        // Not valid for:
        // - Bitcoin
        // - Testnet
        // - Signet
        let bitcoin_regtest_bech32_address_str = "bcrt1q39c0vrwpgfjkhasu5mfke9wnym45nydfwaeems";
        let bitcoin_regtest_bech32_address = Address::new(
            bitcoin_regtest_bech32_address_str.to_string(),
            Network::Regtest,
        )
            .unwrap();
        assert!(
            !bitcoin_regtest_bech32_address.is_valid_for_network(Network::Bitcoin),
            "Address should not be valid for Bitcoin"
        );
        assert!(
            !bitcoin_regtest_bech32_address.is_valid_for_network(Network::Testnet),
            "Address should not be valid for Testnet"
        );
        assert!(
            !bitcoin_regtest_bech32_address.is_valid_for_network(Network::Signet),
            "Address should not be valid for Signet"
        );
        assert!(
            bitcoin_regtest_bech32_address.is_valid_for_network(Network::Regtest),
            "Address should be valid for Regtest"
        );

        // ====P2PKH====

        //     | Network                            | Prefix for P2PKH | Prefix for P2SH |
        //     |------------------------------------|------------------|-----------------|
        //     | Bitcoin Mainnet                    | `1`              | `3`             |
        //     | Bitcoin Testnet, Regtest, Signet   | `m` or `n`       | `2`             |

        // P2PKH - Bitcoin
        // Valid for:
        // - Bitcoin
        // Not valid for:
        // - Testnet
        // - Regtest
        let bitcoin_mainnet_p2pkh_address_str = "1FfmbHfnpaZjKFvyi1okTjJJusN455paPH";
        let bitcoin_mainnet_p2pkh_address = Address::new(
            bitcoin_mainnet_p2pkh_address_str.to_string(),
            Network::Bitcoin,
        )
            .unwrap();
        assert!(
            bitcoin_mainnet_p2pkh_address.is_valid_for_network(Network::Bitcoin),
            "Address should be valid for Bitcoin"
        );
        assert!(
            !bitcoin_mainnet_p2pkh_address.is_valid_for_network(Network::Testnet),
            "Address should not be valid for Testnet"
        );
        assert!(
            !bitcoin_mainnet_p2pkh_address.is_valid_for_network(Network::Regtest),
            "Address should not be valid for Regtest"
        );

        // P2PKH - Testnet
        // Valid for:
        // - Testnet
        // - Regtest
        // Not valid for:
        // - Bitcoin
        let bitcoin_testnet_p2pkh_address_str = "mucFNhKMYoBQYUAEsrFVscQ1YaFQPekBpg";
        let bitcoin_testnet_p2pkh_address = Address::new(
            bitcoin_testnet_p2pkh_address_str.to_string(),
            Network::Testnet,
        )
            .unwrap();
        assert!(
            !bitcoin_testnet_p2pkh_address.is_valid_for_network(Network::Bitcoin),
            "Address should not be valid for Bitcoin"
        );
        assert!(
            bitcoin_testnet_p2pkh_address.is_valid_for_network(Network::Testnet),
            "Address should be valid for Testnet"
        );
        assert!(
            bitcoin_testnet_p2pkh_address.is_valid_for_network(Network::Regtest),
            "Address should be valid for Regtest"
        );

        // P2PKH - Regtest
        // Valid for:
        // - Testnet
        // - Regtest
        // Not valid for:
        // - Bitcoin
        let bitcoin_regtest_p2pkh_address_str = "msiGFK1PjCk8E6FXeoGkQPTscmcpyBdkgS";
        let bitcoin_regtest_p2pkh_address = Address::new(
            bitcoin_regtest_p2pkh_address_str.to_string(),
            Network::Regtest,
        )
            .unwrap();
        assert!(
            !bitcoin_regtest_p2pkh_address.is_valid_for_network(Network::Bitcoin),
            "Address should not be valid for Bitcoin"
        );
        assert!(
            bitcoin_regtest_p2pkh_address.is_valid_for_network(Network::Testnet),
            "Address should be valid for Testnet"
        );
        assert!(
            bitcoin_regtest_p2pkh_address.is_valid_for_network(Network::Regtest),
            "Address should be valid for Regtest"
        );

        // ====P2SH====

        //     | Network                            | Prefix for P2PKH | Prefix for P2SH |
        //     |------------------------------------|------------------|-----------------|
        //     | Bitcoin Mainnet                    | `1`              | `3`             |
        //     | Bitcoin Testnet, Regtest, Signet   | `m` or `n`       | `2`             |

        // P2SH - Bitcoin
        // Valid for:
        // - Bitcoin
        // Not valid for:
        // - Testnet
        // - Regtest
        let bitcoin_mainnet_p2sh_address_str = "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy";
        let bitcoin_mainnet_p2sh_address = Address::new(
            bitcoin_mainnet_p2sh_address_str.to_string(),
            Network::Bitcoin,
        )
            .unwrap();
        assert!(
            bitcoin_mainnet_p2sh_address.is_valid_for_network(Network::Bitcoin),
            "Address should be valid for Bitcoin"
        );
        assert!(
            !bitcoin_mainnet_p2sh_address.is_valid_for_network(Network::Testnet),
            "Address should not be valid for Testnet"
        );
        assert!(
            !bitcoin_mainnet_p2sh_address.is_valid_for_network(Network::Regtest),
            "Address should not be valid for Regtest"
        );

        // P2SH - Testnet
        // Valid for:
        // - Testnet
        // - Regtest
        // Not valid for:
        // - Bitcoin
        let bitcoin_testnet_p2sh_address_str = "2NFUBBRcTJbYc1D4HSCbJhKZp6YCV4PQFpQ";
        let bitcoin_testnet_p2sh_address = Address::new(
            bitcoin_testnet_p2sh_address_str.to_string(),
            Network::Testnet,
        )
            .unwrap();
        assert!(
            !bitcoin_testnet_p2sh_address.is_valid_for_network(Network::Bitcoin),
            "Address should not be valid for Bitcoin"
        );
        assert!(
            bitcoin_testnet_p2sh_address.is_valid_for_network(Network::Testnet),
            "Address should be valid for Testnet"
        );
        assert!(
            bitcoin_testnet_p2sh_address.is_valid_for_network(Network::Regtest),
            "Address should be valid for Regtest"
        );

        // P2SH - Regtest
        // Valid for:
        // - Testnet
        // - Regtest
        // Not valid for:
        // - Bitcoin
        let bitcoin_regtest_p2sh_address_str = "2NEb8N5B9jhPUCBchz16BB7bkJk8VCZQjf3";
        let bitcoin_regtest_p2sh_address = Address::new(
            bitcoin_regtest_p2sh_address_str.to_string(),
            Network::Regtest,
        )
            .unwrap();
        assert!(
            !bitcoin_regtest_p2sh_address.is_valid_for_network(Network::Bitcoin),
            "Address should not be valid for Bitcoin"
        );
        assert!(
            bitcoin_regtest_p2sh_address.is_valid_for_network(Network::Testnet),
            "Address should be valid for Testnet"
        );
        assert!(
            bitcoin_regtest_p2sh_address.is_valid_for_network(Network::Regtest),
            "Address should be valid for Regtest"
        );
    }
}
