use crate::error::{
    AddressParseError, FromScriptError, PsbtError, PsbtParseError, TransactionError,
};

use bitcoin_ffi::OutPoint;
use bitcoin_ffi::Script;

use bdk_bitcoind_rpc::bitcoincore_rpc::jsonrpc::serde_json;
use bdk_wallet::bitcoin::address::{NetworkChecked, NetworkUnchecked};
use bdk_wallet::bitcoin::consensus::encode::serialize;
use bdk_wallet::bitcoin::consensus::Decodable;
use bdk_wallet::bitcoin::io::Cursor;
use bdk_wallet::bitcoin::psbt::ExtractTxError;
use bdk_wallet::bitcoin::{Address as BdkAddress, Amount as BdkAmount, ScriptBuf as BdkScriptBuf};
use bdk_wallet::bitcoin::Network;
use bdk_wallet::bitcoin::Psbt as BdkPsbt;
use bdk_wallet::bitcoin::Transaction as BdkTransaction;
use bdk_wallet::bitcoin::TxIn as BdkTxIn;
use bdk_wallet::bitcoin::TxOut as BdkTxOut;
use bdk_wallet::bitcoin::BlockHash as BdkBlockHash;

use std::fmt::Display;
use std::ops::Deref;
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use bdk_core::bitcoin::hex::FromHex;
use bdk_wallet::bitcoin::hashes::Hash;

#[derive(Debug, PartialEq, Eq)]
pub struct Address(BdkAddress<NetworkChecked>);

impl Address {
    pub fn new(address: String, network: Network) -> Result<Self, AddressParseError> {
        let parsed_address = address.parse::<bdk_wallet::bitcoin::Address<NetworkUnchecked>>()?;
        let network_checked_address = parsed_address.require_network(network)?;

        Ok(Address(network_checked_address))
    }

    pub fn from_script(script: Arc<Script>, network: Network) -> Result<Self, FromScriptError> {
        let address = BdkAddress::from_script(&script.0.clone(), network)?;

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
            unchecked_address.is_valid_for_network(network)
        } else {
            false
        }
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

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockHash(pub(crate) BdkBlockHash);

impl BlockHash {
    pub fn new(str: String) -> Self {
        let hash = BdkBlockHash::from_str(&str).unwrap();
        BlockHash(hash)
    }
    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.to_byte_array().to_vec()
    }
}
impl From<BdkBlockHash> for BlockHash {

    fn from(hash: BdkBlockHash) -> Self {
        BlockHash(hash)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Transaction(BdkTransaction);

impl Transaction {
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

pub struct Psbt(pub(crate) Mutex<BdkPsbt>);

impl Psbt {
    pub(crate) fn new(psbt_base64: String) -> Result<Self, PsbtParseError> {
        let psbt: BdkPsbt = BdkPsbt::from_str(&psbt_base64)?;
        Ok(Psbt(Mutex::new(psbt)))
    }

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

    pub(crate) fn fee(&self) -> Result<u64, PsbtError> {
        self.0
            .lock()
            .unwrap()
            .fee()
            .map(|fee| fee.to_sat())
            .map_err(PsbtError::from)
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

#[derive(Debug, Clone)]
pub struct TxIn {
    pub previous_output: OutPoint,
    pub script_sig: Arc<Script>,
    pub sequence: u32,
    pub witness: Vec<Vec<u8>>,
}

impl From<&BdkTxIn> for TxIn {
    fn from(tx_in: &BdkTxIn) -> Self {
        TxIn {
            previous_output: OutPoint {
                txid: tx_in.previous_output.txid,
                vout: tx_in.previous_output.vout,
            },
            script_sig: Arc::new(Script(tx_in.script_sig.clone())),
            sequence: tx_in.sequence.0,
            witness: tx_in.witness.to_vec(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct TxOut {
    pub value: u64,
    pub script_pubkey: Arc<Script>,
}

impl From<&BdkTxOut> for TxOut {
    fn from(tx_out: &BdkTxOut) -> Self {
        TxOut {
            value: tx_out.value.to_sat(),
            script_pubkey: Arc::new(Script(tx_out.script_pubkey.clone())),
        }
    }
}

impl From<TxOut> for BdkTxOut {
    fn from(tx_out: TxOut) -> Self {
        BdkTxOut {
            value: BdkAmount::from_sat(tx_out.value),
            script_pubkey: BdkScriptBuf::from(tx_out.script_pubkey.deref().clone()),
        }
    }
}
#[cfg(test)]
mod tests {
    use crate::bitcoin::{Address, Psbt};
    use crate::bitcoin::Network;

    #[test]
    fn test_psbt() {
        let ps = Psbt::from_hex("70736274ff0100fd2b010100000006de3eefa79f3f2dc29a4a33e764f9bf54caf05e7e91fe234abb8fb9fec33a2e500400000000feffffff91329018b4b4ecc8708b115753ee8a3966c9fd08ca7d071d65b671d99cccb4210200000000feffffff86b8e6e806ffec40b9c4cd13377626191f11f3a51c397cd18586c0d68090c8a40500000000feffffffde3eefa79f3f2dc29a4a33e764f9bf54caf05e7e91fe234abb8fb9fec33a2e500300000000fefffffffd20860f68339759801117316eb14fe86ebed007d21399d75951ba6365d165940200000000feffffff0fea20d100653fcc900fb796ae93a6ddd352ec17836f0b324eb03752d01a9dc20100000000feffffff01a08601000000000022512083a969a65986d0a5ac3a15c33224200b85fcaa01718a26f6fcebb9b52513900c921b0d00000100fd4f0302000000000104d5a9ff49eec275298ba1094c217664223240a3b6ac50455997e184c97c25344f040000001716001492588f5e06a4e663a2806c1b7f562c4868f610f7fdffffff0a55bfc868ae502c1edb043ec657adde713dfb0a3f80008623ee90f488a0db7b040000001716001492588f5e06a4e663a2806c1b7f562c4868f610f7fdffffff64e98bc9756053b9e0ec2a114e9c03d20d5752a1439237a937a91bd67e9548500000000000ffffffffdb10f5bec8d7b82a8dd84ac47a7651005435760450c0fd989dfad90ec5432424010000001716001492588f5e06a4e663a2806c1b7f562c4868f610f7fdffffff06b00400000000000017a91426fe02b0e7331fa5d5b4b324aec50ee7b1880b6787220200000000000022512083a969a65986d0a5ac3a15c33224200b85fcaa01718a26f6fcebb9b52513900c90230b000000000022512062631738bd701015bbd96e7e191a21971c61b8d281278d315c030700bb683cc9580200000000000017a91426fe02b0e7331fa5d5b4b324aec50ee7b1880b6787580200000000000017a91426fe02b0e7331fa5d5b4b324aec50ee7b1880b67874b4100000000000017a91426fe02b0e7331fa5d5b4b324aec50ee7b1880b67870247304402207260a4a974b8c5b1643969601c0c4c372e3e9f4d0e9769face585549216d759e02207884b4d89d6c362c9152ec6c0ea3ae7b14bf97431adc58421a3a47116b67ae36012102b013041d26a8dd2de66c07e9ab9004ab4ae35f7fd6a6931d31ab78e26e6f92210247304402203a9ddf9e0f1b883af72272249e358dd21e3d0c2ed6eb05a443088542a9e1e1d402202718e3d0283d93872f1eb7a5b7eddc1244bfa9bf742fc142b52d1ee40f0962ef012102b013041d26a8dd2de66c07e9ab9004ab4ae35f7fd6a6931d31ab78e26e6f9221014188a54825d2a03cf04ed7d0ca1eeb7875c5ca43d6a54e9fc9fb6adb66a78f2bcb731cca6d9f20701887f2f53de04905d85fe043d17af04cf8d4e78fbedabaac21830247304402201d9497e33eed913d7f13460f8c3d316b41cea386b92749b89374bfccccd9682f02203f8f712085a2a77bad35b17be2d6b28254362e6df205730e2bcdf4908e1cc962012102b013041d26a8dd2de66c07e9ab9004ab4ae35f7fd6a6931d31ab78e26e6f922100000000010120580200000000000017a91426fe02b0e7331fa5d5b4b324aec50ee7b1880b6787010416001492588f5e06a4e663a2806c1b7f562c4868f610f7220602b013041d26a8dd2de66c07e9ab9004ab4ae35f7fd6a6931d31ab78e26e6f9221186d1d4c603100008000000080000000800000000000000000000100fd59020200000000010329bb5da0b430869bdcea542f35e7c6d061a78685bc0a8fe6a06b6fc373b72eaa020000001716001492588f5e06a4e663a2806c1b7f562c4868f610f7fdffffff79665a5fb13eed248894bef2d2cc6e4a4cb9d70362fbda1a54c66413c0b73be01706000000ffffffffe2adf899b6ef2f4936c65a7ef0ed7b30cdf27848ff9e78514791efe6202570ee000000001716001492588f5e06a4e663a2806c1b7f562c4868f610f7fdffffff04220200000000000022512083a969a65986d0a5ac3a15c33224200b85fcaa01718a26f6fcebb9b52513900c18643a000000000017a914e2196a97377428febf7b8094a7cf4f0d1c91a99787580200000000000017a91426fe02b0e7331fa5d5b4b324aec50ee7b1880b6787687701000000000017a91426fe02b0e7331fa5d5b4b324aec50ee7b1880b67870247304402204db8d8566a23f355b31aafd8dec27a6f7952a20266d56966c0bf3ef79088b660022049673892c2ae773da3132772632bd32414c151b68e922a853800704a6db563e9012102b013041d26a8dd2de66c07e9ab9004ab4ae35f7fd6a6931d31ab78e26e6f922101416f887d051dd40828c3890a636a34d4862f8910044ba8b868e75a4c56884f344ad6471a00a2480cd8d9a1c701d15d2134b2ae3c8fcd6c490a243168c8e1991432830247304402200121017eff10645c35335fd9c54cb60710bb1e2805d6b80837b560c33c1740f90220657dc9f6e0ac138c8dd4dd28d7ee8a87283a82d615caa70a938afa22a9666267012102b013041d26a8dd2de66c07e9ab9004ab4ae35f7fd6a6931d31ab78e26e6f922100000000010120580200000000000017a91426fe02b0e7331fa5d5b4b324aec50ee7b1880b6787010416001492588f5e06a4e663a2806c1b7f562c4868f610f7220602b013041d26a8dd2de66c07e9ab9004ab4ae35f7fd6a6931d31ab78e26e6f9221186d1d4c603100008000000080000000800000000000000000000100fd9803020000000001048516a2dd8b4a180cb2eb6964e9bf2a44d895eb1eee2115352a52a900bd20a195020000001716001492588f5e06a4e663a2806c1b7f562c4868f610f7ffffffff7a95bcb834ce5afcada7f860f0d9c0dad49571addd143d9a5dbfbff165a2fdae040000001716001492588f5e06a4e663a2806c1b7f562c4868f610f7ffffffff7c49ab4075951df55062535098a98db28d8d500d5cba38776f04184a5f56f9c60000000000ffffffff329a0ff2a722f2f3df25fad112688aa13b5d617999741934a265eff3af663b31050000001716001492588f5e06a4e663a2806c1b7f562c4868f610f7ffffffff07b00400000000000017a91426fe02b0e7331fa5d5b4b324aec50ee7b1880b6787220200000000000022512083a969a65986d0a5ac3a15c33224200b85fcaa01718a26f6fcebb9b52513900c425000000000000016001441af330cff1a3aeee547906db6f9923f76c85d4aa4010000000000002251209b57783ff38333b575f35634ba9795d28dddbe75b0e5fd582974df3b4f0fc37c580200000000000017a91426fe02b0e7331fa5d5b4b324aec50ee7b1880b6787580200000000000017a91426fe02b0e7331fa5d5b4b324aec50ee7b1880b6787532b29000000000017a91426fe02b0e7331fa5d5b4b324aec50ee7b1880b67870248304502210086d954899586a41b74a115924b4aba9c38c8c0861c21dfbd86252ecd5d244b3f0220030477a8afc7172a7e024ea6b6ee3eecf8c4f071e06b42476b4c55fded70ac0f012102b013041d26a8dd2de66c07e9ab9004ab4ae35f7fd6a6931d31ab78e26e6f922102473044022025b725285ad67c1fad6454f2eb611db7409e7cbc2eddfedc231254be7e29075c022076968e5cbeac5efa0fdf094110685308cbd9cfc981e2ff5e249ff975471ea3df012102b013041d26a8dd2de66c07e9ab9004ab4ae35f7fd6a6931d31ab78e26e6f922102483045022100ef7a22b7cfec390d4d7197ae5520cd485f02b23a4a5946d2c02b6da13a8ff1f502203b263036b143454ec51ee8f863f059175ca1932709fb97a4bc01a8d6edb8a03e832102066f44fe6d1c9ad05abb1ffcefaa0b46d0e49225e8d4732848e406c98f218c4602473044022015454b78ac30be8e3804992a73691302dcf13450d5f26a4d004415040b17522702205ff61ddd66fa557907cfb3db8c219d4319ca9d8fb8f0482769312360f32c9ed1012102b013041d26a8dd2de66c07e9ab9004ab4ae35f7fd6a6931d31ab78e26e6f922100000000010120580200000000000017a91426fe02b0e7331fa5d5b4b324aec50ee7b1880b6787010416001492588f5e06a4e663a2806c1b7f562c4868f610f7220602b013041d26a8dd2de66c07e9ab9004ab4ae35f7fd6a6931d31ab78e26e6f9221186d1d4c603100008000000080000000800000000000000000000100fd4f0302000000000104d5a9ff49eec275298ba1094c217664223240a3b6ac50455997e184c97c25344f040000001716001492588f5e06a4e663a2806c1b7f562c4868f610f7fdffffff0a55bfc868ae502c1edb043ec657adde713dfb0a3f80008623ee90f488a0db7b040000001716001492588f5e06a4e663a2806c1b7f562c4868f610f7fdffffff64e98bc9756053b9e0ec2a114e9c03d20d5752a1439237a937a91bd67e9548500000000000ffffffffdb10f5bec8d7b82a8dd84ac47a7651005435760450c0fd989dfad90ec5432424010000001716001492588f5e06a4e663a2806c1b7f562c4868f610f7fdffffff06b00400000000000017a91426fe02b0e7331fa5d5b4b324aec50ee7b1880b6787220200000000000022512083a969a65986d0a5ac3a15c33224200b85fcaa01718a26f6fcebb9b52513900c90230b000000000022512062631738bd701015bbd96e7e191a21971c61b8d281278d315c030700bb683cc9580200000000000017a91426fe02b0e7331fa5d5b4b324aec50ee7b1880b6787580200000000000017a91426fe02b0e7331fa5d5b4b324aec50ee7b1880b67874b4100000000000017a91426fe02b0e7331fa5d5b4b324aec50ee7b1880b67870247304402207260a4a974b8c5b1643969601c0c4c372e3e9f4d0e9769face585549216d759e02207884b4d89d6c362c9152ec6c0ea3ae7b14bf97431adc58421a3a47116b67ae36012102b013041d26a8dd2de66c07e9ab9004ab4ae35f7fd6a6931d31ab78e26e6f92210247304402203a9ddf9e0f1b883af72272249e358dd21e3d0c2ed6eb05a443088542a9e1e1d402202718e3d0283d93872f1eb7a5b7eddc1244bfa9bf742fc142b52d1ee40f0962ef012102b013041d26a8dd2de66c07e9ab9004ab4ae35f7fd6a6931d31ab78e26e6f9221014188a54825d2a03cf04ed7d0ca1eeb7875c5ca43d6a54e9fc9fb6adb66a78f2bcb731cca6d9f20701887f2f53de04905d85fe043d17af04cf8d4e78fbedabaac21830247304402201d9497e33eed913d7f13460f8c3d316b41cea386b92749b89374bfccccd9682f02203f8f712085a2a77bad35b17be2d6b28254362e6df205730e2bcdf4908e1cc962012102b013041d26a8dd2de66c07e9ab9004ab4ae35f7fd6a6931d31ab78e26e6f922100000000010120580200000000000017a91426fe02b0e7331fa5d5b4b324aec50ee7b1880b6787010416001492588f5e06a4e663a2806c1b7f562c4868f610f7220602b013041d26a8dd2de66c07e9ab9004ab4ae35f7fd6a6931d31ab78e26e6f9221186d1d4c603100008000000080000000800000000000000000000100fd6402020000000001031e80fcc75d96ac7d41a1d6db49318cf13cadc92c4d362d490d7de12da4a01980040000001716001492588f5e06a4e663a2806c1b7f562c4868f610f7fdffffffbece30eb68bf68d229716931bab2f4df02271493e9e5b1723f0dc9c396d014de0000000000ffffffff91dc43bb328b22c5c8a28a1bd4cda8cc4c268fa2f630df17a0af5a184a0d2200000000001716001492588f5e06a4e663a2806c1b7f562c4868f610f7fdffffff04220200000000000022512083a969a65986d0a5ac3a15c33224200b85fcaa01718a26f6fcebb9b52513900c384f360000000000225120a6e08f89b93b9496cd518a69c396d152900cf2b033d32c9e521d0b0f8d6dc2cc580200000000000017a91426fe02b0e7331fa5d5b4b324aec50ee7b1880b67870ee500000000000017a91426fe02b0e7331fa5d5b4b324aec50ee7b1880b67870247304402202bd37999e8f7393a506506bdac803787bcd0972cda464afda776e0d592dc385902200142f26bffc4f4d54ff8efd4f7815d49eaa20479c24790bdf7f33f0d44b10707012102b013041d26a8dd2de66c07e9ab9004ab4ae35f7fd6a6931d31ab78e26e6f922101410ea9de1c36503738197faa34ff95209be4815c8ab5ef4b371b869de6553d5b5f866031283f26f41586a94dc623c997b02de4646f46d56353430485c5cded353583024730440220547579b427885b827037399cc5207acc9f92578337ef25fb86ccf15005810f1102207b4ad8dd0f062619938856bc4ebae4048bce20230d4c92947810717cbcb8e5f7012102b013041d26a8dd2de66c07e9ab9004ab4ae35f7fd6a6931d31ab78e26e6f922100000000010120580200000000000017a91426fe02b0e7331fa5d5b4b324aec50ee7b1880b6787010416001492588f5e06a4e663a2806c1b7f562c4868f610f7220602b013041d26a8dd2de66c07e9ab9004ab4ae35f7fd6a6931d31ab78e26e6f9221186d1d4c603100008000000080000000800000000000000000000100c202000000000101c1f2fa08d68a341fc04966ff8d899307e986b3b026301446a9f45faa195ff33301000000001b00000002516d070000000000225120b032c314d8c395ea6f5a6767084950f39a8993152517624810bba6b22eae1a66a08601000000000017a91426fe02b0e7331fa5d5b4b324aec50ee7b1880b67870140391dc32d52be0583aca4bd410f8429de26e4111d75bfbf8115d7824ac6b4009dab22e90a6cc4b0df9081024b608cd31b4b04b9f8d7ec2ddd159e152b0e93bc6100000000010120a08601000000000017a91426fe02b0e7331fa5d5b4b324aec50ee7b1880b6787010416001492588f5e06a4e663a2806c1b7f562c4868f610f7220602b013041d26a8dd2de66c07e9ab9004ab4ae35f7fd6a6931d31ab78e26e6f9221186d1d4c6031000080000000800000008000000000000000000000".to_string()).unwrap();
        println!("{}", ps.extract_tx().unwrap().compute_txid());
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
