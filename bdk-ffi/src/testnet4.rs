use bdk_wallet::bitcoin::{absolute, block, script, transaction, Amount, Block, BlockHash, CompactTarget, OutPoint, Sequence, Transaction, TxIn, TxMerkleNode, TxOut, Txid, Witness};
use bdk_wallet::bitcoin::hashes::{sha256d, Hash};
use bdk_wallet::bitcoin::opcodes::all::OP_CHECKSIG;
use bdk_wallet::bitcoin::script::{write_scriptint, PushBytes};
use bdk_wallet::bitcoin::network::Network as BitcoinNetwork;
use serde::{Deserialize, Serialize};

#[derive(Copy, PartialEq, Eq, PartialOrd, Ord, Clone, Hash, Debug)]
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CustomNetwork {
    Bitcoin,
    Signet,
    Testnet,
    Testnet4,
    Regtest,
}

impl From<BitcoinNetwork> for CustomNetwork {
    fn from(value: BitcoinNetwork) -> Self {
        match value {
            BitcoinNetwork::Bitcoin => {
                CustomNetwork::Bitcoin
            }
            BitcoinNetwork::Testnet => {
                CustomNetwork::Testnet
            }
            BitcoinNetwork::Signet => {
                CustomNetwork::Signet
            }
            BitcoinNetwork::Regtest => {
                CustomNetwork::Regtest
            }
            _ => {
                unreachable!()
            }
        }
    }
}

impl CustomNetwork {
    pub fn to_bitcoin_network(&self) -> BitcoinNetwork {
        match self {
            CustomNetwork::Bitcoin => {
                BitcoinNetwork::Bitcoin
            }
            CustomNetwork::Signet => {
                BitcoinNetwork::Signet
            }
            CustomNetwork::Testnet => {
                BitcoinNetwork::Testnet
            }
            CustomNetwork::Testnet4 => {
                BitcoinNetwork::Testnet
            }
            CustomNetwork::Regtest => {
                BitcoinNetwork::Regtest
            }
        }
    }
}

#[rustfmt::skip]
const TESTNET4_GENESIS_OUTPUT_PK: [u8; 33] = [
    0x00; 33
];

fn bitcoin_testnet4_genesis_tx() -> Transaction {
    // Base
    let mut ret = Transaction {
        version: transaction::Version::ONE,
        lock_time: absolute::LockTime::ZERO,
        input: vec![],
        output: vec![],
    };

    let mut in_script = script::Builder::new()
        .push_int(486604799);
    // .push_int_non_minimal(4)
    // .push_slice(b"03/May/2024 000000000000000000001ebd58c244970b3aa9d783bb001011fbe8ea8e98e00e")
    // .into_script();

    let mut buf = [0u8; 8];
    let len = write_scriptint(&mut buf, 4);
    in_script = in_script.push_slice(&<&PushBytes>::from(&buf)[..len]);

    let pb = unsafe{&*(b"03/May/2024 000000000000000000001ebd58c244970b3aa9d783bb001011fbe8ea8e98e00e" as *const [u8] as *const PushBytes)};
    in_script = in_script.push_slice(&pb);


    let in_script = in_script.into_script();

    let out_script = script::Builder::new().push_slice(TESTNET4_GENESIS_OUTPUT_PK).push_opcode(OP_CHECKSIG).into_script();


    ret.input.push(TxIn {
        previous_output: OutPoint { txid: Txid::from_byte_array([0; 32]), vout: u32::MAX },
        script_sig: in_script,
        sequence: Sequence::MAX,
        witness: Witness::default(),
    });

    ret.output.push(TxOut { value: Amount::from_sat(50 * 100_000_000), script_pubkey: out_script });

    // end
    ret
}

pub fn testnet4_genesis_block() -> Block {
    let txdata = vec![bitcoin_testnet4_genesis_tx()];
    let hash: sha256d::Hash = txdata[0].compute_txid().into();
    let merkle_root: TxMerkleNode = hash.into();

    Block {
        header: block::Header {
            version: block::Version::ONE,
            prev_blockhash: BlockHash::all_zeros(),
            merkle_root,
            time: 1714777860,
            bits: CompactTarget::from_consensus(0x1d00ffff),
            nonce: 393743547,
        },
        txdata,
    }
}