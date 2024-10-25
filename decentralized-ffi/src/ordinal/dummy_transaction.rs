use bdk_core::bitcoin::Weight;
use bdk_wallet::bitcoin::{
    absolute::LockTime,
    Amount, key::constants::SCHNORR_SIGNATURE_SIZE, OutPoint, ScriptBuf, Sequence, Transaction, transaction::Version, TxIn, TxOut, Witness,
};
pub(crate) struct DummyTransaction(pub Transaction);

impl DummyTransaction {
    pub(crate) fn new() -> Self {
        DummyTransaction(Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![],
            output: vec![],
        })
    }

    pub(crate) fn append_input(
        &mut self,
        script_pubkey: ScriptBuf,
        sig: Option<ScriptBuf>,
        witness: Option<Witness>,
    ) {
        let sig = sig.unwrap_or({
            if script_pubkey.is_p2sh() {
                script_pubkey.to_p2sh()
            } else if script_pubkey.is_p2wsh() {
                script_pubkey.to_p2wsh()
            } else {
                ScriptBuf::new()
            }
        });
        let witness = witness.unwrap_or({
            match true {
                _ if script_pubkey.is_p2wsh() => {}
                _ if script_pubkey.is_p2sh() => {}
                _ => {}
            }
            if script_pubkey.is_p2tr() {
                Witness::from_slice(&[&[0; SCHNORR_SIGNATURE_SIZE]])
            } else if script_pubkey.is_p2wpkh() {
                Witness::from_slice(&[vec![0; 105]]) // 第一个值最大73 这里已知在xx下
            } else { Witness::new() }
        });
        self.0.input.push(TxIn {
            previous_output: OutPoint::null(),
            script_sig: sig,
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness,
        })
    }

    pub(crate) fn append_output(&mut self, script_pubkey: ScriptBuf) {
        self.0.output.push(TxOut {
            value: Amount::ZERO,
            script_pubkey,
        })
    }

    pub(crate) fn vsize(&self) -> usize {
        self.0.vsize()
    }

    pub(crate) fn weight(&self) -> Weight {
        self.0.weight()
    }
}
