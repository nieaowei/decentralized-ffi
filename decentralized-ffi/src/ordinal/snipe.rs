use std::collections::HashMap;
use std::num::ParseIntError;
use bdk_wallet::bitcoin::{Address, Amount, FeeRate, OutPoint, Psbt, ScriptBuf, Sequence, Transaction, TxIn, TxOut};
use bdk_wallet::bitcoin::absolute::LockTime;
use bdk_wallet::bitcoin::policy::get_virtual_tx_size;
use bdk_wallet::bitcoin::psbt::Input;
use bdk_wallet::bitcoin::transaction::Version;
use ordinals::{Edict, RuneId, Runestone};
use crate::error::EsploraError;
use crate::ordinal::dummy_transaction::DummyTransaction;
use crate::types::LocalOutput;
//
// pub(crate) const ADDITIONAL_INPUT_VBYTES: usize = 58;
// pub(crate) const ADDITIONAL_OUTPUT_VBYTES: usize = 43;
// pub(crate) const SCHNORR_SIGNATURE_SIZE: usize = 64;

// pub(crate) const DUMMY_UTXO: Amount = Amount::from_sat(600);

pub(crate) const APPEND_NETWORK_FEE_SAT: Amount = Amount::from_sat(666);


#[derive(Debug, thiserror::Error, uniffi::Error)]
pub(crate) enum SnipeError {
    #[error("utxo not enough")]
    UtxoNotEnough,

    #[error("api error")]
    ApiError,

    #[error("amount error")]
    U128Parse,

    #[error("missing dummy utxo")]
    MissingDummyUtxo,
}

impl From<ParseIntError> for SnipeError {
    fn from(_: ParseIntError) -> Self {
        Self::U128Parse
    }
}

impl From<EsploraError> for SnipeError {
    fn from(_: EsploraError) -> Self {
        Self::ApiError
    }
}

pub(crate) struct SnipeRunePsbtBuilder {
    pub(crate) cardinal_utxos: Vec<LocalOutput>,
    pub(crate) snipe_utxo_pairs: Vec<(TxIn, TxOut, TxOut)>, // ordi input and prevout , ordi output
    pub(crate) pay_addr: Address,
    pub(crate) recv_addr: Address,
    pub(crate) min_fee: Amount,
    pub(crate) fee_rate: FeeRate,
}

impl SnipeRunePsbtBuilder {
    pub(crate) fn build(self) -> Result<Psbt, SnipeError> {
        build_snipe_rune_psbt(self.snipe_utxo_pairs, self.cardinal_utxos, self.pay_addr, self.recv_addr, self.min_fee, self.fee_rate)
    }
}

fn build_snipe_rune_psbt(
    snipe_utxo_pairs: Vec<(TxIn, TxOut, TxOut)>,
    cardinal_utxos: Vec<LocalOutput>,
    pay_addr: Address,
    rev_addr: Address,
    min_fee: Amount,
    fee_rate: FeeRate,
) -> Result<Psbt, SnipeError> {
    let mut dummy_signed_tx_1 = DummyTransaction::new();

    let mut inputs = Vec::new();
    let mut signed_psbt_inputs = Vec::new();
    let mut inputs_amount = Amount::ZERO;

    let mut outputs = Vec::new();
    let mut outputs_amount = Amount::ZERO;

    for (txin, prevout, txout) in snipe_utxo_pairs {
        inputs.push({
            TxIn {
                previous_output: txin.previous_output.clone(),
                sequence: txin.sequence,
                ..Default::default()
            }
        });

        dummy_signed_tx_1.append_input(
            prevout.script_pubkey.clone(),
            Some(txin.script_sig.clone()),
            Some(txin.witness.clone()),
        );

        signed_psbt_inputs.push(Input {
            witness_utxo: Some({
                TxOut {
                    value: prevout.value,
                    script_pubkey: prevout.script_pubkey.clone(),
                }
            }),
            final_script_witness: Some(txin.witness.clone()), // 可以优化少打一个请求 直接解析pool
            final_script_sig: Some(txin.script_sig.clone()),
            ..Default::default()
        });

        outputs.push(txout.clone());
        dummy_signed_tx_1.append_output(txout.script_pubkey.clone());
        outputs_amount += txout.value;
        inputs_amount += prevout.value;
    }

    let mut buyer_unsigned_tx = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: inputs,
        output: outputs,
    };

    // 占位和找零共用
    buyer_unsigned_tx.output.insert(
        0,
        TxOut {
            value: Amount::ZERO,
            script_pubkey: rev_addr.script_pubkey(),
        },
    );
    dummy_signed_tx_1.append_output(rev_addr.script_pubkey());

    let mut unsigned_tx = buyer_unsigned_tx;
    // merge output
    let mut psbt_inputs = signed_psbt_inputs;
    let need_amount = outputs_amount - inputs_amount; // 需要的 todo 如果为负数
    let mut extra_network_fee = Amount::ZERO; // RBF需要总交易费用大于原始交易
    let mut amount = Amount::ZERO; // 计算
    let mut ok = false;
    let mut init = false; // 第一个input填充

    'outer: for utxo in cardinal_utxos {
        amount += utxo.txout.value.0;

        if !init {
            psbt_inputs.insert(0, {
                Input {
                    witness_utxo: Some({
                        TxOut {
                            value: utxo.txout.value.0,
                            script_pubkey: pay_addr.script_pubkey(),
                        }
                    }),
                    ..Default::default()
                }
            });

            unsigned_tx.input.insert(0, {
                TxIn {
                    previous_output: utxo.outpoint.clone().into(),
                    sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                    ..Default::default()
                }
            });
            init = true;
        } else {
            psbt_inputs.push({
                Input {
                    witness_utxo: Some({
                        TxOut {
                            value: utxo.txout.value.0,
                            script_pubkey: pay_addr.script_pubkey(),
                        }
                    }),
                    ..Default::default()
                }
            });

            unsigned_tx.input.push({
                TxIn {
                    previous_output: utxo.outpoint.clone().into(),
                    sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                    ..Default::default()
                }
            });
        }
        dummy_signed_tx_1.append_input(pay_addr.script_pubkey(), None, None);

        let network_fee = fee_rate.fee_wu(dummy_signed_tx_1.weight()).unwrap();
        println!("{}", dummy_signed_tx_1.vsize());
        loop {
            if let Some(unfilled) =
                amount.checked_sub(network_fee + need_amount + extra_network_fee)
            {
                // 找零小于粉尘值
                if unfilled < pay_addr.script_pubkey().minimal_non_dust() {
                    break;
                }

                if (network_fee + extra_network_fee) > min_fee {
                    // 大于原始交易的总费用才能上链
                    unsigned_tx.output.first_mut().unwrap().value = unfilled; // 找零

                    ok = true;
                    break 'outer;
                }
                // 不够就追加
                extra_network_fee += Amount::from_sat(1);
            } else {
                continue 'outer;
            }
        }
    }
    if !ok {
        return Err(SnipeError::UtxoNotEnough);
    }

    let o_len = unsigned_tx.output.len();
    let psbt = Psbt {
        unsigned_tx,
        version: 0,
        xpub: Default::default(),
        proprietary: Default::default(),
        unknown: Default::default(),
        inputs: psbt_inputs,
        outputs: vec![Default::default(); o_len],
    };

    Ok(psbt)
}


pub(crate) struct SplitRunePsbtBuilder {
    pub(crate) ordi_addr_outpoint_with_amount: (Address, OutPoint, Amount),
    pub(crate) runes: HashMap<RuneId, u128>, // all rune
    pub(crate) recv_addr: Address, // rune recv address
    pub(crate) change_addr: Address, // change address
    pub(crate) fee_rate: FeeRate,
}

impl SplitRunePsbtBuilder {
    pub(crate) fn build(self) -> Result<Psbt, SnipeError> {
        build_split_rune_psbt(
            self.ordi_addr_outpoint_with_amount, self.runes, self.recv_addr, self.change_addr, self.fee_rate)
    }
}


fn build_split_rune_psbt(
    (ordi_addr, outpoint, amount): (Address, OutPoint, Amount), // all rune
    runes: HashMap<RuneId, u128>, // all rune
    recv_addr: Address, // rune recv address
    change_addr: Address, // change address
    fee_rate: FeeRate,
) -> Result<Psbt, SnipeError> {
    let mut unsigned_tx = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![],
        output: vec![],
    };
    let mut dummy_tx = DummyTransaction::new();
    let mut psbt_inputs = Vec::new();
    // input rune
    unsigned_tx.input.push(TxIn {
        previous_output: outpoint,
        script_sig: Default::default(),
        sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
        witness: Default::default(),
    });

    psbt_inputs.push(Input {
        witness_utxo: Some(TxOut {
            value: amount,
            script_pubkey: ordi_addr.script_pubkey(),
        }),
        ..Default::default()
    });
    dummy_tx.append_input(ordi_addr.script_pubkey(), None, None);

    // build edict
    let mut rs = Runestone {
        edicts: vec![],
        etching: None,
        mint: None,
        pointer: None,
    };

    let runes_len = runes.len() as u64;
    for (index, rune) in runes.into_iter().enumerate() {
        if runes_len > 1 {
            rs.edicts.push(Edict {
                id: rune.0,
                amount: rune.1,
                output: index as u32,
            });
        }

        // rune index
        unsigned_tx.output.push(TxOut {
            value: recv_addr.script_pubkey().minimal_non_dust(),
            script_pubkey: recv_addr.script_pubkey(),
        });
        dummy_tx.append_output(recv_addr.script_pubkey());
    }

    if runes_len > 1 {
        unsigned_tx.output.push(TxOut { value: Amount::ZERO, script_pubkey: ScriptBuf::from_bytes(rs.encipher().into_bytes()) });
        dummy_tx.append_output(ScriptBuf::from_bytes(rs.encipher().into_bytes()));
    }

    // change
    unsigned_tx.output.push(TxOut {
        value: Amount::ZERO,
        script_pubkey: change_addr.script_pubkey(),
    });
    dummy_tx.append_output(change_addr.script_pubkey());

    let network_fee = fee_rate.fee_vb(dummy_tx.vsize() as u64).unwrap();
    unsigned_tx.output.last_mut().unwrap().value = amount - network_fee - recv_addr.script_pubkey().minimal_non_dust() * runes_len;

    let o_len = unsigned_tx.output.len();
    let psbt = Psbt {
        unsigned_tx,
        version: 0,
        xpub: Default::default(),
        proprietary: Default::default(),
        unknown: Default::default(),
        inputs: psbt_inputs,
        outputs: vec![Default::default(); o_len],
    };
    Ok(psbt)
}


pub struct SnipeInscriptionPsbtBuilder {
    pub cardinal_utxos: Vec<LocalOutput>,
    pub dummy_utxos: Vec<LocalOutput>,
    pub snipe_utxo_pairs: Vec<(TxIn, TxOut, TxOut)>, // ordi input and prevout , ordi output
    pub pay_addr: Address,
    pub recv_addr: Address,
    pub min_fee: Amount,
    pub fee_rate: FeeRate,
}

impl SnipeInscriptionPsbtBuilder {
    pub fn build(self) -> Result<Psbt, SnipeError> {
        build_snipe_inscription_psbt(
            self.snipe_utxo_pairs,
            self.cardinal_utxos,
            self.dummy_utxos,
            self.pay_addr,
            self.recv_addr,
            self.min_fee,
            self.fee_rate,
        )
    }
}

fn build_snipe_inscription_psbt(
    snipe_utxo_pairs: Vec<(TxIn, TxOut, TxOut)>,
    cardinal_utxos: Vec<LocalOutput>,
    dummy_utxos: Vec<LocalOutput>,
    pay_addr: Address,
    rev_addr: Address,
    min_fee: Amount,
    fee_rate: FeeRate,
) -> Result<Psbt, SnipeError> {
    let mut dummy_signed_tx_1 = DummyTransaction::new();

    let mut inputs = Vec::new();
    let mut signed_psbt_inputs = Vec::new();
    let mut inputs_amount = Amount::ZERO;

    let mut outputs = Vec::new();
    let mut outputs_amount = Amount::ZERO;

    let Some(dummy_utxo) = dummy_utxos.first() else {
        return Err(SnipeError::MissingDummyUtxo);
    };

    inputs.push(TxIn {
        previous_output: dummy_utxo.outpoint.clone().into(),
        script_sig: Default::default(),
        sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
        witness: Default::default(),
    });
    signed_psbt_inputs.push(Input {
        witness_utxo: Some({
            TxOut {
                value: dummy_utxo.txout.value.0,
                script_pubkey: dummy_utxo.txout.script_pubkey.0.clone(),
            }
        }),
        ..Default::default()
    });
    dummy_signed_tx_1.append_input(dummy_utxo.txout.script_pubkey.0.clone(), None, None);
    inputs_amount += dummy_utxo.txout.value.0;

    for (txin, prevout, txout) in snipe_utxo_pairs {
        inputs.push({
            TxIn {
                previous_output: txin.previous_output.clone(),
                sequence: txin.sequence,
                ..Default::default()
            }
        });

        dummy_signed_tx_1.append_input(
            prevout.script_pubkey.clone(),
            Some(txin.script_sig.clone()),
            Some(txin.witness.clone()),
        );

        signed_psbt_inputs.push(Input {
            witness_utxo: Some({
                TxOut {
                    value: prevout.value,
                    script_pubkey: prevout.script_pubkey.clone(),
                }
            }),
            final_script_witness: Some(txin.witness.clone()), // 可以优化少打一个请求 直接解析pool
            final_script_sig: Some(txin.script_sig.clone()),
            ..Default::default()
        });
        inputs_amount += prevout.value;

        outputs.push(txout.clone());
        dummy_signed_tx_1.append_output(txout.script_pubkey.clone());
        outputs_amount += txout.value;
    }

    let mut buyer_unsigned_tx = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: inputs,
        output: outputs,
    };

    // 占位和找零共用
    buyer_unsigned_tx.output.insert(
        0,
        TxOut {
            value: Amount::ZERO,
            script_pubkey: rev_addr.script_pubkey(),
        },
    );
    dummy_signed_tx_1.append_output(rev_addr.script_pubkey());

    let mut unsigned_tx = buyer_unsigned_tx;
    // merge output
    let mut psbt_inputs = signed_psbt_inputs;
    let need_amount = outputs_amount - inputs_amount; // 需要的
    let mut extra_network_fee = Amount::ZERO; // RBF需要总交易费用大于原始交易
    let mut amount = Amount::ZERO; // 计算
    let mut ok = false;

    'outer: for utxo in cardinal_utxos {
        amount += utxo.txout.value.0;


        psbt_inputs.push({
            Input {
                witness_utxo: Some({
                    TxOut {
                        value: utxo.txout.value.0,
                        script_pubkey: pay_addr.script_pubkey(),
                    }
                }),
                ..Default::default()
            }
        });

        unsigned_tx.input.push({
            TxIn {
                previous_output: utxo.outpoint.clone().into(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                ..Default::default()
            }
        });

        dummy_signed_tx_1.append_input(pay_addr.script_pubkey(), None, None);

        let network_fee = fee_rate.fee_vb(dummy_signed_tx_1.vsize() as u64).unwrap();

        loop {
            if let Some(unfilled) =
                amount.checked_sub(network_fee + need_amount + extra_network_fee)
            {
                // 找零小于粉尘值
                if unfilled < pay_addr.script_pubkey().minimal_non_dust() {
                    break;
                }

                if (network_fee + extra_network_fee) > min_fee {
                    // 大于原始交易的总费用才能上链
                    unsigned_tx.output.first_mut().unwrap().value = unfilled; // 找零

                    ok = true;
                    break 'outer;
                }
                // 不够就追加
                extra_network_fee += Amount::from_sat(1);
            } else {
                continue 'outer;
            }
        }
    }
    if !ok {
        return Err(SnipeError::UtxoNotEnough);
    }

    let o_len = unsigned_tx.output.len();
    let psbt = Psbt {
        unsigned_tx,
        version: 0,
        xpub: Default::default(),
        proprietary: Default::default(),
        unknown: Default::default(),
        inputs: psbt_inputs,
        outputs: vec![Default::default(); o_len],
    };


    Ok(psbt)
}


pub struct SplitInscriptionPsbtBuilder {
    pub(crate) ordi_addr_outpoint_with_amount: (Address, OutPoint, Amount),
    pub(crate) inscription_offsets: Vec<Amount>,
    pub(crate) recv_addr: Address, // rune recv address
    pub(crate) change_addr: Address, // change address
    pub(crate) fee_rate: FeeRate,
}

impl SplitInscriptionPsbtBuilder {
    pub(crate) fn build(self) -> Result<Psbt, SnipeError> {
        build_split_inscription_psbt(
            self.ordi_addr_outpoint_with_amount,
            self.inscription_offsets,
            self.recv_addr,
            self.change_addr,
            self.fee_rate,
        )
    }
}

fn build_split_inscription_psbt(
    (ordi_addr, outpoint, amount): (Address, OutPoint, Amount), // all inscription
    inscription_offsets: Vec<Amount>,
    recv_addr: Address, // rune recv address
    change_addr: Address, // change address
    fee_rate: FeeRate,
) -> Result<Psbt, SnipeError> {
    let mut unsigned_tx = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![],
        output: vec![],
    };
    let mut dummy_tx = DummyTransaction::new();
    let mut psbt_inputs = Vec::new();

    // all input inscription
    unsigned_tx.input.push(TxIn {
        previous_output: outpoint,
        sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
        ..Default::default()
    });

    psbt_inputs.push(Input {
        witness_utxo: Some(TxOut {
            value: amount,
            script_pubkey: ordi_addr.script_pubkey(),
        }),
        ..Default::default()
    });
    dummy_tx.append_input(ordi_addr.script_pubkey(), None, None);

    let mut output_amount = Amount::ZERO;

    unsigned_tx.output.push(TxOut {
        value: Amount::from_sat(600),
        script_pubkey: change_addr.script_pubkey(),
    });
    dummy_tx.append_output(change_addr.script_pubkey());
    output_amount += Amount::from_sat(600);

    for offset in inscription_offsets.into_iter() {
        // index
        unsigned_tx.output.push(TxOut {
            value: offset,
            script_pubkey: recv_addr.script_pubkey(),
        });
        dummy_tx.append_output(recv_addr.script_pubkey());
        output_amount += offset;
    }

    // change
    unsigned_tx.output.push(TxOut {
        value: Amount::ZERO,
        script_pubkey: change_addr.script_pubkey(),
    });
    dummy_tx.append_output(change_addr.script_pubkey());

    let network_fee = fee_rate.fee_vb(dummy_tx.vsize() as u64).unwrap();
    unsigned_tx.output.last_mut().unwrap().value = amount - network_fee - output_amount;

    let o_len = unsigned_tx.output.len();
    let psbt = Psbt {
        unsigned_tx,
        version: 0,
        xpub: Default::default(),
        proprietary: Default::default(),
        unknown: Default::default(),
        inputs: psbt_inputs,
        outputs: vec![Default::default(); o_len],
    };
    Ok(psbt)
}
