use std::collections::HashMap;
use std::convert::Into;
use std::str::FromStr;
use std::sync::Arc;
use bdk_wallet::bitcoin;
use bdk_wallet::bitcoin::TapSighashType;
use uniffi::export;
use crate::bitcoin::{Address, Amount, FeeRate, Psbt, Transaction, TxIn, TxOut};
use crate::ordinal::rune::RuneId;
use crate::ordinal::snipe::{SnipeError};
use crate::types::LocalOutput;

pub(crate) mod snipe;
mod dummy_transaction;

pub(crate) mod rune;
pub(crate) mod inscription;

#[derive(uniffi::Record, Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct TxInAndTxOut {
    pub txin: TxIn,
    pub txout: TxOut,
}

#[uniffi::export]
pub fn get_single_anyone_pay_tx_pair(tx: &Transaction) -> Vec<TxInAndTxOut> {
    let mut pair = Vec::new();
    for (i, txin) in tx.input().iter().enumerate() {
        if let Some(sign) = txin.witness.first() {
            if let Some(sign_type) = sign.last() {
                if let Ok(t) = TapSighashType::from_consensus_u8(sign_type.clone()) {
                    if t == TapSighashType::SinglePlusAnyoneCanPay {
                        if let Some(txout) = tx.output().get(i) {
                            pair.push(TxInAndTxOut { txin: txin.clone(), txout: txout.clone() });
                        }
                    }
                }
            }
        }
    }
    pair
}

#[derive(uniffi::Record, Debug, Clone, PartialEq, Eq, Hash)]
pub struct SnipeRuneUtxoPair {
    pub txin: TxIn,
    pub prevout: TxOut,
    pub txout: TxOut,
    pub rune_id: Arc<RuneId>,
    pub amount: String,
}

#[derive(uniffi::Record, Debug)]
pub struct SnipePsbtPair {
    pub snipe: Arc<Psbt>,
    pub split: Arc<Psbt>,
}

#[uniffi::export]
pub fn build_rune_snipe_psbt(
    cardinal_utxos: Vec<LocalOutput>,
    snipe_utxo_pairs: Vec<SnipeRuneUtxoPair>,
    pay_addr: Arc<Address>,
    ordi_addr: Arc<Address>,
    snipe_min_fee: Arc<Amount>,
    snipe_rate: Arc<FeeRate>,
    split_rate: Arc<FeeRate>,

    rune_recv_addr: Option<Arc<Address>>, // ordi addr if none
) -> Result<SnipePsbtPair, snipe::SnipeError> {
    let mut runes_map = HashMap::new();
    for rune in snipe_utxo_pairs.iter() {
        let amount = u128::from_str(&rune.amount)?;
        let rune_id = ordinals::RuneId { block: rune.rune_id.block, tx: rune.rune_id.tx };
        if let Some(a) = runes_map.get_mut(&rune_id) {
            *a += amount;
        } else {
            runes_map.insert(rune_id, amount);
        }
    }

    let snipe_psbt = snipe::SnipeRunePsbtBuilder {
        cardinal_utxos,
        snipe_utxo_pairs: snipe_utxo_pairs.into_iter().map(|x| ((&x.txin).into(), (&x.prevout).into(), (&x.txout).into())).collect(),
        pay_addr: pay_addr.0.clone(),
        recv_addr: ordi_addr.0.clone(),
        min_fee: snipe_min_fee.0,
        fee_rate: snipe_rate.0,
    }.build()?;

    let tx = snipe_psbt.clone().extract_tx_unchecked_fee_rate();
    let outpoint = tx.output.first().unwrap();

    let split_psbt = snipe::SplitRunePsbtBuilder {
        ordi_addr_outpoint_with_amount: (ordi_addr.0.clone(), bitcoin::OutPoint { txid: tx.compute_txid(), vout: 0 }, outpoint.value),
        runes: runes_map,
        recv_addr: rune_recv_addr.unwrap_or(ordi_addr).0.clone(),
        change_addr: pay_addr.0.clone(),
        fee_rate: split_rate.0,
    }.build()?;

    Ok(SnipePsbtPair {
        snipe: Arc::new(Psbt::from(snipe_psbt)),
        split: Arc::new(Psbt::from(split_psbt)),
    })
}

#[derive(uniffi::Record, Debug, Clone, PartialEq, Eq, Hash)]
pub struct SnipeInscriptionPair {
    pub txin: TxIn,
    pub prevout: TxOut,
    pub txout: TxOut,
}

#[uniffi::export]
pub fn build_inscription_snipe_psbt(
    cardinal_utxos: Vec<LocalOutput>,
    dummy_utxos: Vec<LocalOutput>,
    snipe_utxo_pairs: Vec<SnipeInscriptionPair>,
    pay_addr: Arc<Address>,
    ordi_addr: Arc<Address>,
    snipe_min_fee: Arc<Amount>,
    snipe_rate: Arc<FeeRate>,
    split_rate: Arc<FeeRate>,
    inscription_recv_addr: Option<Arc<Address>>, // ordi addr if none
) -> Result<SnipePsbtPair, SnipeError> {
    let snipe_psbt = snipe::SnipeInscriptionPsbtBuilder {
        cardinal_utxos,
        snipe_utxo_pairs: snipe_utxo_pairs.iter().map(|x| ((&x.txin).into(), (&x.prevout).into(), (&x.txout).into())).collect(),
        dummy_utxos,
        pay_addr: pay_addr.0.clone(),
        recv_addr: ordi_addr.0.clone(),
        min_fee: snipe_min_fee.0,
        fee_rate: snipe_rate.0,
    }.build()?;

    let tx = snipe_psbt.clone().extract_tx_unchecked_fee_rate();
    let outpoint = tx.output.first().unwrap();

    let split_psbt = snipe::SplitInscriptionPsbtBuilder {
        ordi_addr_outpoint_with_amount: (ordi_addr.0.clone(), bitcoin::OutPoint { txid: tx.compute_txid(), vout: 0 }, outpoint.value),
        inscription_offsets: snipe_utxo_pairs.into_iter().map(|x| x.prevout.value.0).collect(),
        recv_addr: inscription_recv_addr.unwrap_or(ordi_addr).0.clone(),
        change_addr: pay_addr.0.clone(),
        fee_rate: split_rate.0,
    }.build()?;

    Ok(SnipePsbtPair {
        snipe: Arc::new(Psbt::from(snipe_psbt)),
        split: Arc::new(Psbt::from(split_psbt)),
    })
}

#[cfg(test)]
mod tests {
    use bdk_wallet::{bitcoin, serde_json};
    use bdk_wallet::bitcoin::absolute::LockTime;
    use bdk_wallet::bitcoin::consensus::encode::{deserialize_hex, serialize_hex};
    use bdk_wallet::bitcoin::{ScriptBuf, Witness};
    use bdk_wallet::bitcoin::transaction::Version;
    use ordinals::Runestone;
    use regex::Regex;
    use crate::bitcoin::{OutPoint, Script};
    use crate::esplora::EsploraClient;
    use crate::ordinal::dummy_transaction::DummyTransaction;
    use crate::ordinal::rune::extract_rune_from_script;
    use crate::types::ConfirmationTime;
    use crate::utils::{get_json_info_from_url, new_txin_from_hex, new_txout_from_hex};
    use crate::wallet::KeychainKind;
    use super::*;

    #[test]
    fn test_regex() {
        let reg = Regex::new(r"hmac\((.*)\)").unwrap();
        let c = reg.captures("hmac(dsasdsaddsadad,dsads)");
        if let Some(c) = c {
            for a in c.iter() {
                if let Some(a) = a {
                    println!("{}", a.as_str());
                }
            }
        }
    }
    #[test]
    fn test_witness() {
        let back: bitcoin::Witness = serde_json::from_str(r#"["9d8a066732ed20e446f72ced810a6e9988b742215120051dd96c4451789f903f1fa97eab574454e0b63b47854cb18802e7548d944c1132b6c08c25630cbd84d3"]"#).unwrap();

        // let w:Vec<u8> = deserialize_hex("f450981ec815b0851983fbc2a9f906c7e067cca818240d7cd0fa9f2a800117ca6527dd5b7d36b44b13c68e497ed59aa5bb63beeb449a5c8b5bd997a65e003c83").unwrap();
        println!("{:?}", TapSighashType::from_consensus_u8(*back.to_vec().last().unwrap().last().unwrap()));
    }
    #[test]
    fn test_get_ordinal_tx_pair() {
        // let js = r#"{"code":200,"msg":"","data":[{"id":34734391,"runeId":"842166:27","ticker":"EPIC•EPIC•EPIC•EPIC","symbol":"\uD83D\uDCA5","divisibility":2,"address":"bc1pezaelju5x9eqxlq5zzypxrpr3ggq79cy5fae7vwfku672vt0jspshqxmq6","txid":"5fdca4b6b09346a8592e48a57a2964cd0f02a3c987d8ae7aed9a9878a18b8542","output":"5fdca4b6b09346a8592e48a57a2964cd0f02a3c987d8ae7aed9a9878a18b8542:576","value":"546","block":851235,"blockIndex":8512350846,"mint":"0","transfer":"100000","pointer":"0","balance":"100000","timestamp":1720431147,"status":false,"disableBlockIndex":null}]}"#;
        // let data = serde_json::from_str::<serde_json::Value>(js).unwrap();
        // let jp = JsonPath::from_str("$.data[0].ticker").unwrap();
        // let value = jp.find(&data);
        // if !value.is_null() {
        //     println!("{}", value);
        // }
        let auth = r#"{
        "Ok-Access-Key":"dead4a8a-598f-4710-8512-ddb5f1045ce0",
        "OK-ACCESS-SIGN":"hmac({timestamp}{request_method}{request_path},82F81D877AD377FC814A0BCB2D473283)",
        "OK-ACCESS-TIMESTAMP":"{timestamp}",
        "OK-ACCESS-PASSPHRASE":"Nieaowei360!",
        "OK-ACCESS-PROJECT":"fc4304bb854b4634fee86f00a10b0b5c"
        }"#;
        let resp = get_json_info_from_url("https://www.okx.com/api/v5/wallet/utxo/utxo-detail?chainIndex=0&txHash={0}&voutIndex={1}".to_string(), auth.to_string(), vec!["b4966171961e97fe738750f3739f8cc706b09d972209e3f217f4d7495ef94494".to_string(), "0".to_string()], vec!["$.data[0].btcAssets[?(@.protocol != '3')].nftId".to_string()]);
        println!("{:?}", resp.unwrap());
    }

    #[test]
    fn test_buy_rune() {
        let es = EsploraClient::new("https://mempool.space/api".to_string());

        let paris = vec![
            // (
            //     "e7b44ea74d474248422f87d5a2280c873a9bec736be0f28a17c77021bb176ff60000000000ffffffff",
            //     "01414b2c869ec6502490decfe74e746e00bd916dd7f9ed9c7236f348ded25cdf9e02c24c65b5a1d2259880caf9a8263afb778c0487293c55e82fcecaac5a61f6b05a83",
            //     "85a708000000000022512087e16268bb93b3ef05de14fd77874f96e425b3478cd166f3f957cea4c08cf6f3",
            //     RuneId::new(865863, 520).unwrap(),
            //     "15750",
            // ),
            (
                "0e65408f5342e3852e884a7539f2d0d806d18f00092c306ef59ee52cec3d80fd0300000000ffffffff",
                "01419e392df3fce61430034e7fe4dad5e46cdf71134507fd49071c10ea33089a712e246cc7f36538bfcd1b1c3b8ae700db7d64fd68de9b39207a6e28f48d1178286583",
                "bcca00000000000017a9142c8a2b29bcdb0628217574f4b48f12b26314862a87",
                RuneId::new(840000, 3).unwrap(),
                "638888889",
            )
        ];


        let mut snipe_pair = vec![];

        for (txinhex, witness, txout, runeid, amount) in paris {
            let txin = new_txin_from_hex(txinhex.to_string(), witness.to_string()).unwrap();
            let txout = new_txout_from_hex(txout.to_string()).unwrap();
            let tx = es.get_tx(txin.previous_output.txid.to_string()).unwrap();
            let outputs = tx.output();
            let p = SnipeRuneUtxoPair {
                txin: txin.clone(),
                prevout: TxOut {
                    value: outputs[txin.previous_output.vout.clone() as usize].value.clone(),
                    script_pubkey: outputs[txin.previous_output.vout.clone() as usize].script_pubkey.clone(),
                    serialize_hex: "".to_string(),
                },
                txout,
                rune_id: Arc::new(runeid),
                amount: amount.to_string(),
            };
            snipe_pair.push(p);
        }


        let recv = bitcoin::Address::from_str("bc1pfuqd6gadnlycmyas8nc8zgads69uhzhejjvx8epenqa7pcfxqtkqyq6666").unwrap().assume_checked();
        let ordi = bitcoin::Address::from_str("bc1pdv25r3a8sq7chv6nxpazcnsvpatwrepk7m0krn07u63c9px9st3sauc8eu").unwrap().assume_checked();

        let utxo = LocalOutput {
            outpoint: OutPoint { txid: Arc::new("b5fa21b422ea2bd8ea073cae531d420711fd87c9105fc3a8bb5eae8d46f3794d".parse().unwrap()), vout: 2 },
            txout: TxOut {
                value: Arc::new(Amount::from_sat(6173607)),
                script_pubkey: Arc::new(recv.script_pubkey().clone().into()),
                serialize_hex: "".to_string(),
            },
            keychain: KeychainKind::External,
            is_spent: false,
            confirmation_time: ConfirmationTime::Confirmed { height: 0, time: 0 },
        };
        let psbt = build_rune_snipe_psbt(
            vec![utxo],
            snipe_pair,
            Arc::new(recv.clone().into()), Arc::new(ordi.clone().into()),
            Arc::new(Amount::from_sat(600)),
            Arc::new(FeeRate::from_sat_per_vb(100).unwrap()),
            Arc::new(FeeRate::from_sat_per_vb(10).unwrap()),
            None,
        ).unwrap();

        println!("{}", psbt.snipe.serialize_hex());
        println!("{}", psbt.split.serialize_hex());
        // Runestone::encipher()
        // println!("{:?}",Runestone::decipher(psbt.split.extract_tx_unchecked_fee_rate()))
        println!("{}", serialize_hex(psbt.split.extract_tx_unchecked_fee_rate().output()[1].script_pubkey.0.as_script()));
        println!("{}", psbt.split.extract_tx_unchecked_fee_rate().output()[1].script_pubkey.0.as_script());
        // OP_RETURN 0b00c0a23303b9d7d2b00200
    }

    #[test]
    fn test_buy_fund() {
        let txin = new_txin_from_hex("b8b315d4eeb7ec56908d0614d7f10add24460353eca4e01e9d815efbb32dbfe60500000000ffffffff".to_string(), "014015d938347df4b1920ab16a9916be1f4fa911aa4d61e5899ac99a2c67533ce2235176deb222579123413e675153d1aae41466a992548283142e729b9ff4094e83".to_string()).unwrap();
        let txout = new_txout_from_hex("22020000000000002251206d119ae1593d1dd6a964136bd7775c45a54414bb41640385e053e239626678e3".to_string()).unwrap();

        let recv = bitcoin::Address::from_str("bc1pfuqd6gadnlycmyas8nc8zgads69uhzhejjvx8epenqa7pcfxqtkqyq6666").unwrap().assume_checked();
        println!("{:?}", txin);
        println!("{:?}", txout);
        let mut tx = bitcoin::Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![
                bitcoin::TxIn {
                    previous_output: bitcoin::OutPoint { txid: "e689eca28f7be8f813040cee65f49cf5f6ce3b3a0e1d7699bc378d06b7d252f4".parse().unwrap(), vout: 0 },
                    script_sig: Default::default(),
                    sequence: Default::default(),
                    witness: Default::default(),
                },
                bitcoin::TxIn {
                    previous_output: txin.previous_output.into(),
                    script_sig: Default::default(),
                    sequence: bitcoin::Sequence::from_consensus(txin.sequence),
                    witness: txin.witness.clone().into(),
                }
            ],
            output: vec![
                bitcoin::TxOut {
                    value: bitcoin::Amount::from_sat(1200),
                    script_pubkey: recv.script_pubkey(),
                },
                bitcoin::TxOut {
                    value: txout.value.0,
                    script_pubkey: txout.script_pubkey.0.clone(),
                },
                bitcoin::TxOut {
                    value: bitcoin::Amount::from_sat(129300),
                    script_pubkey: recv.script_pubkey(),
                }
            ],
        };

        let l = tx.output.len();

        let mut dummy = DummyTransaction::new();
        dummy.append_input(recv.script_pubkey(), None, None);
        dummy.append_input(bitcoin::Address::from_str("bc1pd5ge4c2e85wad2tyzd4awa6ugkj5g99mg9jq8p0q203rjcnx0r3se32590").unwrap().assume_checked().script_pubkey(), None, Some(Witness::from(txin.witness.clone())));
        dummy.append_output(recv.script_pubkey());
        dummy.append_output(recv.script_pubkey());
        dummy.append_output(txout.script_pubkey.0.clone());

        println!("{}", dummy.vsize());
        let psbt = bitcoin::Psbt {
            unsigned_tx: tx,
            version: 0,
            xpub: Default::default(),
            proprietary: Default::default(),
            unknown: Default::default(),
            inputs: vec![
                bitcoin::psbt::Input {
                    witness_utxo: Some(bitcoin::TxOut { value: bitcoin::Amount::from_sat(1200), script_pubkey: recv.script_pubkey() }),
                    ..Default::default()
                },
                bitcoin::psbt::Input {
                    witness_utxo: Some(bitcoin::TxOut { value: bitcoin::Amount::from_sat(132546), script_pubkey: bitcoin::Address::from_str("bc1pd5ge4c2e85wad2tyzd4awa6ugkj5g99mg9jq8p0q203rjcnx0r3se32590").unwrap().assume_checked().script_pubkey() }),
                    sighash_type: Some(TapSighashType::SinglePlusAnyoneCanPay.into()),
                    final_script_witness: Some(txin.witness.into()),
                    ..Default::default()
                },
            ],
            outputs: vec![Default::default(); l],
        };

        println!("{}", psbt.serialize_hex());
        println!("{}", serialize_hex(&psbt.extract_tx_unchecked_fee_rate()));
    }

    #[test]
    fn test_extract_runestone() {
        let hex = ScriptBuf::from_hex("1600147bd1b0bca48d8da756eb59c21cfd097fa2a52d16").unwrap();
        println!("{}", hex);
        let rune = extract_rune_from_script(Arc::new(Script::from(hex))).unwrap();
        println!("{:?}", rune);
    }
}