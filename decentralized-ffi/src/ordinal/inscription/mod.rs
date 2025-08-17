use crate::ordinal::inscription::{
    batch::Mode, inscription::Inscription, inscription_id::InscriptionId,
};

use crate::types::LocalOutput;
use anyhow::{bail, Context, Result};
use bdk_wallet::bitcoin::transaction::Version;
use bdk_wallet::bitcoin::{
    absolute::LockTime,
    address::NetworkChecked,
    key::{
        constants::SCHNORR_SIGNATURE_SIZE, TapTweak, TweakedPublicKey, UntweakedKeypair,
        XOnlyPublicKey,
    },
    opcodes,
    policy::MAX_STANDARD_TX_WEIGHT,
    psbt::{Input, Psbt},
    script, secp256k1,
    secp256k1::{rand::thread_rng, Secp256k1},
    sighash::{Prevouts, SighashCache, TapSighashType},
    taproot::{ControlBlock, LeafVersion, Signature, TapLeafHash, TaprootBuilder},
    Address, AddressType, Amount, FeeRate, Network, OutPoint, PrivateKey, Script, ScriptBuf,
    Sequence, Transaction, TxIn, TxOut, Txid, Witness,
};
use bdk_wallet::{bitcoin, serde_json};
use ciborium::Value;
use derive_more::Display;
use ordinals::{Sat, SatPoint};
use serde::{Deserialize, Serialize};
use std::convert::{TryFrom, TryInto};
use std::sync::Arc;
use std::{
    collections::BTreeMap, fmt, fs, fs::File, io::Cursor, ops::Deref, path::PathBuf, str::FromStr,
};

mod batch;
mod common;
pub mod config;
mod envelope;
mod inscription;
mod inscription_id;

mod decimal;
// mod decimal_sat;
// mod degree;
mod deserialize_from_str;
// mod epoch;
// mod height;
mod media;
// mod rarity;
// mod sat;
// mod sat_point;

pub struct Client;

// pub trait RemoteClient {
//     async fn get_transaction(&self, tx_ix: &str) -> anyhow::Result<Transaction>;
// }

#[derive(uniffi::Record)]
pub struct NamedFile {
    pub name: String,
    pub data: Vec<u8>,
}

#[derive(uniffi::Error, Debug, Display)]
pub enum MintError {
    AnyError(String),
}

// impl From<anyhow::Error> for MintError
//
// {
//     fn from(value: anyhow::Error) -> Self {
//         MintError::any(value.to_string())
//     }
// }

impl<E> From<E> for MintError
where
    E: std::error::Error,
{
    fn from(value: E) -> Self {
        MintError::AnyError(value.to_string())
    }
}

#[uniffi::export]
pub async fn mint(
    network: Network,
    utxos: Vec<LocalOutput>,
    file: NamedFile,
    pay_address: &str,
    to_addr: &str,
    fee_rate: u64,
    postage: Option<u64>,
) -> Result<Output, MintError> {
    let destination = Address::from_str(to_addr)?.require_network(network)?;

    // 1. Legacy (P2PKH) 以 1 开始的地址限制输出为 546 sats
    // 2. Nested Segwit (P2SH-P2WPKH) 以 3 开始的地址限制输出为 540 sats
    // 3. NativeSegwit (P2WPKH) 以 bc1q 开始的地址限制输出为 294 sats
    // 4. Taproot (P2TR) 以 bc1p 开始的地址限制输出为 330 sats
    let postage = if let Some(postage) = postage {
        postage
    } else {
        match destination.address_type() {
            None => 546,
            Some(typ) => match typ {
                AddressType::P2pkh => 546,
                AddressType::P2sh => 540,
                AddressType::P2wpkh => 294,
                AddressType::P2wsh => 546,
                AddressType::P2tr => 330,
                _ => 546,
            },
        }
    };

    Inscribe {
        pay_address: Address::from_str(pay_address)?.require_network(network)?,
        destination: Address::from_str(to_addr)?.require_network(network)?,
        fee_rate: FeeRate::from_sat_per_vb_unchecked(fee_rate),
        file: Some((file.name.to_string(), file.data)),
        postage: Amount::from_sat(postage),

        json_metadata: None,
        metaprotocol: None,
        dry_run: false,
        batch: None,
        cbor_metadata: None,
        commit_fee_rate: None,
        compress: false,
        no_backup: false,
        no_limit: false,
        parent: None,
        reinscribe: false,
        satpoint: None,
        sat: None,
    }
    .run(
        // api,
        network, utxos,
    )
    .await
    .map_err(|e| MintError::AnyError(e.to_string()))
}

pub(crate) struct Inscribe {
    pub(crate) pay_address: Address<NetworkChecked>,
    pub(crate) destination: Address<NetworkChecked>, // 接收地址
    pub(crate) fee_rate: FeeRate,                    // 费率
    pub(crate) file: Option<(String, Vec<u8>)>,      // 文件名-文件数据
    pub(crate) batch: Option<Vec<(String, Vec<u8>)>>,
    pub(crate) json_metadata: Option<PathBuf>,
    pub(crate) metaprotocol: Option<String>,
    pub(crate) dry_run: bool,
    pub(crate) postage: Amount, // 默认 546

    // 下面暂不可用
    pub(crate) cbor_metadata: Option<PathBuf>,
    pub(crate) commit_fee_rate: Option<FeeRate>,
    pub(crate) compress: bool,
    pub(crate) no_backup: bool,
    pub(crate) no_limit: bool,
    pub(crate) parent: Option<InscriptionId>,
    pub(crate) reinscribe: bool,
    pub(crate) satpoint: Option<SatPoint>,
    pub(crate) sat: Option<Sat>,
}

impl Inscribe {
    pub(crate) async fn run(
        self,
        // cli: impl RemoteClient,
        network: Network,
        utxos: Vec<LocalOutput>,
    ) -> Result<Output> {
        let metadata = Inscribe::parse_metadata(self.cbor_metadata, self.json_metadata)?;

        // let utxos_net = cli
        //     .get_utxo(&self.pay_address.to_string())
        //     .await?
        //     .into_iter()
        //     .filter(|e| e.status.confirmed && e.value > 600)
        //     .collect::<Vec<_>>(); // todo 过滤铭文
        // let locked_utxos = index.get_locked_outputs(wallet)?;
        // let runic_utxos = index.get_runic_outputs(&utxos.keys().cloned().collect::<Vec<OutPoint>>())?;

        // let mut utxos = BTreeMap::new();
        // utxos.extend(local_utxos.into_iter().map(|utxo| {
        //     let outpoint = utxo.outpoint;
        //     let amount = utxo.txout.value;
        //
        //     (outpoint, amount)
        // }));

        let postage;
        let destinations;
        let inscriptions;
        let mode;
        let parent_info;
        let sat;

        match (self.file, self.batch) {
            (Some(file), None) => {
                //todo 暂时不支持父子铭文
                // parent_info = Inscribe::get_parent_info(self.parent, &index, &utxos, &client, chain)?; // todo
                parent_info = None;

                postage = self.postage;

                inscriptions = vec![Inscription::from_bytes(
                    network,
                    file,
                    self.parent,
                    None,
                    self.metaprotocol,
                    metadata,
                    self.compress,
                )?];

                mode = Mode::SeparateOutputs;

                sat = self.sat;

                destinations = vec![self.destination.clone()];
            }
            (None, Some(batch)) => {
                // 暂不支持批量
                unreachable!();
                // let batchfile = Batchfile::load(&batch)?;
                //
                // // todo batch
                // parent_info = Inscribe::get_parent_info(batchfile.parent, &index, &utxos, &client, chain)?;
                //
                // postage = batchfile
                //   .postage
                //   .map(Amount::from_sat)
                //   .unwrap_or(TARGET_POSTAGE);
                //
                // (inscriptions, destinations) = batchfile.inscriptions(
                //   &client,
                //   chain,
                //   parent_info.as_ref().map(|info| info.tx_out.value),
                //   metadata,
                //   postage,
                //   self.compress,
                // )?;
                //
                // mode = batchfile.mode;
                //
                // if batchfile.sat.is_some()
                //   && mode != crate::subcommand::wallet::inscribe::batch::Mode::SameSat
                // {
                //   return Err(anyhow!("`sat` can only be set in `same-sat` mode"));
                // }
                //
                // sat = batchfile.sat;
            }
            _ => unreachable!(),
        }

        // 获取 sat 位置
        // let satpoint = if let Some(sat) = sat {
        //   // todo custom sat
        //   if !index.has_sat_index() {
        //     return Err(anyhow!(
        //       "index must be built with `--index-sats` to use `--sat`"
        //     ));
        //   }
        //   match index.find(sat)? {
        //     Some(satpoint) => Some(satpoint),
        //     None => return Err(anyhow!(format!("could not find sat `{sat}`"))),
        //   }
        // } else {
        //   self.satpoint
        // };

        Batch {
            commit_fee_rate: self.commit_fee_rate.unwrap_or(self.fee_rate),
            destinations,
            dry_run: self.dry_run,
            inscriptions,
            mode,
            no_backup: self.no_backup,
            no_limit: self.no_limit,
            parent_info,
            postage,
            reinscribe: self.reinscribe,
            reveal_fee_rate: self.fee_rate,
            satpoint: self.satpoint,
        }
        .inscribe(&self.pay_address, utxos, network)
        .await
    }

    fn parse_metadata(
        cbor: Option<PathBuf>,
        json: Option<PathBuf>,
    ) -> anyhow::Result<Option<Vec<u8>>> {
        if let Some(path) = cbor {
            let cbor = fs::read(path)?;
            let _value: Value = ciborium::from_reader(Cursor::new(cbor.clone()))
                .context("failed to parse CBOR metadata")?;

            Ok(Some(cbor))
        } else if let Some(path) = json {
            let value: serde_json::Value = serde_json::from_reader(File::open(path)?)
                .context("failed to parse JSON metadata")?;
            let mut cbor = Vec::new();
            ciborium::into_writer(&value, &mut cbor)?;

            Ok(Some(cbor))
        } else {
            Ok(None)
        }
    }

    // fn get_parent_info(
    //   parent: Option<InscriptionId>,
    //   index: &Index,
    //   utxos: &BTreeMap<OutPoint, Amount>,
    //   client: &btc_api::Client,
    //   chain: Chain,
    //   to_addr: Address,
    // ) -> crate::Result<Option<ParentInfo>> {
    //   if let Some(parent_id) = parent {
    //     if let Some(satpoint) = index.get_inscription_satpoint_by_id(parent_id)? {
    //       if !utxos.contains_key(&satpoint.outpoint) {
    //         return Err(anyhow!(format!("parent {parent_id} not in wallet")));
    //       }
    //
    //       Ok(Some(ParentInfo {
    //         destination: to_addr, //todo
    //         id: parent_id,
    //         location: satpoint,
    //         tx_out: index
    //           .get_transaction(satpoint.outpoint.txid)?
    //           .expect("parent transaction not found in index")
    //           .output
    //           .into_iter()
    //           .nth(satpoint.outpoint.vout.try_into().unwrap())
    //           .expect("current transaction output"),
    //       }))
    //     } else {
    //       Err(anyhow!(format!("parent {parent_id} does not exist")))
    //     }
    //   } else {
    //     Ok(None)
    //   }
    // }
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct InscriptionInfo {
    pub id: InscriptionId,
    pub location: SatPoint,
}

#[derive(uniffi::Record)]
pub struct Output {
    pub commit_psbt_tx: Arc<crate::Psbt>,

    pub reveal_tx: Arc<crate::Transaction>,
    pub reveal_private_key: String,

    // pub parent: Option<InscriptionId>,
    // pub inscriptions: Vec<InscriptionInfo>,
    pub total_fees: u64,
}

#[derive(Clone, Debug)]
pub(crate) struct ParentInfo {
    pub(crate) destination: Address,
    pub(crate) id: InscriptionId,
    pub(crate) location: SatPoint,
    pub(crate) tx_out: TxOut,
}

pub(crate) struct Batch {
    pub(crate) commit_fee_rate: FeeRate,
    pub(crate) destinations: Vec<Address>,
    pub(crate) dry_run: bool,
    pub(crate) inscriptions: Vec<Inscription>,
    pub(crate) mode: Mode,
    pub(crate) no_backup: bool,
    pub(crate) no_limit: bool,
    pub(crate) parent_info: Option<ParentInfo>,
    pub(crate) postage: Amount,
    pub(crate) reinscribe: bool,
    pub(crate) reveal_fee_rate: FeeRate,
    pub(crate) satpoint: Option<SatPoint>,
}

impl Default for Batch {
    fn default() -> Batch {
        Batch {
            commit_fee_rate: FeeRate::from_sat_per_vb_unchecked(1),
            destinations: Vec::new(),
            dry_run: false,
            inscriptions: Vec::new(),
            mode: Mode::SharedOutput,
            no_backup: false,
            no_limit: false,
            parent_info: None,
            postage: Amount::from_sat(10_000),
            reinscribe: false,
            reveal_fee_rate: FeeRate::from_sat_per_vb_unchecked(1),
            satpoint: None,
        }
    }
}

impl Batch {
    pub(crate) async fn inscribe(
        &self,
        pay_address: &Address,
        utxos: Vec<LocalOutput>,
        // client: impl RemoteClient,
        network: Network,
    ) -> Result<Output> {
        let (commit_tx, reveal_tx, recovery_key_pair, total_fees) = self
            .create_batch_inscription_transactions(pay_address, utxos, network)
            .await?;

        let signed_reveal_tx = if self.parent_info.is_some() {
            // todo
            // let input_utxos = commit_tx
            //   .output
            //   .iter()
            //   .enumerate()
            //   .map(|(vout, output)| SignRawTransactionInput {
            //     txid: commit_tx.txid(),
            //     vout: vout.try_into().unwrap(),
            //     script_pub_key: output.script_pubkey.clone(),
            //     redeem_script: None,
            //     amount: Some(Amount::from_sat(output.value)),
            //   })
            //   .collect::<Vec<SignRawTransactionInput>>();
            // vec![]
            String::new()
            // client
            //   .sign_raw_transaction_with_wallet(
            //     //tdo
            //     &reveal_tx,
            //     Some(
            //       &commit_tx
            //         .output
            //         .iter()
            //         .enumerate()
            //         .map(|(vout, output)| SignRawTransactionInput {
            //           txid: commit_tx.txid(),
            //           vout: vout.try_into().unwrap(),
            //           script_pub_key: output.script_pubkey.clone(),
            //           redeem_script: None,
            //           amount: Some(Amount::from_sat(output.value)),
            //         })
            //         .collect::<Vec<SignRawTransactionInput>>(),
            //     ),
            //     None,
            //   )?
            //   .hex
        } else {
            bitcoin::consensus::encode::serialize_hex(&reveal_tx)
        };

        let commit_tx_hex = commit_tx.serialize_hex();

        Ok(self.output(
            commit_tx, // 未签名 传回给用户签名
            reveal_tx, // 已签名  存储到缓存或者数据库 等用户签名广播 commit 再广播
            total_fees,
            self.inscriptions.clone(),
            recovery_key_pair, //
        ))
    }

    fn output(
        &self,
        commit: Psbt,
        reveal: Transaction,
        total_fees: u64,
        inscriptions: Vec<Inscription>,
        reveal_private_key: String,
    ) -> Output {
        // let mut inscriptions_output = Vec::new();
        // for index in 0..inscriptions.len() {
        //     let index = u32::try_from(index).unwrap();
        //
        //     let vout = match self.mode {
        //         Mode::SharedOutput | Mode::SameSat => {
        //             if self.parent_info.is_some() {
        //                 1
        //             } else {
        //                 0
        //             }
        //         }
        //         Mode::SeparateOutputs => {
        //             if self.parent_info.is_some() {
        //                 index + 1
        //             } else {
        //                 index
        //             }
        //         }
        //     };
        //
        //     let offset = match self.mode {
        //         Mode::SharedOutput => u64::from(index) * self.postage.to_sat(),
        //         Mode::SeparateOutputs | Mode::SameSat => 0,
        //     };
        //
        //     inscriptions_output.push(InscriptionInfo {
        //         id: InscriptionId {
        //             txid: reveal.0,
        //             index,
        //         },
        //         location: SatPoint {
        //             outpoint: OutPoint {
        //                 txid: reveal.0,
        //                 vout,
        //             },
        //             offset,
        //         },
        //     });
        // }

        Output {
            // commit: commit.0,
            // reveal: reveal.0,
            reveal_tx: Arc::new(crate::Transaction::from(reveal)),
            total_fees,
            // parent: self.parent_info.clone().map(|info| info.id),
            // inscriptions: inscriptions_output,
            commit_psbt_tx: Arc::new(crate::Psbt::from(commit)),
            reveal_private_key,
        }
    }

    pub(crate) async fn create_batch_inscription_transactions(
        &self,
        pay_address: &Address,
        utxos: Vec<LocalOutput>,
        // client: impl RemoteClient,
        network: Network,
    ) -> Result<(Psbt, Transaction, String, u64)> {
        if let Some(parent_info) = &self.parent_info {
            assert!(self
                .inscriptions
                .iter()
                .all(|inscription| inscription.parent().unwrap() == parent_info.id))
        }

        match self.mode {
            Mode::SameSat => assert_eq!(
                self.destinations.len(),
                1,
                "invariant: same-sat has only one destination"
            ),
            Mode::SeparateOutputs => assert_eq!(
                self.destinations.len(),
                self.inscriptions.len(),
                "invariant: destination addresses and number of inscriptions doesn't match"
            ),
            Mode::SharedOutput => assert_eq!(
                self.destinations.len(),
                1,
                "invariant: destination addresses and number of inscriptions doesn't match"
            ),
        }

        // 创建临时私钥地址
        let secp256k1 = Secp256k1::new();
        let key_pair = UntweakedKeypair::new(&secp256k1, &mut thread_rng());
        let (public_key, _parity) = XOnlyPublicKey::from_keypair(&key_pair);

        let reveal_script = Inscription::append_batch_reveal_script(
            &self.inscriptions,
            ScriptBuf::builder()
                .push_slice(public_key.serialize())
                .push_opcode(opcodes::all::OP_CHECKSIG),
        );

        let taproot_spend_info = TaprootBuilder::new()
            .add_leaf(0, reveal_script.clone())
            .expect("adding leaf should work")
            .finalize(&secp256k1, public_key)
            .expect("finalizing taproot builder should work");

        let control_block = taproot_spend_info
            .control_block(&(reveal_script.clone(), LeafVersion::TapScript))
            .expect("should compute control block");

        let mint_addr = Address::p2tr_tweaked(taproot_spend_info.output_key(), network);

        let total_postage = match self.mode {
            Mode::SameSat => self.postage,
            Mode::SharedOutput | Mode::SeparateOutputs => {
                self.postage * u64::try_from(self.inscriptions.len()).unwrap()
            }
        };

        let mut reveal_inputs = vec![OutPoint::null()];
        let mut reveal_outputs = self
            .destinations
            .iter()
            .map(|destination| TxOut {
                script_pubkey: destination.script_pubkey(),
                value: match self.mode {
                    Mode::SeparateOutputs => self.postage,
                    Mode::SharedOutput | Mode::SameSat => total_postage,
                },
            })
            .collect::<Vec<TxOut>>();

        if let Some(ParentInfo {
            location,
            id: _,
            destination,
            tx_out,
        }) = self.parent_info.clone()
        {
            reveal_inputs.insert(0, location.outpoint);
            reveal_outputs.insert(
                0,
                TxOut {
                    script_pubkey: destination.script_pubkey(),
                    value: tx_out.value,
                },
            );
        }

        let commit_input = if self.parent_info.is_some() { 1 } else { 0 };

        let (_, reveal_fee) = Self::build_reveal_transaction(
            &control_block,
            self.reveal_fee_rate,
            reveal_inputs.clone(),
            commit_input,
            reveal_outputs.clone(),
            &reveal_script,
        );

        let psbt_tx = CommitPsbtBuilder::new(
            pay_address.clone(),
            utxos,
            mint_addr.clone(),
            self.commit_fee_rate,       // 提交费率
            reveal_fee + total_postage, // reveal 费用 total_postage会转回去
        )
        .build_transaction()
        .await?;

        let (vout, _commit_output) = psbt_tx
            .unsigned_tx
            .output
            .iter()
            .enumerate()
            .find(|(_vout, output)| output.script_pubkey == mint_addr.script_pubkey())
            .expect("should find sat commit/inscription output");

        reveal_inputs[commit_input] = OutPoint {
            txid: psbt_tx.unsigned_tx.compute_txid(),
            vout: vout.try_into().unwrap(),
        };

        let (mut reveal_tx, _fee) = Self::build_reveal_transaction(
            &control_block,
            self.reveal_fee_rate,
            reveal_inputs,
            commit_input,
            reveal_outputs.clone(),
            &reveal_script,
        );

        if reveal_tx.output[commit_input].value
            < reveal_tx.output[commit_input]
                .script_pubkey
                .minimal_non_dust()
        {
            bail!("commit transaction output would be dust");
        }

        let mut prevouts = vec![psbt_tx.unsigned_tx.output[vout].clone()];

        if let Some(parent_info) = self.parent_info.clone() {
            prevouts.insert(0, parent_info.tx_out);
        }

        let mut sighash_cache = SighashCache::new(&mut reveal_tx);

        let sighash = sighash_cache
            .taproot_script_spend_signature_hash(
                commit_input,
                &Prevouts::All(&prevouts),
                TapLeafHash::from_script(&reveal_script, LeafVersion::TapScript),
                TapSighashType::Default,
            )
            .expect("signature hash should compute");

        let sig = secp256k1.sign_schnorr(
            &secp256k1::Message::from_digest_slice(sighash.as_ref())
                .expect("should be cryptographically secure hash"),
            &key_pair,
        );

        let witness = sighash_cache
            .witness_mut(commit_input)
            .expect("getting mutable witness reference should work");

        witness.push(
            Signature {
                signature: sig,
                sighash_type: TapSighashType::Default,
            }
            .to_vec(),
        );

        witness.push(reveal_script);
        witness.push(control_block.serialize());

        let recovery_key_pair = key_pair.tap_tweak(&secp256k1, taproot_spend_info.merkle_root());

        let (x_only_pub_key, _parity) = recovery_key_pair.to_keypair().x_only_public_key();
        assert_eq!(
            Address::p2tr_tweaked(
                TweakedPublicKey::dangerous_assume_tweaked(x_only_pub_key),
                network,
            ),
            mint_addr
        );

        let reveal_weight = reveal_tx.weight();

        if !self.no_limit && reveal_weight > bitcoin::Weight::from_wu(MAX_STANDARD_TX_WEIGHT.into())
        {
            bail!(
        "reveal transaction weight greater than {MAX_STANDARD_TX_WEIGHT} (MAX_STANDARD_TX_WEIGHT): {reveal_weight}"
      );
        }

        // utxos.insert(
        //     reveal_tx.input[commit_input].previous_output,
        //     psbt_tx.unsigned_tx.output[reveal_tx.input[commit_input].previous_output.vout as usize]
        //         .value,
        // );

        // let psbt = Psbt::from_unsigned_tx(unsigned_commit_tx)?;

        // 构建 psbt

        // let total_fees = Self::calculate_fee(&psbt_tx.unsigned_tx, &utxos)
        //     + Self::calculate_fee(&reveal_tx, &utxos);

        Ok((
            psbt_tx,
            reveal_tx,
            PrivateKey::new(key_pair.secret_key(), network).to_wif(),
            0,
        ))
    }

    fn build_reveal_transaction(
        control_block: &ControlBlock,
        fee_rate: FeeRate,
        inputs: Vec<OutPoint>,
        commit_input_index: usize,
        outputs: Vec<TxOut>,
        script: &Script,
    ) -> (Transaction, Amount) {
        let reveal_tx = Transaction {
            input: inputs
                .iter()
                .map(|outpoint| TxIn {
                    previous_output: *outpoint,
                    script_sig: script::Builder::new().into_script(),
                    witness: Witness::new(),
                    sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                })
                .collect(),
            output: outputs,
            lock_time: LockTime::ZERO,
            version: Version::TWO,
        };

        let fee = {
            let mut reveal_tx = reveal_tx.clone();

            for (current_index, txin) in reveal_tx.input.iter_mut().enumerate() {
                // add dummy inscription witness for reveal input/commit output
                if current_index == commit_input_index {
                    txin.witness.push(
                        Signature::from_slice(&[0; SCHNORR_SIGNATURE_SIZE])
                            .unwrap()
                            .to_vec(),
                    );
                    txin.witness.push(script);
                    txin.witness.push(control_block.serialize());
                } else {
                    txin.witness = Witness::from_slice(&[&[0; SCHNORR_SIGNATURE_SIZE]]);
                }
            }
            fee_rate * reveal_tx.weight()
            // fee_rate.fee(reveal_tx.vsize())
        };

        (reveal_tx, fee)
    }

    fn calculate_fee(tx: &Transaction, utxos: &BTreeMap<OutPoint, Amount>) -> u64 {
        tx.input
            .iter()
            .map(|txin| utxos.get(&txin.previous_output).unwrap().to_sat())
            .sum::<u64>()
            .checked_sub(
                tx.output
                    .iter()
                    .map(|txout| txout.value.to_sat())
                    .sum::<u64>(),
            )
            .unwrap()
    }
}

#[derive(Debug, PartialEq)]
pub enum Error {
    DuplicateAddress(Address),
    Dust {
        output_value: Amount,
        dust_value: Amount,
    },
    NotEnoughCardinalUtxos,
    NotInWallet(SatPoint),
    OutOfRange(SatPoint, u64),
    UtxoContainsAdditionalInscription {
        outgoing_satpoint: SatPoint,
        inscribed_satpoint: SatPoint,
        inscription_id: InscriptionId,
    },
    ValueOverflow,
}

#[derive(Debug, PartialEq)]
pub enum Target {
    Value(Amount),
    Postage,
    ExactPostage(Amount),
}

impl std::error::Error for Error {}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Dust {
                output_value,
                dust_value,
            } => write!(f, "output value is below dust value: {output_value} < {dust_value}"),
            Error::NotInWallet(outgoing_satpoint) => write!(f, "outgoing satpoint {outgoing_satpoint} not in wallet"),
            Error::OutOfRange(outgoing_satpoint, maximum) => write!(f, "outgoing satpoint {outgoing_satpoint} offset higher than maximum {maximum}"),
            Error::NotEnoughCardinalUtxos => write!(
                f,
                "wallet does not contain enough cardinal UTXOs, please add additional funds to wallet."
            ),
            Error::UtxoContainsAdditionalInscription {
                outgoing_satpoint,
                inscribed_satpoint,
                inscription_id,
            } => write!(
                f,
                "cannot send {outgoing_satpoint} without also sending inscription {inscription_id} at {inscribed_satpoint}"
            ),
            Error::ValueOverflow => write!(f, "arithmetic overflow calculating value"),
            Error::DuplicateAddress(address) => write!(f, "duplicate input address: {address}"),
        }
    }
}

pub struct CommitPsbtBuilder {
    pub(crate) cardinal_utxos: Vec<LocalOutput>,

    pub(crate) pay_address: Address,  // 找零地址
    pub(crate) mint_address: Address, // 铭刻地址

    pub(crate) fee_rate: FeeRate,
    pub(crate) reveal_fee: Amount,

    pub(crate) inputs: Vec<OutPoint>,           // utxo
    pub(crate) outputs: Vec<(Address, Amount)>, // 输出
}

type BuildResult<T> = std::result::Result<T, Error>;

impl CommitPsbtBuilder {
    const ADDITIONAL_INPUT_VBYTES: usize = 58;
    const ADDITIONAL_OUTPUT_VBYTES: usize = 43;
    const SCHNORR_SIGNATURE_SIZE: usize = 64;
    pub(crate) const MAX_POSTAGE: Amount = Amount::from_sat(2 * 10_000);

    pub fn new(
        pay_address: Address,
        cardinal_utxos: Vec<LocalOutput>,
        mint_address: Address,
        fee_rate: FeeRate,
        reveal_fee: Amount,
    ) -> Self {
        Self {
            cardinal_utxos,
            pay_address,
            mint_address,
            fee_rate,
            reveal_fee,
            inputs: Vec::new(),
            outputs: Vec::new(),
        }
    }

    pub async fn build_transaction(self) -> Result<Psbt> {
        // 创建一个空的比特币交易
        let mut transaction = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![],  // 可以添加多个 input
            output: vec![], // 可以添加多个 output
        };

        let from_script_pub_key = self.pay_address.script_pubkey();

        let mut transfer_amount = 0;

        // 初始化找零
        transaction.output.push(TxOut {
            value: Amount::ZERO,
            script_pubkey: from_script_pub_key.clone(),
        });

        // 其他费用
        let  to_addrs = vec![(self.mint_address, self.reveal_fee)];

        for (addr, amount) in to_addrs {
            transaction.output.push(TxOut {
                value: amount,
                script_pubkey: addr.script_pubkey(),
            });
            transfer_amount += amount.to_sat();
        }

        let mut psbt_inputs = vec![];

        let mut amount = 0;

        let mut ok = false;
        for utxo in self.cardinal_utxos {
            amount += utxo.txout.value.to_sat();

            // let utxo_tx = client.get_transaction(&utxo.outpoint.txid.to_string()).await?;

            // let mut non_witness_utxo = Transaction {
            //     version: utxo_tx.version,
            //     lock_time: LockTime::from_consensus(utxo_tx.locktime),
            //     input: vec![],
            //     output: vec![],
            // };
            // for out in utxo_tx.vin {
            //     non_witness_utxo.input.push(TxIn {
            //         previous_output: OutPoint {
            //             txid: out.txid,
            //             vout: out.vout,
            //         },
            //         script_sig: ScriptBuf::from_hex(&out.scriptsig).unwrap_or_default(),
            //         sequence: out.sequence,
            //         witness: Witness::from_slice(&out.witness),
            //     });
            // }
            //
            // for out in utxo_tx.vout {
            //     non_witness_utxo.output.push(TxOut {
            //         value: out.value,
            //         script_pubkey: ScriptBuf::from_hex(&out.scriptpubkey).unwrap(),
            //     });
            // }

            transaction.input.push(TxIn {
                previous_output: OutPoint {
                    txid: utxo.outpoint.txid.0,
                    vout: utxo.outpoint.vout,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            });

            let mut psbt_input = Input::default();
            // psbt_input.non_witness_utxo = Some(non_witness_utxo);

            let witness_utxo = TxOut {
                value: utxo.txout.value.0,
                script_pubkey: from_script_pub_key.clone(),
            };
            psbt_input.witness_utxo = Some(witness_utxo);

            psbt_inputs.push(psbt_input);

            let network_fee = (self.fee_rate * transaction.weight()).to_sat();

            if let Some(unfilled) = amount.checked_sub(network_fee + transfer_amount) {
                transaction.output[0].value = Amount::from_sat(unfilled); // 找零

                ok = true;
                break;
            }
        }
        if !ok {
            return Err(anyhow::anyhow!("no utxo or utxo not enough"));
        }
        if transaction.output.first().unwrap().value
            < transaction
                .output
                .first()
                .unwrap()
                .script_pubkey
                .minimal_non_dust()
        {
            transaction.output.remove(0);
        }

        let o_len = transaction.output.len();

        let psbt = Psbt {
            unsigned_tx: transaction,
            version: 0,
            xpub: Default::default(),
            proprietary: Default::default(),
            unknown: Default::default(),
            inputs: psbt_inputs,
            outputs: vec![Default::default(); o_len],
        };
        Ok(psbt)
    }
}
//
// #[cfg(test)]
// mod tests {
//     use std::io::Read;
//
//     use base64::Engine;
//     use bitcoin::address::NetworkUnchecked;
//     use btc_api::{mempool, ApiClient};
//
//     use super::*;
//     use crate::client::common::Output;
//
//     fn check_brc420() {}
//
//     #[tokio::test]
//     async fn test_bitcoin() {
//         let mut cli = btc_api::Client::new();
//         cli.add(ApiClient::from(mempool::new(Network::Bitcoin)))
//             .await;
//
//         let conf = Config {
//             network: Network::Bitcoin,
//             service_fee: Amount::from_sat(1000),
//             service_addr: "bc1p4jjpjfdtu437uvr3xx79afkc4h27mq4pxzskqv2my7w6ll55gcnqfmj73j"
//                 .parse::<Address<NetworkUnchecked>>()
//                 .expect("")
//                 .require_network(Network::Bitcoin)
//                 .expect(""),
//         };
//         let a = Client::new(cli, conf);
//         let mut f = File::open("/Users/nekilc/Downloads/WechatIMG187.jpg").unwrap();
//         // let mut bf = BufReader::new(f);
//         let mut file = Vec::new();
//         f.read_to_end(&mut file).unwrap();
//
//         a.mint(
//             ("1.png", file),
//             "bc1pr2q73hv7hzgg30y9zpq6u642whpufe9ugdz5sg0zvqp7dzhef9ws02t49a",
//             "bc1pr2q73hv7hzgg30y9zpq6u642whpufe9ugdz5sg0zvqp7dzhef9ws02t49a",
//             10,
//             None,
//             None,
//         )
//         .await
//         .expect("TODO: panic message")
//         .print_json();
//     }
//     #[tokio::test]
//     async fn test_testnet() {
//         let mut cli = btc_api::Client::new();
//         cli.add(ApiClient::from(mempool::new(Network::Testnet)))
//             .await;
//
//         let conf = Config {
//             network: Network::Testnet,
//             service_fee: Amount::from_sat(1000),
//             service_addr: "tb1p4jjpjfdtu437uvr3xx79afkc4h27mq4pxzskqv2my7w6ll55gcnq7ny3ta"
//                 .parse::<Address<NetworkUnchecked>>()
//                 .expect("")
//                 .require_network(Network::Testnet)
//                 .expect(""),
//         };
//         let a = Client::new(cli, conf);
//         let mut f = File::open("/Users/nekilc/Downloads/WechatIMG187.jpg").unwrap();
//         // let mut bf = BufReader::new(f);
//         let mut file = Vec::new();
//         f.read_to_end(&mut file).unwrap();
//
//         a.mint(
//             ("1.mp4", base64::decode("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CgAAAAABAAAEAAAAAAEAAAAAAAAAAQAAAgAAAAABAAAKAAAAAAEAAAQAAAAAAQAAAAAAAAABAAACAAAAAAEAAAYAAAAAAQAAAgAAAAABAAAKAAAAAAEAAAQAAAAAAQAAAAAAAAABAAACAAAAAAEAAAoAAAAAAQAABAAAAAABAAAAAAAAAAEAAAIAAAAAAQAACgAAAAABAAAEAAAAAAEAAAAAAAAAAQAAAgAAAAABAAAKAAAAAAEAAAQAAAAAAQAAAAAAAAABAAACAAAAAAEAAAoAAAAAAQAABAAAAAABAAAAAAAAAAEAAAIAAAAAAQAACgAAAAABAAAEAAAAAAEAAAAAAAAAAQAAAgAAAAABAAAEAAAAAAEAAAoAAAAAAQAABAAAAAABAAAAAAAAAAEAAAIAAAAAAQAABAAAAAABAAAKAAAAAAEAAAQAAAAAAQAAAAAAAAABAAACAAAAAAEAAAQAAAAAAQAABgAAAAABAAACAAAAAAEAAAgAAAAAAgAAAgAAAAABAAAKAAAAAAEAAAQAAAAAAQAAAAAAAAABAAACAAAAAAEAAAoAAAAAAQAABAAAAAABAAAAAAAAAAEAAAIAAAAAAQAABAAAAAABAAAKAAAAAAEAAAQAAAAAAQAAAAAAAAABAAACAAAAAAIAAAQAAAAAAQAABgAAAAABAAACAAAAAAEAAAQAAAAAAQAACgAAAAABAAAEAAAAAAEAAAAAAAAAAQAAAgAAAAACAAAEAAAAAAEAAAoAAAAAAQAABAAAAAABAAAAAAAAAAEAAAIAAAAAAQAACgAAAAABAAAEAAAAAAEAAAAAAAAAAQAAAgAAAAABAAAGAAAAAAEAAAIAAAAAAQAACgAAAAABAAAEAAAAAAEAAAAAAAAAAQAAAgAAAAABAAAEAAAAAAEAAAgAAAAAAgAAAgAAAAABAAAKAAAAAAEAAAQAAAAAAQAAAAAAAAABAAACAAAAAAIAAAQAAAAAAQAACgAAAAABAAAEAAAAAAEAAAAAAAAAAQAAAgAAAAAEAAAEAAAAAAEAAAYAAAAAAQAAAgAAAAABAAAKAAAAAAEAAAQAAAAAAQAAAAAAAAABAAACAAAAAAEAAAgAAAAAAgAAAgAAAAABAAAKAAAAAAEAAAQAAAAAAQAAAAAAAAABAAACAAAAAAEAAAoAAAAAAQAABAAAAAABAAAAAAAAAAEAAAIAAAAAAQAABAAAAAABAAAKAAAAAAEAAAQAAAAAAQAAAAAAAAABAAACAAAAAAEAAAQAAAAAAQAACgAAAAABAAAEAAAAAAEAAAAAAAAAAQAAAgAAAAABAAAKAAAAAAEAAAQAAAAAAQAAAAAAAAABAAACAAAAAAEAAAoAAAAAAQAABAAAAAABAAAAAAAAAAEAAAIAAAAAAQAACgAAAAABAAAEAAAAAAEAAAAAAAAAAQAAAgAAAAABAAAKAAAAAAEAAAQAAAAAAQAAAAAAAAABAAACAAAAAAEAAAoAAAAAAQAABAAAAAABAAAAAAAAAAEAAAIAAAAAAQAABAAAAAABAAAGAAAAAAEAAAIAAAAAAQAABAAAAAABAAAGAAAAAAEAAAIAAAAAAQAABAAAAAABAAAKAAAAAAEAAAQAAAAAAQAAAAAAAAABAAACAAAAAAEAAAQAAAAAAQAACgAAAAABAAAEAAAAAAEAAAAAAAAAAQAAAgAAAAABAAAGAAAAAAEAAAIAAAAAAQAABAAAAAABAAAGAAAAAAEAAAIAAAAAAgAABAAAAAABAAAIAAAAAAIAAAIAAAAAAQAABAAAAAABAAAKAAAAAAEAAAQAAAAAAQAAAAAAAAABAAACAAAAAAEAAAoAAAAAAQAABAAAAAABAAAAAAAAAAEAAAIAAAAAAQAACgAAAAABAAAEAAAAAAEAAAAAAAAAAQAAAgAAAAABAAAKAAAAAAEAAAQAAAAAAQAAAAAAAAABAAACAAAAAAEAAAoAAAAAAQAABAAAAAABAAAAAAAAAAEAAAIAAAAAAQAACAAAAAACAAACAAAAAAEAAAQAAAAAAQAABgAAAAABAAACAAAAAAEAAAQAAAAAAQAACAAAAAACAAACAAAAAAEAAAQAAAAAAQAABgAAAAABAAACAAAAAAEAAAYAAAAAAQAAAgAAAAABAAAKAAAAAAEAAAQAAAAAAQAAAAAAAAABAAACAAAAAAEAAAoAAAAAAQAABAAAAAABAAAAAAAAAAEAAAIAAAAABQAABAAAAAABAAAKAAAAAAEAAAQAAAAAAQAAAAAAAAABAAACAAAAAAEAAAoAAAAAAQAABAAAAAABAAAAAAAAAAEAAAIAAAAAAgAABAAAAAABAAAGAAAAAAEAAAIAAAAAAgAABAAAAAABAAAGAAAAAAEAAAIAAAAAAgAABAAAAAABAAAKAAAAAAEAAAQAAAAAAQAAAAAAAAABAAACAAAAAAEAAAoAAAAAAQAABAAAAAABAAAAAAAAAAEAAAIAAAAAAQAACAAAAAACAAACAAAAAAEAAAoAAAAAAQAABAAAAAABAAAAAAAAAAEAAAIAAAAAAQAACAAAAAACAAACAAAAAAEAAAoAAAAAAQAABAAAAAABAAAAAAAAAAEAAAIAAAAAAQAABgAAAAABAAACAAAAAAEAAAoAAAAAAQAABAAAAAABAAAAAAAAAAEAAAIAAAAAAQAACgAAAAABAAAEAAAAAAEAAAAAAAAAAQAAAgAAAAABAAAEAAAAAAEAAAYAAAAAAQAAAgAAAAABAAAIAAAAAAIAAAIAAAAAAQAACgAAAAABAAAEAAAAAAEAAAAAAAAAAQAAAgAAAAACAAAEAAAAAAEAAAoAAAAAAQAABAAAAAABAAAAAAAAAAEAAAIAAAAAAQAACgAAAAABAAAEAAAAAAEAAAAAAAAAAQAAAgAAAAABAAAKAAAAAAEAAAQAAAAAAQAAAAAAAAABAAACAAAAAAEAAAQAAAAAAQAACgAAAAABAAAEAAAAAAEAAAAAAAAAAQAAAgAAAAABAAAGAAAAAAEAAAIAAAAAAQAABAAAAAABAAAIAAAAAAIAAAIAAAAAAQAACgAAAAABAAAEAAAAAAEAAAAAAAAAAQAAAgAAAAABAAAKAAAAAAEAAAQAAAAAAQAAAAAAAAABAAACAAAAAAMAAAQAAAAAAQAACgAAAAABAAAEAAAAAAEAAAAAAAAAAQAAAgAAAAABAAAKAAAAAAEAAAQAAAAAAQAAAAAAAAABAAACAAAAAAEAAAQAAAAAAQAACgAAAAABAAAEAAAAAAEAAAAAAAAAAQAAAgAAAAAcc3RzYwAAAAAAAAABAAAAAQAAAVoAAAABAAAFfHN0c3oAAAAAAAAAAAAAAVoAAAozAAAAiQAAAc0AAAA7AAAAPwAAAfoAAABgAAAAQgAAADgAAAF1AAAASwAAACwAAAAoAAABaAAAAEIAAAA5AAAALQAAAV0AAAA9AAABaAAAAFgAAAArAAAALgAAAbgAAABqAAAANQAAAD4AAAFRAAAAWwAAAC0AAAApAAABXwAAAEUAAAArAAAAKwAAAQEAAABjAAAAJQAAAC8AAAFGAAAARgAAACYAAAA0AAAA0QAAAOcAAABFAAAAMgAAAD4AAAC5AAAAwAAAAGUAAABKAAAANgAAALgAAACuAAAAGgAAAJUAAAA1AAAAHAAAAYcAAABCAAAAQgAAACMAAAEMAAAAVgAAACgAAAAqAAAA0gAAAMMAAAA3AAAAJQAAADMAAACJAAAA+wAAAIQAAAApAAAAtAAAALcAAAAuAAAAKwAAACUAAAAvAAAAhwAAAUQAAABPAAAAKAAAACoAAADNAAAAMQAAACIAAAAeAAAAwgAAACIAAADMAAAAQQAAACAAAAAlAAAAuAAAAosAAABaAAAAMAAAAQEAAABWAAAAKAAAADgAAACZAAAAoAAAAF0AAAA3AAAAHwAAABsAAABpAAAAjgAAAC0AAABWAAAAtAAAACgAAAEUAAAAPgAAACwAAAAbAAAAvQAAAEgAAAAmAAABAQAAAGkAAAArAAAALAAAAawAAABTAAAANwAAADkAAAC5AAAAzQAAAHcAAABBAAAAKgAAAHkAAAC8AAAAKgAAACAAAAAaAAAAnwAAADgAAAAdAAAAIgAAAOIAAAA+AAAAIwAAACoAAAGrAAAAawAAADEAAABGAAAA5gAAAD8AAAAsAAAAGgAAAVgAAABWAAAALAAAACwAAADlAAAApwAAAEgAAAC7AAAAtwAAAEMAAADvAAAA+wAAAF4AAAA1AAAAMQAAAMIAAADJAAAAYgAAACYAAAAtAAAAlgAAACEAAABnAAAAvAAAACQAAACTAAAAuAAAAREAAAAqAAAAJAAAANoAAADHAAAAYwAAACQAAAApAAAB1gAAAGwAAAA4AAAAQAAAAkMAAABXAAAANwAAADAAAAFTAAAAVwAAACUAAAArAAAApAAAADsAAAAlAAAAHwAAAPIAAAAmAAAAIAAAAEoAAADQAAAAJAAAAKQAAADxAAAAKQAAABoAAADBAAAA6QAAACUAAADuAAAAIAAAANQAAAA5AAAAIAAAABgAAAC6AAAAMgAAABkAAAAaAAAAZAAAAJwAAADSAAAA2AAAALoAAAEkAAAAeAAAACkAAAAtAAABBwAAAEIAAAAsAAAAJQAAAGkAAACWAAABFgAAACcAAAAgAAANaAAAAC0AAAAXAAAAdQAAAG8AAACKAAAAJAAAABcAAAAcAAAAeAAAAC0AAAAgAAAAFQAAAMEAAAAnAAAAJwAAAFoAAAAnAAAAGAAAABoAAAB/AAAAJQAAABwAAABKAAAAWAAAACUAAAApAAAAlAAAABwAAABXAAAARQAAACkAAAAjAAAASAAAACYAAAAbAAAAHAAAAIIAAABNAAAAFgAAAQEAAAArAAAALAAAAG8AAAA1AAAAJAAAACMAAABvAAAAwgAAAa0AAABSAAAAJAAAACkAAADTAAAALgAAACYAAAAiAAAAoQAAAD0AAAAXAAAAHwAAAI0AAACsAAAAIQAAAB4AAAAUAAAAdwAAABkAAABkAAAAhgAAADcAAAAaAAAB2wAAAKQAAABaAAAAYwAAARAAAACYAAAAPAAAAE4AAAC1AAAAqgAAAJsAAACLAAAANgAAACcAAAAtAAAAzQAAAHYAAAA/AAAANwAAAIQAAAB2AAAAhAAAADkAAAAvAAAAFHN0Y28AAAAAAAAAAQAAADAAAACFdWR0YQAAAFptZXRhAAAAAAAAACFoZGxyAAAAAAAAAABtZGlyYXBwbAAAAAAAAAAAAAAAAC1pbHN0AAAAJal0b28AAAAdZGF0YQAAAAEAAAAATGF2ZjYwLjE1LjEwMAAAACNsb2NpAAAAABXHAAAAcPtqABwVqABAK8ZlYXJ0aAAA").unwrap()),
//             "tb1png3ng028cxvnsmczs0nmwhyv5p2dzevwyupzh3mqn5dum7v7jpnsx58vam",
//             "tb1png3ng028cxvnsmczs0nmwhyv5p2dzevwyupzh3mqn5dum7v7jpnsx58vam",
//             10,
//             None,
//             None
//         )
//         .await
//         .expect("TODO: panic message")
//         .print_json();
//     }
//
//     #[test]
//     fn cal_fee() {
//         let mut file = File::open("/Users/nekilc/Downloads/WechatIMG187.jpg").expect("");
//         let mut b = vec![];
//         let f = file.read_to_end(&mut b);
//         let s = base64::prelude::BASE64_STANDARD.encode(b);
//         println!("{}", s.len());
//         let mut tx = Transaction {
//             version: 2,
//             lock_time: LockTime::ZERO,
//             input: vec![],
//             output: vec![],
//         };
//         println!("{}", tx.vsize());
//         tx.input.push(TxIn {
//             previous_output: Default::default(),
//             script_sig: Default::default(),
//             sequence: Default::default(),
//             witness: Default::default(),
//         });
//         println!("{}", tx.vsize());
//         tx.output.push(TxOut {
//             value: 0,
//             script_pubkey: Default::default(),
//         });
//         tx.output.push(TxOut {
//             value: 0,
//             script_pubkey: Default::default(),
//         });
//         println!("{}", tx.vsize());
//     }
// }
