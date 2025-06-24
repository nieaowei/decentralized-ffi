use bdk_electrum::electrum_client::ElectrumApi;
use bdk_electrum::{electrum_client, BdkElectrumClient};
use bdk_wallet::bitcoin::{Address, Txid};
use bdk_wallet::serde_json;
use deffi::esplora::EsploraClient;
use serde::Serialize;
use std::collections::{BTreeSet, HashMap};
use std::str::FromStr;

#[derive(Serialize, Eq, Hash, PartialEq, Ord, PartialOrd, Clone)]
struct CpfpTx {
    txid: String,
    fee: u64,
    weight: u64,
    parents: BTreeSet<CpfpTx>,
    childs: BTreeSet<CpfpTx>,
}

impl CpfpTx {
    fn find_chain(c: &EsploraClient, start_txid: String, prev_txid: Option<String>) -> CpfpTx {
        println!("find_chain {start_txid}\n");

        let start_tx = c.get_tx_info(start_txid.clone()).unwrap();
        let mut chain_start = CpfpTx {
            txid: start_txid.clone(),
            fee: start_tx.fee.to_sat(),
            weight: start_tx.weight,
            parents: Default::default(),
            childs: Default::default(),
        };

        // if let Some(v) = visited.get(&start_txid) {
        //     println!("989\n");
        //     return v.clone();
        // }else {
        //     visited.insert(start_txid.clone(), (chain_start.clone()));
        // }

        for txin in start_tx.vin {
            if let Some(prev_txid) = prev_txid.clone() {
                if prev_txid == txin.txid {
                    continue;
                }
            }
            let tx_info = c.get_tx_info(txin.txid.clone()).unwrap();
            if tx_info.status.confirmed {
                continue;
            }

            chain_start.parents.insert(Self::find_chain(
                c,
                tx_info.txid.clone(),
                Some(start_txid.clone()),
            ));
        }
        for txout in start_tx.vout.iter().enumerate() {
            let outstatus = c
                .get_output_status(start_txid.clone(), txout.0 as u64)
                .unwrap();
            if !outstatus.spent {
                continue;
            }
            let tx_info = c.get_tx_info(outstatus.txid.unwrap()).unwrap();
            if let Some(prev_txid) = prev_txid.clone() {
                if prev_txid == tx_info.txid {
                    continue;
                }
            }
            if tx_info.status.confirmed {
                continue;
            }
            chain_start.childs.insert(Self::find_chain(
                c,
                tx_info.txid.clone(),
                Some(start_txid.clone()),
            ));
        }
        chain_start
    }
}

fn main() {
    let c = EsploraClient::new("https://mempool.space/api".to_string());
    let e = electrum_client::Client::new("ssl://mempool.space:40002").unwrap();
    let txid =
        Txid::from_str("48463f7d969bf0b818db48a874335b42b2b765db501157e418ecf44d9a5d5cc8").unwrap();

    // let childs = CpfpTx::find_chain(&c, "b3c517c60e8475d20198da090a3a89a2190969882b5304b2820d630c657288e0".to_string(), None);
    // println!("{}", serde_json::to_string(&childs).unwrap());

    let addr = Address::from_str("tb1peaxng4ag9d2a7lsf4zkq2y3slk4aww9vtrcs3yg2j0w66j3qdqesc7qhx4")
        .unwrap()
        .assume_checked();

    let tx = e.transaction_get(&txid).unwrap();

    // let his = e.script_get_history(addr.script_pubkey().as_script()).unwrap();

    // println!("{:?}", his);
    let utxo = e
        .script_list_unspent(addr.script_pubkey().as_script())
        .unwrap();
    println!("{:?}", utxo);
}
