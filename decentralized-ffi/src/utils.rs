use std::collections::HashMap;
use std::str::FromStr;
use std::sync::Arc;
use base64::Engine;
use base64::prelude::BASE64_STANDARD;
use bdk_wallet::bitcoin::consensus::encode::deserialize_hex;
use crate::bitcoin::{Script, TxIn, TxOut};

use bdk_wallet::bitcoin::{TxIn as BDKTxIn, Witness};
use bdk_wallet::bitcoin::TxOut as BDKTxOut;
use bdk_wallet::serde_json;
use chrono::SecondsFormat;
use hmac::{Hmac, KeyInit, Mac};
use jsonpath_rust::JsonPath;
use regex::Regex;
use sha2::Sha256;
use url::Url;

#[uniffi::export]
pub fn script_to_asm_string(script: Arc<Script>) -> String {
    script.0.to_asm_string()
}


#[uniffi::export]
pub fn new_txin_from_hex(hex: String, witness_hex: String) -> Option<TxIn> {
    let w = deserialize_hex::<Witness>(&witness_hex).ok()?;

    deserialize_hex::<BDKTxIn>(hex.as_str()).ok().map(|mut e| {
        e.witness = w;
        (&e).into()
    })
}

#[uniffi::export]
pub fn new_txout_from_hex(hex: String) -> Option<TxOut> {
    deserialize_hex::<BDKTxOut>(hex.as_str()).ok().map(|e| (&e).into())
}


#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum UtilsError {
    #[error("minreq error: {error_message}")]
    Minreq { error_message: String },

    #[error("json path error: {error_message}")]
    JsonPath { error_message: String },
}


#[uniffi::export]
pub fn get_json_info_from_url(url: String, auth: String, params: Vec<String>, paths: Vec<String>) -> Result<Vec<Option<String>>, UtilsError> {
    let mut url = url;
    for param in params.iter().enumerate() {
        url = url.replace(&format!(r#"{{{}}}"#, param.0), param.1);
    }

    let url = Url::parse(&url).unwrap();
    let resp = minreq::get(url.as_str());

    let now = chrono::Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true);
    let auths: HashMap<String, String> = serde_json::from_str(&auth).map_err(|err| UtilsError::JsonPath { error_message: err.to_string() })?;
    let mut headers = HashMap::new();
    for (key, mut value) in auths {
        if key.to_lowercase() == "AUTHORIZATION".to_lowercase() {
            headers.insert("AUTHORIZATION".to_string(), value);
        } else {
            value = value.replace("{timestamp}", now.as_str());
            value = value.replace("{request_method}", "GET");
            value = value.replace("{request_path}", &format!("{}?{}", url.path(), url.query().unwrap_or_default()));

            let reg = Regex::new(r"hmac\((.*)\)").unwrap();
            let data = reg.captures(&value);
            if let Some(data) = data {
                if let Some(hmac) = data.get(1) {
                    let split = hmac.as_str().split(',').collect::<Vec<&str>>();
                    let secret = split[1].as_bytes(); // 密钥
                    let message = split[0].as_bytes();

                    let mut mac = Hmac::<Sha256>::new_from_slice(secret)
                        .expect("HMAC can take key of any size");

                    mac.update(message);

                    // 生成签名
                    let result = mac.finalize();
                    let code_bytes = result.into_bytes().to_vec();
                    value = BASE64_STANDARD.encode(&code_bytes);
                }
            }
            headers.insert(key, value);
        }
    }
    let json = resp.with_headers(headers).send().map_err(|e| UtilsError::Minreq { error_message: e.to_string() })?;
    if json.status_code != 200 {
        return Err(UtilsError::Minreq { error_message: json.as_str().unwrap_or_default().to_string() });
    }
    let json = json.as_str().map_err(|e| UtilsError::JsonPath { error_message: e.to_string() })?;

    let mut datas = Vec::new();
    for path in paths {
        let path = JsonPath::from_str(path.as_str()).map_err(|e| UtilsError::JsonPath { error_message: e.to_string() })?;
        let data = path.find(&serde_json::Value::from_str(&json).map_err(|e| UtilsError::JsonPath { error_message: e.to_string() })?);
        if !data.is_null() {
            if let Some(data) = data.as_array() {
                if let Some(data) = data.first() {
                    if !data.is_null() {
                        if let Some(data) = data.as_str() {
                            if !data.is_empty() {
                                datas.push(Some(data.to_string()));
                                continue;
                            }
                        }
                    }
                }
            }
        }
        datas.push(None);
    }
    Ok(datas)
}


#[cfg(test)]
mod tests {
    fn get_esplora_client() -> crate::esplora::EsploraClient {
        crate::esplora::EsploraClient::new("https://mempool.space/api".to_string())
    }
}