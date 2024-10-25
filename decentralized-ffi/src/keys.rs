use crate::error::{Bip32Error, Bip39Error, DescriptorKeyError};

use bdk_wallet::bitcoin::bip32::DerivationPath as BdkDerivationPath;
use bdk_wallet::bitcoin::key::Secp256k1;
use bdk_wallet::bitcoin::secp256k1::rand;
use bdk_wallet::bitcoin::secp256k1::rand::Rng;
use bdk_wallet::keys::bip39::WordCount as BdkWordCount;
use bdk_wallet::keys::bip39::{Language, Mnemonic as BdkMnemonic};
use bdk_wallet::keys::{DerivableKey, DescriptorPublicKey as BdkDescriptorPublicKey, DescriptorSecretKey as BdkDescriptorSecretKey, ExtendedKey, GeneratableKey, GeneratedKey, SinglePriv};
use bdk_wallet::miniscript::descriptor::{DescriptorXKey, Wildcard};
use bdk_wallet::miniscript::BareCtx;

use std::fmt::Display;
use std::ops::Deref;
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use crate::testnet4::Network;

#[derive(uniffi::Enum, Debug, Clone, PartialEq, Eq, Hash)]
pub enum WordCount {
    /// 12 words mnemonic (128 bits entropy)
    Words12 = 128,
    /// 15 words mnemonic (160 bits entropy)
    Words15 = 160,
    /// 18 words mnemonic (192 bits entropy)
    Words18 = 192,
    /// 21 words mnemonic (224 bits entropy)
    Words21 = 224,
    /// 24 words mnemonic (256 bits entropy)
    Words24 = 256,
}

impl From<WordCount> for BdkWordCount {
    fn from(value: WordCount) -> Self {
        match value {
            WordCount::Words12 => {
                BdkWordCount::Words12
            }
            WordCount::Words15 => {
                BdkWordCount::Words15
            }
            WordCount::Words18 => {
                BdkWordCount::Words18
            }
            WordCount::Words21 => {
                BdkWordCount::Words21
            }
            WordCount::Words24 => {
                BdkWordCount::Words24
            }
        }
    }
}

#[derive(uniffi::Object, Debug, Clone, PartialEq, Eq, Hash)]
#[uniffi::export(Debug, Display, Eq, Hash)]
pub(crate) struct Mnemonic(BdkMnemonic);

#[uniffi::export]
impl Mnemonic {
    #[uniffi::constructor]
    pub(crate) fn new(word_count: WordCount) -> Self {
        // TODO 4: I DON'T KNOW IF THIS IS A DECENT WAY TO GENERATE ENTROPY PLEASE CONFIRM
        let mut rng = rand::thread_rng();
        let mut entropy = [0u8; 32];
        rng.fill(&mut entropy);

        let generated_key: GeneratedKey<_, BareCtx> =
            BdkMnemonic::generate_with_entropy((BdkWordCount::from(word_count), Language::English), entropy).unwrap();
        let mnemonic = BdkMnemonic::parse_in(Language::English, generated_key.to_string()).unwrap();
        Mnemonic(mnemonic)
    }

    #[uniffi::constructor]
    pub(crate) fn from_string(mnemonic: &str) -> Result<Self, Bip39Error> {
        BdkMnemonic::from_str(&mnemonic)
            .map(Mnemonic)
            .map_err(Bip39Error::from)
    }

    #[uniffi::constructor]
    pub(crate) fn from_entropy(entropy: Vec<u8>) -> Result<Self, Bip39Error> {
        BdkMnemonic::from_entropy(entropy.as_slice())
            .map(Mnemonic)
            .map_err(Bip39Error::from)
    }
}


impl Display for Mnemonic {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[derive(uniffi::Object)]
pub(crate) struct DerivationPath {
    inner_mutex: Mutex<BdkDerivationPath>,
}

#[uniffi::export]
impl DerivationPath {
    #[uniffi::constructor]
    pub(crate) fn new(path: String) -> Result<Self, Bip32Error> {
        BdkDerivationPath::from_str(&path)
            .map(|x| DerivationPath {
                inner_mutex: Mutex::new(x),
            })
            .map_err(Bip32Error::from)
    }
}

#[derive(Debug, uniffi::Object)]
pub struct DescriptorSecretKey(pub(crate) BdkDescriptorSecretKey);

#[uniffi::export]
impl DescriptorSecretKey {
    #[uniffi::constructor]
    pub(crate) fn new(network: Network, mnemonic: &Mnemonic, password: Option<String>) -> Self {
        let mnemonic = mnemonic.0.clone();
        let xkey: ExtendedKey = (mnemonic, password).into_extended_key().unwrap();
        let descriptor_secret_key = BdkDescriptorSecretKey::XPrv(DescriptorXKey {
            origin: None,
            xkey: xkey.into_xprv(network.to_bitcoin_network()).unwrap(),
            derivation_path: BdkDerivationPath::master(),
            wildcard: Wildcard::Unhardened,
        });
        Self(descriptor_secret_key)
    }

    #[uniffi::constructor]
    pub(crate) fn from_string(private_key: String) -> Result<Self, DescriptorKeyError> {
        let descriptor_secret_key = BdkDescriptorSecretKey::from_str(private_key.as_str())
            .map_err(DescriptorKeyError::from)?;
        Ok(Self(descriptor_secret_key))
    }

    pub(crate) fn derive_priv(&self, path: &DerivationPath) -> Result<Arc<DescriptorSecretKey>, DescriptorKeyError> {
        let secp = Secp256k1::new();
        let descriptor_secret_key = &self.0;
        let path = path.inner_mutex.lock().unwrap().deref().clone();
        match descriptor_secret_key {
            BdkDescriptorSecretKey::Single(_) => Err(DescriptorKeyError::InvalidKeyType),
            BdkDescriptorSecretKey::XPrv(descriptor_x_key) => {
                let xpriv = descriptor_x_key.xkey.derive_priv(&secp, &path)?;

                let xprv = BdkDescriptorSecretKey::Single(SinglePriv { origin: Some((xpriv.fingerprint(&secp), path.clone())), key: xpriv.to_priv() });
                // let descriptor_secret_key = BdkDescriptorSecretKey::from_str(&xpriv.to_priv().to_wif()).unwrap();
                Ok(Arc::new(DescriptorSecretKey(xprv)))
            }
            BdkDescriptorSecretKey::MultiXPrv(_) => Err(DescriptorKeyError::InvalidKeyType),
        }
    }

    pub(crate) fn derive(&self, path: &DerivationPath) -> Result<Arc<Self>, DescriptorKeyError> {
        let secp = Secp256k1::new();
        let descriptor_secret_key = &self.0;
        let path = path.inner_mutex.lock().unwrap().deref().clone();
        match descriptor_secret_key {
            BdkDescriptorSecretKey::Single(_) => Err(DescriptorKeyError::InvalidKeyType),
            BdkDescriptorSecretKey::XPrv(descriptor_x_key) => {
                let derived_xprv = descriptor_x_key
                    .xkey
                    .derive_priv(&secp, &path)
                    .map_err(DescriptorKeyError::from)?;
                let key_source = match descriptor_x_key.origin.clone() {
                    Some((fingerprint, origin_path)) => (fingerprint, origin_path.extend(path)),
                    None => (descriptor_x_key.xkey.fingerprint(&secp), path),
                };
                let derived_descriptor_secret_key = BdkDescriptorSecretKey::XPrv(DescriptorXKey {
                    origin: Some(key_source),
                    xkey: derived_xprv,
                    derivation_path: BdkDerivationPath::default(),
                    wildcard: descriptor_x_key.wildcard,
                });
                Ok(Arc::new(Self(derived_descriptor_secret_key)))
            }
            BdkDescriptorSecretKey::MultiXPrv(_) => Err(DescriptorKeyError::InvalidKeyType),
        }
    }

    pub(crate) fn extend(&self, path: &DerivationPath) -> Result<Arc<Self>, DescriptorKeyError> {
        let descriptor_secret_key = &self.0;
        let path = path.inner_mutex.lock().unwrap().deref().clone();
        match descriptor_secret_key {
            BdkDescriptorSecretKey::Single(_) => Err(DescriptorKeyError::InvalidKeyType),
            BdkDescriptorSecretKey::XPrv(descriptor_x_key) => {
                let extended_path = descriptor_x_key.derivation_path.extend(path);
                let extended_descriptor_secret_key = BdkDescriptorSecretKey::XPrv(DescriptorXKey {
                    origin: descriptor_x_key.origin.clone(),
                    xkey: descriptor_x_key.xkey,
                    derivation_path: extended_path,
                    wildcard: descriptor_x_key.wildcard,
                });
                Ok(Arc::new(Self(extended_descriptor_secret_key)))
            }
            BdkDescriptorSecretKey::MultiXPrv(_) => Err(DescriptorKeyError::InvalidKeyType),
        }
    }

    pub(crate) fn as_public(&self) -> Arc<DescriptorPublicKey> {
        let secp = Secp256k1::new();
        let descriptor_public_key = self.0.to_public(&secp).unwrap();
        Arc::new(DescriptorPublicKey(descriptor_public_key))
    }

    pub(crate) fn secret_bytes(&self) -> Vec<u8> {
        let inner = &self.0;
        let secret_bytes: Vec<u8> = match inner {
            BdkDescriptorSecretKey::Single(_) => {
                unreachable!()
            }
            BdkDescriptorSecretKey::XPrv(descriptor_x_key) => {
                descriptor_x_key.xkey.private_key.secret_bytes().to_vec()
            }
            BdkDescriptorSecretKey::MultiXPrv(_) => {
                unreachable!()
            }
        };

        secret_bytes
    }

    pub(crate) fn as_string(&self) -> String {
        self.0.to_string()
    }
}

#[derive(Debug, uniffi::Object)]
pub struct DescriptorPublicKey(pub(crate) BdkDescriptorPublicKey);

#[uniffi::export]
impl DescriptorPublicKey {
    #[uniffi::constructor]
    pub(crate) fn from_string(public_key: String) -> Result<Self, DescriptorKeyError> {
        let descriptor_public_key = BdkDescriptorPublicKey::from_str(public_key.as_str())
            .map_err(DescriptorKeyError::from)?;
        Ok(Self(descriptor_public_key))
    }

    pub(crate) fn derive(&self, path: &DerivationPath) -> Result<Arc<Self>, DescriptorKeyError> {
        let secp = Secp256k1::new();
        let descriptor_public_key = &self.0;
        let path = path.inner_mutex.lock().unwrap().deref().clone();

        match descriptor_public_key {
            BdkDescriptorPublicKey::Single(_) => Err(DescriptorKeyError::InvalidKeyType),
            BdkDescriptorPublicKey::XPub(descriptor_x_key) => {
                let derived_xpub = descriptor_x_key
                    .xkey
                    .derive_pub(&secp, &path)
                    .map_err(DescriptorKeyError::from)?;
                let key_source = match descriptor_x_key.origin.clone() {
                    Some((fingerprint, origin_path)) => (fingerprint, origin_path.extend(path)),
                    None => (descriptor_x_key.xkey.fingerprint(), path),
                };
                let derived_descriptor_public_key = BdkDescriptorPublicKey::XPub(DescriptorXKey {
                    origin: Some(key_source),
                    xkey: derived_xpub,
                    derivation_path: BdkDerivationPath::default(),
                    wildcard: descriptor_x_key.wildcard,
                });
                Ok(Arc::new(Self(derived_descriptor_public_key)))
            }
            BdkDescriptorPublicKey::MultiXPub(_) => Err(DescriptorKeyError::InvalidKeyType),
        }
    }

    pub(crate) fn extend(&self, path: &DerivationPath) -> Result<Arc<Self>, DescriptorKeyError> {
        let descriptor_public_key = &self.0;
        let path = path.inner_mutex.lock().unwrap().deref().clone();
        match descriptor_public_key {
            BdkDescriptorPublicKey::Single(_) => Err(DescriptorKeyError::InvalidKeyType),
            BdkDescriptorPublicKey::XPub(descriptor_x_key) => {
                let extended_path = descriptor_x_key.derivation_path.extend(path);
                let extended_descriptor_public_key = BdkDescriptorPublicKey::XPub(DescriptorXKey {
                    origin: descriptor_x_key.origin.clone(),
                    xkey: descriptor_x_key.xkey,
                    derivation_path: extended_path,
                    wildcard: descriptor_x_key.wildcard,
                });
                Ok(Arc::new(Self(extended_descriptor_public_key)))
            }
            BdkDescriptorPublicKey::MultiXPub(_) => Err(DescriptorKeyError::InvalidKeyType),
        }
    }

    pub(crate) fn as_string(&self) -> String {
        self.0.to_string()
    }
}

#[cfg(test)]
mod test {
    use std::ops::Deref;
    use std::str::FromStr;
    use crate::error::DescriptorKeyError;
    use crate::keys::{DerivationPath, DescriptorPublicKey, DescriptorSecretKey, Mnemonic};
    use std::sync::Arc;
    use bdk_wallet::bitcoin::bip32::{ExtendendPrivKey, Xpriv};
    use bdk_wallet::keys::{DerivableKey, ExtendedKey};
    use bdk_wallet::{bip39, bitcoin, descriptor, miniscript, KeychainKind, Wallet};
    use bdk_wallet::bitcoin::bip32;
    use bdk_wallet::bitcoin::key::Secp256k1;
    use bdk_wallet::descriptor::{Descriptor, IntoWalletDescriptor};
    use bdk_wallet::miniscript::Tap;
    use crate::testnet4::Network;

    fn get_inner() -> DescriptorSecretKey {
        let mnemonic = Mnemonic::from_string("chaos fabric time speed sponsor all flat solution wisdom trophy crack object robot pave observe combine where aware bench orient secret primary cable detect").unwrap();
        DescriptorSecretKey::new(Network::Testnet, &mnemonic, None)
    }

    fn derive_dsk(
        key: &DescriptorSecretKey,
        path: &str,
    ) -> Result<Arc<DescriptorSecretKey>, DescriptorKeyError> {
        let path = DerivationPath::new(path.to_string()).unwrap();
        key.derive(&path)
    }

    fn extend_dsk(
        key: &DescriptorSecretKey,
        path: &str,
    ) -> Result<Arc<DescriptorSecretKey>, DescriptorKeyError> {
        let path = DerivationPath::new(path.to_string()).unwrap();
        key.extend(&path)
    }

    fn derive_dpk(
        key: &DescriptorPublicKey,
        path: &str,
    ) -> Result<Arc<DescriptorPublicKey>, DescriptorKeyError> {
        let path = DerivationPath::new(path.to_string()).unwrap();
        key.derive(&path)
    }

    fn extend_dpk(
        key: &DescriptorPublicKey,
        path: &str,
    ) -> Result<Arc<DescriptorPublicKey>, DescriptorKeyError> {
        let path = DerivationPath::new(path.to_string()).unwrap();
        key.extend(&path)
    }

    #[test]
    fn test_generate_single() {
        let mnemonic = Mnemonic::from_string("chaos fabric time speed sponsor all flat solution wisdom trophy crack object robot pave observe combine where aware bench orient secret primary cable detect").unwrap();
        let a = DescriptorSecretKey::new(Network::Bitcoin, &mnemonic, None);
        // let seed = mnemonic.0.to_seed("");
        // let xp = Xpriv::new_master(bitcoin::Network::Bitcoin, &seed).unwrap();
        // let a: ExtendedKey<Tap> = ExtendedKey::from(xp);
        // let derivation_path = bip32::DerivationPath::from_str("m/86'/0'/0'/0/1").expect("Invalid derivation path");
        // let a = xp.derive_priv(&Secp256k1::new(), &derivation_path).unwrap();
        // let private_key = a.to_priv().to_wif();

        // println!("{}", private_key);

        // let ds = DescriptorSecretKey::from_string(private_key.clone()).unwrap();

        // println!("{}", ds.as_string());

        // let bitcoin_xprv = ExtendedPrivKey::from_str(&derived_xprv.to_string(Prefix::XPRV)).expect("Error converting to bitcoin xprv");
        //
        // // 生成公钥用于描述符
        // let bitcoin_xpub = ExtendedPubKey::from_private(&bitcoin_xprv, Network::Bitcoin);

        // let ds = DescriptorSecretKey::new(Network::Bitcoin, &mnemonic, None);

        // let d = Descriptor::new_tr(ds.as_string(),None).unwrap();
        // let c = Descriptor::new_tr(private_key, None).unwrap();
        // println!("{}", c.to_string());

        // let d = Descriptor::new_tr(a.private_key, None).unwrap();
        // println!("{}", d.to_string());
        // match ds.0 {
        //     miniscript::descriptor::DescriptorSecretKey::Single(s) => {}
        //     miniscript::descriptor::DescriptorSecretKey::XPrv(x) => {
        //         x.xkey.derive_priv()
        //     }
        //     miniscript::descriptor::DescriptorSecretKey::MultiXPrv(mp) => {
        //
        //     }
        // }
        // let a = ds.derive_priv(&crate::DerivationPath::new("m/86'/0'/0'/0/0".to_string()).unwrap()).unwrap();
        // let a = ds.derive(&crate::DerivationPath::new("m/86'/0'/0'/0/1".to_string()).unwrap()).unwrap();


        // let a = crate::Descriptor::new_bip86(&a, crate::KeychainKind::External, Network::Bitcoin);
        // println!("{}", a.to_string_with_secret());

        // let external_path = bip32::DerivationPath::from_str("m/86h/0h/0h/0/1").unwrap();
        // let ds = descriptor!(tr(((mnemonic,None), external_path))).unwrap()
        //     .into_wallet_descriptor(&Secp256k1::new(), bitcoin::Network::Bitcoin).unwrap();;
        let d = crate::Descriptor::new_bip86(&a, crate::KeychainKind::External, Network::Bitcoin).to_string_with_secret();
        println!("{}", d);

        let mut a = Wallet::create_single(d).create_wallet_no_persist().unwrap();
        println!("{}", a.peek_address(KeychainKind::External, 0));
        println!("{}", a.peek_address(KeychainKind::External, 1));

        println!("{:?}", a.next_unused_address(KeychainKind::External));

        // let a = DescriptorSecretKey::from_string(private_key).unwrap();
        // let derived_xprv = a.into_extended_key().unwrap();

        // let d = bdk_wallet::miniscript::Descriptor::new_tr();
        // let dp = DerivationPath::new("m/86'/0'/0'/0/1".to_string()).unwrap();
        // let ds = ds.derive(&dp).unwrap();
        // println!("{}",ds.as_string());
        // let walllet = bdk_wallet::Wallet::create_single();


        // println!("{:?}",ds.0.into_single_keys());

    }

    #[test]
    fn test_generate_descriptor_secret_key() {
        let master_dsk = get_inner();
        assert_eq!(master_dsk.as_string(), "tprv8ZgxMBicQKsPdWuqM1t1CDRvQtQuBPyfL6GbhQwtxDKgUAVPbxmj71pRA8raTqLrec5LyTs5TqCxdABcZr77bt2KyWA5bizJHnC4g4ysm4h/*");
        assert_eq!(master_dsk.as_public().as_string(), "tpubD6NzVbkrYhZ4WywdEfYbbd62yuvqLjAZuPsNyvzCNV85JekAEMbKHWSHLF9h3j45SxewXDcLv328B1SEZrxg4iwGfmdt1pDFjZiTkGiFqGa/*");
    }

    #[test]
    fn test_derive_self() {
        let master_dsk = get_inner();
        let derived_dsk: &DescriptorSecretKey = &derive_dsk(&master_dsk, "m").unwrap();
        assert_eq!(derived_dsk.as_string(), "[d1d04177]tprv8ZgxMBicQKsPdWuqM1t1CDRvQtQuBPyfL6GbhQwtxDKgUAVPbxmj71pRA8raTqLrec5LyTs5TqCxdABcZr77bt2KyWA5bizJHnC4g4ysm4h/*");
        let master_dpk: &DescriptorPublicKey = &master_dsk.as_public();
        let derived_dpk: &DescriptorPublicKey = &derive_dpk(master_dpk, "m").unwrap();
        assert_eq!(derived_dpk.as_string(), "[d1d04177]tpubD6NzVbkrYhZ4WywdEfYbbd62yuvqLjAZuPsNyvzCNV85JekAEMbKHWSHLF9h3j45SxewXDcLv328B1SEZrxg4iwGfmdt1pDFjZiTkGiFqGa/*");
    }

    #[test]
    fn test_derive_descriptors_keys() {
        let master_dsk = get_inner();
        let derived_dsk: &DescriptorSecretKey = &derive_dsk(&master_dsk, "m/0").unwrap();
        assert_eq!(derived_dsk.as_string(), "[d1d04177/0]tprv8d7Y4JLmD25jkKbyDZXcdoPHu1YtMHuH21qeN7mFpjfumtSU7eZimFYUCSa3MYzkEYfSNRBV34GEr2QXwZCMYRZ7M1g6PUtiLhbJhBZEGYJ/*");
        let master_dpk: &DescriptorPublicKey = &master_dsk.as_public();
        let derived_dpk: &DescriptorPublicKey = &derive_dpk(master_dpk, "m/0").unwrap();
        assert_eq!(derived_dpk.as_string(), "[d1d04177/0]tpubD9oaCiP1MPmQdndm7DCD3D3QU34pWd6BbKSRedoZF1UJcNhEk3PJwkALNYkhxeTKL29oGNR7psqvT1KZydCGqUDEKXN6dVQJY2R8ooLPy8m/*");
    }

    #[test]
    fn test_extend_descriptor_keys() {
        let master_dsk = get_inner();
        let extended_dsk: &DescriptorSecretKey = &extend_dsk(&master_dsk, "m/0").unwrap();
        assert_eq!(extended_dsk.as_string(), "tprv8ZgxMBicQKsPdWuqM1t1CDRvQtQuBPyfL6GbhQwtxDKgUAVPbxmj71pRA8raTqLrec5LyTs5TqCxdABcZr77bt2KyWA5bizJHnC4g4ysm4h/0/*");
        let master_dpk: &DescriptorPublicKey = &master_dsk.as_public();
        let extended_dpk: &DescriptorPublicKey = &extend_dpk(master_dpk, "m/0").unwrap();
        assert_eq!(extended_dpk.as_string(), "tpubD6NzVbkrYhZ4WywdEfYbbd62yuvqLjAZuPsNyvzCNV85JekAEMbKHWSHLF9h3j45SxewXDcLv328B1SEZrxg4iwGfmdt1pDFjZiTkGiFqGa/0/*");
        let wif = "L2wTu6hQrnDMiFNWA5na6jB12ErGQqtXwqpSL7aWquJaZG8Ai3ch";
        let extended_key = DescriptorSecretKey::from_string(wif.to_string()).unwrap();
        let result = extended_key.derive(&DerivationPath::new("m/0".to_string()).unwrap());
        dbg!(&result);
        assert!(result.is_err());
    }

    #[test]
    fn test_from_str_inner() {
        let key1 = "L2wTu6hQrnDMiFNWA5na6jB12ErGQqtXwqpSL7aWquJaZG8Ai3ch";
        let key2 = "tprv8ZgxMBicQKsPcwcD4gSnMti126ZiETsuX7qwrtMypr6FBwAP65puFn4v6c3jrN9VwtMRMph6nyT63NrfUL4C3nBzPcduzVSuHD7zbX2JKVc/1/1/1/*";
        let private_descriptor_key1 = DescriptorSecretKey::from_string(key1.to_string()).unwrap();
        let private_descriptor_key2 = DescriptorSecretKey::from_string(key2.to_string()).unwrap();
        dbg!(private_descriptor_key1);
        dbg!(private_descriptor_key2);
        // Should error out because you can't produce a DescriptorSecretKey from an xpub
        let key0 = "tpubDBrgjcxBxnXyL575sHdkpKohWu5qHKoQ7TJXKNrYznh5fVEGBv89hA8ENW7A8MFVpFUSvgLqc4Nj1WZcpePX6rrxviVtPowvMuGF5rdT2Vi";
        assert!(DescriptorSecretKey::from_string(key0.to_string()).is_err());
    }

    #[test]
    fn test_derive_and_extend_inner() {
        let master_dsk = get_inner();
        // derive DescriptorSecretKey with path "m/0" from master
        let derived_dsk: &DescriptorSecretKey = &derive_dsk(&master_dsk, "m/0").unwrap();
        assert_eq!(derived_dsk.as_string(), "[d1d04177/0]tprv8d7Y4JLmD25jkKbyDZXcdoPHu1YtMHuH21qeN7mFpjfumtSU7eZimFYUCSa3MYzkEYfSNRBV34GEr2QXwZCMYRZ7M1g6PUtiLhbJhBZEGYJ/*");
        // extend derived_dsk with path "m/0"
        let extended_dsk: &DescriptorSecretKey = &extend_dsk(derived_dsk, "m/0").unwrap();
        assert_eq!(extended_dsk.as_string(), "[d1d04177/0]tprv8d7Y4JLmD25jkKbyDZXcdoPHu1YtMHuH21qeN7mFpjfumtSU7eZimFYUCSa3MYzkEYfSNRBV34GEr2QXwZCMYRZ7M1g6PUtiLhbJhBZEGYJ/0/*");
    }

    #[test]
    fn test_derive_hardened_path_using_public() {
        let master_dpk = get_inner().as_public();
        let derived_dpk = &derive_dpk(&master_dpk, "m/84h/1h/0h");
        assert!(derived_dpk.is_err());
    }

    // TODO 7: It appears that the to_hex() method is not available anymore.
    //       Look into the correct way to pull the hex out of the DescriptorSecretKey.
    //       Note: ToHex was removed in bitcoin_hashes 0.12.0
    // #[test]
    // fn test_retrieve_master_secret_key() {
    //     let master_dpk = get_inner();
    //     let master_private_key = master_dpk.secret_bytes().to_hex();
    //     assert_eq!(
    //         master_private_key,
    //         "e93315d6ce401eb4db803a56232f0ed3e69b053774e6047df54f1bd00e5ea936"
    //     )
    // }
}
