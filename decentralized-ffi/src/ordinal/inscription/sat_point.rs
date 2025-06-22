use std::{
    fmt,
    fmt::{Display, Formatter},
    io,
    str::FromStr,
};
use std::num::ParseIntError;
use anyhow::{anyhow, Result};
use bdk_wallet::bitcoin;
use bdk_wallet::bitcoin::{
    consensus::{Decodable, Encodable},
    OutPoint,
};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use thiserror::Error;
use crate::ordinal::inscription::deserialize_from_str::DeserializeFromStr;
use {super::*, bitcoin::transaction::ParseOutPointError};


#[derive(
    Debug,
    PartialEq,
    Copy,
    Clone,
    Eq,
    PartialOrd,
    Ord,
    Default,
    Hash,
    DeserializeFromStr,
    SerializeDisplay,
)]
pub struct SatPoint {
    pub outpoint: OutPoint,
    pub offset: u64,
}

impl Display for SatPoint {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "{}:{}", self.outpoint, self.offset)
    }
}

impl Encodable for SatPoint {
    fn consensus_encode<S: bitcoin::io::Write + ?Sized>(
        &self,
        s: &mut S,
    ) -> Result<usize, bitcoin::io::Error> {
        let len = self.outpoint.consensus_encode(s)?;
        Ok(len + self.offset.consensus_encode(s)?)
    }
}

impl Decodable for SatPoint {
    fn consensus_decode<D: bitcoin::io::Read + bitcoin::io::BufRead + ?Sized>(
        d: &mut D,
    ) -> Result<Self, bitcoin::consensus::encode::Error> {
        Ok(SatPoint {
            outpoint: Decodable::consensus_decode(d)?,
            offset: Decodable::consensus_decode(d)?,
        })
    }
}

impl FromStr for SatPoint {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (outpoint, offset) = s.rsplit_once(':').ok_or_else(|| Error::Colon(s.into()))?;

        Ok(SatPoint {
            outpoint: outpoint
                .parse::<OutPoint>()
                .map_err(|err| Error::Outpoint {
                    outpoint: outpoint.into(),
                    err,
                })?,
            offset: offset.parse::<u64>().map_err(|err| Error::Offset {
                offset: offset.into(),
                err,
            })?,
        })
    }
}

#[derive(Debug, Error)]
pub enum Error {
    #[error("satpoint `{0}` missing colon")]
    Colon(String),
    #[error("satpoint offset `{offset}` invalid: {err}")]
    Offset { offset: String, err: ParseIntError },
    #[error("satpoint outpoint `{outpoint}` invalid: {err}")]
    Outpoint {
        outpoint: String,
        err: ParseOutPointError,
    },
}
#[cfg(test)]
mod tests {
    use super::*;
    use bdk_wallet::serde_json;

    #[test]
    fn from_str_ok() {
        assert_eq!(
            "1111111111111111111111111111111111111111111111111111111111111111:1:1"
                .parse::<SatPoint>()
                .unwrap(),
            SatPoint {
                outpoint: "1111111111111111111111111111111111111111111111111111111111111111:1"
                    .parse()
                    .unwrap(),
                offset: 1,
            }
        );
    }

    #[test]
    fn from_str_err() {
        "abc".parse::<SatPoint>().unwrap_err();

        "abc:xyz".parse::<SatPoint>().unwrap_err();

        "1111111111111111111111111111111111111111111111111111111111111111:1"
            .parse::<SatPoint>()
            .unwrap_err();

        "1111111111111111111111111111111111111111111111111111111111111111:1:foo"
            .parse::<SatPoint>()
            .unwrap_err();
    }

    #[test]
    fn deserialize_ok() {
        assert_eq!(
            serde_json::from_str::<SatPoint>(
                "\"1111111111111111111111111111111111111111111111111111111111111111:1:1\""
            )
            .unwrap(),
            SatPoint {
                outpoint: "1111111111111111111111111111111111111111111111111111111111111111:1"
                    .parse()
                    .unwrap(),
                offset: 1,
            }
        );
    }
}
