use std::convert::TryInto;
use std::fmt::{Display, Formatter};
use std::num::ParseIntError;
use std::str::FromStr;
use std::sync::Arc;

#[derive(uniffi::Object, Debug, Clone, PartialEq, Eq, Hash)]
#[uniffi::export(Debug, Display, Eq, Hash)]
#[derive(Default)]
pub struct RuneId {
    pub block: u64,
    pub tx: u32,
}

impl Display for RuneId {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!("{}:{}", self.block, self.tx))
    }
}

impl FromStr for RuneId {
    type Err = ParseRuneIdError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (height, index) = s.split_once(':').ok_or(ParseRuneIdError::Separator)?;

        Ok(Self {
            block: height.parse::<u64>().map_err(|e| ParseRuneIdError::Block { error_message: e.to_string() })?,
            tx: index.parse::<u32>().map_err(|e| ParseRuneIdError::Transaction { error_message: e.to_string() })?,
        })
    }
}

#[derive(thiserror::Error, uniffi::Error, Debug)]
pub enum ParseRuneIdError {
    #[error("missing separator")]
    Separator,
    #[error("invalid block number:{error_message}")]
    Block { error_message: String },
    #[error("invalid tx number:{error_message}")]
    Transaction { error_message: String },
    #[error("invalid tx runeid")]
    InvalidRuneId
}

#[uniffi::export]
impl RuneId {
    #[uniffi::constructor]
    pub fn new(block: u64, tx: u32) -> Result<Self, ParseRuneIdError> {
        let id = RuneId { block, tx };

        if id.block == 0 && id.tx > 0 {
            return Err(ParseRuneIdError::InvalidRuneId)
        }

        Ok(id)
    }

    #[uniffi::constructor]
    pub fn from_string(s: &str) -> Result<Self, ParseRuneIdError> {
        Ok(s.parse()?)
    }

    pub fn block(&self) -> u64 {
        self.block
    }

    pub fn tx(&self) -> u32 {
        self.tx
    }
}


impl RuneId {

    pub fn delta(self, next: RuneId) -> Option<(u128, u128)> {
        let block = next.block.checked_sub(self.block)?;

        let tx = if block == 0 {
            next.tx.checked_sub(self.tx)?
        } else {
            next.tx
        };

        Some((block.into(), tx.into()))
    }

    pub fn next(self: RuneId, block: u128, tx: u128) -> Option<RuneId> {
        Some(RuneId {
            block: self.block.checked_add(block.try_into().ok()?)?,
            tx: if block == 0 {
                self.tx.checked_add(tx.try_into().ok()?)?
            } else {
                tx.try_into().ok()?
            },
        })
    }
}

