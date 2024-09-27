use std::convert::TryInto;
use std::fmt::{Display, Formatter};

#[derive(Default, Ord, PartialOrd, PartialEq, Eq,Copy, Clone)]
pub struct RuneId {
    pub block: u64,
    pub tx: u32,
}

impl Display for RuneId {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!("{}:{}", self.block, self.tx))
    }
}

impl RuneId {
    pub fn new(block: u64, tx: u32) -> Option<RuneId> {
        let id = RuneId { block, tx };

        if id.block == 0 && id.tx > 0 {
            return None;
        }

        Some(id)
    }

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
        RuneId::new(
            self.block.checked_add(block.try_into().ok()?)?,
            if block == 0 {
                self.tx.checked_add(tx.try_into().ok()?)?
            } else {
                tx.try_into().ok()?
            },
        )
    }
}

