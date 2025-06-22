use std::{
    cmp,
    ops::{Add, AddAssign},
    str::FromStr,
};
use std::convert::TryFrom;
use anyhow::{anyhow, bail, Error, Result};
use bdk_wallet::bitcoin::constants::{ DIFFCHANGE_INTERVAL, SUBSIDY_HALVING_INTERVAL};
use derive_more::Display;
use serde::{Deserialize, Serialize};

use crate::ordinal::inscription::{
    common::CYCLE_EPOCHS, decimal_sat::DecimalSat, degree::Degree, epoch::Epoch, height::Height,
    rarity::Rarity,
};
use crate::ordinal::inscription::common::COIN_VALUE;

#[derive(Copy, Clone, Eq, PartialEq, Debug, Display, Ord, PartialOrd, Deserialize, Serialize)]
#[serde(transparent)]
pub struct Sat(pub u64);

impl Sat {
    pub(crate) const LAST: Self = Self(Self::SUPPLY - 1);
    pub(crate) const SUPPLY: u64 = 2099999997690000;

    pub(crate) fn n(self) -> u64 {
        self.0
    }

    pub(crate) fn degree(self) -> Degree {
        self.into()
    }

    pub(crate) fn height(self) -> Height {
        self.epoch().starting_height()
            + u32::try_from(self.epoch_position() / self.epoch().subsidy()).unwrap()
    }

    pub(crate) fn cycle(self) -> u32 {
        Epoch::from(self).0 / CYCLE_EPOCHS
    }

    pub(crate) fn nineball(self) -> bool {
        self.n() >= 50 * COIN_VALUE * 9 && self.n() < 50 * COIN_VALUE * 10
    }

    pub(crate) fn percentile(self) -> String {
        format!("{}%", (self.0 as f64 / Self::LAST.0 as f64) * 100.0)
    }

    pub(crate) fn epoch(self) -> Epoch {
        self.into()
    }

    pub(crate) fn period(self) -> u32 {
        self.height().n() / DIFFCHANGE_INTERVAL
    }

    pub(crate) fn third(self) -> u64 {
        self.epoch_position() % self.epoch().subsidy()
    }

    pub(crate) fn epoch_position(self) -> u64 {
        self.0 - self.epoch().starting_sat().0
    }

    pub(crate) fn decimal(self) -> DecimalSat {
        self.into()
    }

    pub(crate) fn rarity(self) -> Rarity {
        self.into()
    }

    /// `Sat::rarity` is expensive and is called frequently when indexing.
    /// Sat::is_common only checks if self is `Rarity::Common` but is
    /// much faster.
    pub(crate) fn common(self) -> bool {
        let epoch = self.epoch();
        (self.0 - epoch.starting_sat().0) % epoch.subsidy() != 0
    }

    pub(crate) fn coin(self) -> bool {
        self.n() % COIN_VALUE == 0
    }

    pub(crate) fn name(self) -> String {
        let mut x = Self::SUPPLY - self.0;
        let mut name = String::new();
        while x > 0 {
            name.push(
                "abcdefghijklmnopqrstuvwxyz"
                    .chars()
                    .nth(((x - 1) % 26) as usize)
                    .unwrap(),
            );
            x = (x - 1) / 26;
        }
        name.chars().rev().collect()
    }

    fn from_name(s: &str) -> Result<Self> {
        let mut x = 0;
        for c in s.chars() {
            match c {
                'a'..='z' => {
                    x = x * 26 + c as u64 - 'a' as u64 + 1;
                    if x > Self::SUPPLY {
                        bail!("sat name out of range");
                    }
                }
                _ => bail!("invalid character in sat name: {c}"),
            }
        }
        Ok(Sat(Self::SUPPLY - x))
    }

    fn from_degree(degree: &str) -> Result<Self> {
        let (cycle_number, rest) = degree
            .split_once('°')
            .ok_or_else(|| anyhow!("missing degree symbol"))?;
        let cycle_number = cycle_number.parse::<u32>()?;

        let (epoch_offset, rest) = rest
            .split_once('′')
            .ok_or_else(|| anyhow!("missing minute symbol"))?;
        let epoch_offset = epoch_offset.parse::<u32>()?;
        if epoch_offset >= SUBSIDY_HALVING_INTERVAL {
            bail!("invalid epoch offset");
        }

        let (period_offset, rest) = rest
            .split_once('″')
            .ok_or_else(|| anyhow!("missing second symbol"))?;
        let period_offset = period_offset.parse::<u32>()?;
        if period_offset >= DIFFCHANGE_INTERVAL {
            bail!("invalid period offset");
        }

        let cycle_start_epoch = cycle_number * CYCLE_EPOCHS;

        const HALVING_INCREMENT: u32 = SUBSIDY_HALVING_INTERVAL % DIFFCHANGE_INTERVAL;

        // For valid degrees the relationship between epoch_offset and period_offset
        // will increment by 336 every halving.
        let relationship = period_offset + SUBSIDY_HALVING_INTERVAL * CYCLE_EPOCHS - epoch_offset;

        if relationship % HALVING_INCREMENT != 0 {
            bail!("relationship between epoch offset and period offset must be multiple of 336");
        }

        let epochs_since_cycle_start = relationship % DIFFCHANGE_INTERVAL / HALVING_INCREMENT;

        let epoch = cycle_start_epoch + epochs_since_cycle_start;

        let height = Height(epoch * SUBSIDY_HALVING_INTERVAL + epoch_offset);

        let (block_offset, rest) = match rest.split_once('‴') {
            Some((block_offset, rest)) => (block_offset.parse::<u64>()?, rest),
            None => (0, rest),
        };

        if !rest.is_empty() {
            bail!("trailing characters");
        }

        if block_offset >= height.subsidy() {
            bail!("invalid block offset");
        }

        Ok(height.starting_sat() + block_offset)
    }

    fn from_decimal(decimal: &str) -> Result<Self> {
        let (height, offset) = decimal
            .split_once('.')
            .ok_or_else(|| anyhow!("missing period"))?;
        let height = Height(height.parse()?);
        let offset = offset.parse::<u64>()?;

        if offset >= height.subsidy() {
            bail!("invalid block offset");
        }

        Ok(height.starting_sat() + offset)
    }

    fn from_percentile(percentile: &str) -> Result<Self> {
        if !percentile.ends_with('%') {
            bail!("invalid percentile: {}", percentile);
        }

        let percentile = percentile[..percentile.len() - 1].parse::<f64>()?;

        if percentile < 0.0 {
            bail!("invalid percentile: {}", percentile);
        }

        let last = Sat::LAST.n() as f64;

        let n = (percentile / 100.0 * last).round();

        if n > last {
            bail!("invalid percentile: {}", percentile);
        }

        #[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation)]
        Ok(Sat(n as u64))
    }
}

impl PartialEq<u64> for Sat {
    fn eq(&self, other: &u64) -> bool {
        self.0 == *other
    }
}

impl PartialOrd<u64> for Sat {
    fn partial_cmp(&self, other: &u64) -> Option<cmp::Ordering> {
        self.0.partial_cmp(other)
    }
}

impl Add<u64> for Sat {
    type Output = Self;

    fn add(self, other: u64) -> Sat {
        Sat(self.0 + other)
    }
}

impl AddAssign<u64> for Sat {
    fn add_assign(&mut self, other: u64) {
        *self = Sat(self.0 + other);
    }
}

impl FromStr for Sat {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        if s.chars().any(|c| c.is_ascii_lowercase()) {
            Self::from_name(s)
        } else if s.contains('°') {
            Self::from_degree(s)
        } else if s.contains('%') {
            Self::from_percentile(s)
        } else if s.contains('.') {
            Self::from_decimal(s)
        } else {
            let sat = Self(s.parse()?);
            if sat > Self::LAST {
                Err(anyhow!("invalid sat"))
            } else {
                Ok(sat)
            }
        }
    }
}
