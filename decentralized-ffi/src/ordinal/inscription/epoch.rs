use std::convert::TryFrom;
use bdk_wallet::bitcoin::constants::{ SUBSIDY_HALVING_INTERVAL};
use derive_more::Display;
use serde::Serialize;

use crate::ordinal::inscription::{height::Height, sat::Sat};
use crate::ordinal::inscription::common::COIN_VALUE;

#[derive(Copy, Clone, Eq, PartialEq, Debug, Display, Serialize, PartialOrd)]
pub(crate) struct Epoch(pub(crate) u32);

impl Epoch {
    pub(crate) const STARTING_SATS: [Sat; 34] = [
        Sat(0),
        Sat(1050000000000000),
        Sat(1575000000000000),
        Sat(1837500000000000),
        Sat(1968750000000000),
        Sat(2034375000000000),
        Sat(2067187500000000),
        Sat(2083593750000000),
        Sat(2091796875000000),
        Sat(2095898437500000),
        Sat(2097949218750000),
        Sat(2098974609270000),
        Sat(2099487304530000),
        Sat(2099743652160000),
        Sat(2099871825870000),
        Sat(2099935912620000),
        Sat(2099967955890000),
        Sat(2099983977420000),
        Sat(2099991988080000),
        Sat(2099995993410000),
        Sat(2099997995970000),
        Sat(2099998997250000),
        Sat(2099999497890000),
        Sat(2099999748210000),
        Sat(2099999873370000),
        Sat(2099999935950000),
        Sat(2099999967240000),
        Sat(2099999982780000),
        Sat(2099999990550000),
        Sat(2099999994330000),
        Sat(2099999996220000),
        Sat(2099999997060000),
        Sat(2099999997480000),
        Sat(Sat::SUPPLY),
    ];
    pub(crate) const FIRST_POST_SUBSIDY: Epoch = Self(33);

    pub(crate) fn subsidy(self) -> u64 {
        if self < Self::FIRST_POST_SUBSIDY {
            (50 * COIN_VALUE) >> self.0
        } else {
            0
        }
    }

    pub(crate) fn starting_sat(self) -> Sat {
        *Self::STARTING_SATS
            .get(usize::try_from(self.0).unwrap())
            .unwrap_or_else(|| Self::STARTING_SATS.last().unwrap())
    }

    pub(crate) fn starting_height(self) -> Height {
        Height(self.0 * SUBSIDY_HALVING_INTERVAL)
    }
}

impl PartialEq<u32> for Epoch {
    fn eq(&self, other: &u32) -> bool {
        self.0 == *other
    }
}

impl From<Sat> for Epoch {
    fn from(sat: Sat) -> Self {
        if sat < Self::STARTING_SATS[1] {
            Epoch(0)
        } else if sat < Self::STARTING_SATS[2] {
            Epoch(1)
        } else if sat < Self::STARTING_SATS[3] {
            Epoch(2)
        } else if sat < Self::STARTING_SATS[4] {
            Epoch(3)
        } else if sat < Self::STARTING_SATS[5] {
            Epoch(4)
        } else if sat < Self::STARTING_SATS[6] {
            Epoch(5)
        } else if sat < Self::STARTING_SATS[7] {
            Epoch(6)
        } else if sat < Self::STARTING_SATS[8] {
            Epoch(7)
        } else if sat < Self::STARTING_SATS[9] {
            Epoch(8)
        } else if sat < Self::STARTING_SATS[10] {
            Epoch(9)
        } else if sat < Self::STARTING_SATS[11] {
            Epoch(10)
        } else if sat < Self::STARTING_SATS[12] {
            Epoch(11)
        } else if sat < Self::STARTING_SATS[13] {
            Epoch(12)
        } else if sat < Self::STARTING_SATS[14] {
            Epoch(13)
        } else if sat < Self::STARTING_SATS[15] {
            Epoch(14)
        } else if sat < Self::STARTING_SATS[16] {
            Epoch(15)
        } else if sat < Self::STARTING_SATS[17] {
            Epoch(16)
        } else if sat < Self::STARTING_SATS[18] {
            Epoch(17)
        } else if sat < Self::STARTING_SATS[19] {
            Epoch(18)
        } else if sat < Self::STARTING_SATS[20] {
            Epoch(19)
        } else if sat < Self::STARTING_SATS[21] {
            Epoch(20)
        } else if sat < Self::STARTING_SATS[22] {
            Epoch(21)
        } else if sat < Self::STARTING_SATS[23] {
            Epoch(22)
        } else if sat < Self::STARTING_SATS[24] {
            Epoch(23)
        } else if sat < Self::STARTING_SATS[25] {
            Epoch(24)
        } else if sat < Self::STARTING_SATS[26] {
            Epoch(25)
        } else if sat < Self::STARTING_SATS[27] {
            Epoch(26)
        } else if sat < Self::STARTING_SATS[28] {
            Epoch(27)
        } else if sat < Self::STARTING_SATS[29] {
            Epoch(28)
        } else if sat < Self::STARTING_SATS[30] {
            Epoch(29)
        } else if sat < Self::STARTING_SATS[31] {
            Epoch(30)
        } else if sat < Self::STARTING_SATS[32] {
            Epoch(31)
        } else if sat < Self::STARTING_SATS[33] {
            Epoch(32)
        } else {
            Epoch(33)
        }
    }
}

impl From<Height> for Epoch {
    fn from(height: Height) -> Self {
        Self(height.0 / SUBSIDY_HALVING_INTERVAL)
    }
}
