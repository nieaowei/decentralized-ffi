use std::io;
use bdk_wallet::serde_json;
use serde::Serialize;

pub(crate) trait Output: Send {
    fn print_json(&self);
}

impl<T> Output for T
where
    T: Serialize + Send,
{
    fn print_json(&self) {
        serde_json::to_writer_pretty(io::stdout(), self).ok();
        println!();
    }
}

pub const CYCLE_EPOCHS: u32 = 6;

pub const COIN_VALUE: u64 = 100_000_000;
