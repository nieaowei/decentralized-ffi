use serde::{Deserialize, Serialize};

#[derive(PartialEq, Debug, Copy, Clone, Serialize, Deserialize, Default)]
pub(crate) enum Mode {
    #[serde(rename = "same-sat")]
    SameSat,
    #[default]
    #[serde(rename = "separate-outputs")]
    SeparateOutputs,
    #[serde(rename = "shared-output")]
    SharedOutput,
}
