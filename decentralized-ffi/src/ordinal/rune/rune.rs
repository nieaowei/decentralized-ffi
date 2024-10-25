use std::collections::{HashMap, VecDeque};
use std::convert::TryInto;
use std::sync::Arc;
use bdk_wallet::bitcoin::{
    opcodes,
};
use bdk_wallet::bitcoin::script::Instruction;
use crate::bitcoin::Script;
use crate::ordinal::rune::rune_id::RuneId;
use crate::ordinal::rune::varint;

#[derive(Copy, Clone, Debug)]
pub(super) enum Tag {
    Body = 0,
    Flags = 2,
    Rune = 4,
    Premine = 6,
    Cap = 8,
    Amount = 10,
    HeightStart = 12,
    HeightEnd = 14,
    OffsetStart = 16,
    OffsetEnd = 18,
    Mint = 20,
    Pointer = 22,
    #[allow(unused)]
    Cenotaph = 126,

    Divisibility = 1,
    Spacers = 3,
    Symbol = 5,
    #[allow(unused)]
    Nop = 127,
}

#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum RuneParseError {
    #[error("no OP_RETURN flag")]
    NoOpReturn,

    #[error("no OP_PUSHNUM_13 flag")]
    NoMagicNumber,

    #[error("no rune")]
    NoRune,

    #[error("decode payload error: {error_message}")]
    DecodePayload { error_message: String },

    #[error("u128 to u32 error")]
    U128Tou32,
}


#[derive(uniffi::Enum, Debug, Clone, PartialEq, Eq, Hash)]
pub enum Rune {
    Edicts { edicts: Vec<Edict> },
    Etching { rune_id: Arc<RuneId> },
    Nothing,
}

impl Rune {
    pub fn from_script(script: Arc<Script>) -> Result<Self, RuneParseError> {
        extract_rune_from_script(script)
    }
}


#[derive(uniffi::Record, Debug, Clone, PartialEq, Eq, Hash)]
pub struct Edict {
    pub id: Arc<RuneId>,
    pub amount: u64,
    pub output: u32,
}


impl Tag {
    fn take<const N: usize, T>(
        self,
        fields: &mut HashMap<u128, VecDeque<u128>>,
        with: impl Fn([u128; N]) -> Option<T>,
    ) -> Option<T> {
        let field = fields.get_mut(&self.into())?;

        let mut values: [u128; N] = [0; N];

        for (i, v) in values.iter_mut().enumerate() {
            *v = *field.get(i)?;
        }

        let value = with(values)?;

        field.drain(0..N);

        if field.is_empty() {
            fields.remove(&self.into()).unwrap();
        }

        Some(value)
    }

    // op_return magic_number op_push_bytes 20 block 20 tx
    fn encode<const N: usize>(self, values: [u128; N], payload: &mut Vec<u8>) {
        for value in values {
            varint::encode_to_vec(self.into(), payload);
            varint::encode_to_vec(value, payload);
        }
    }

    fn encode_option<T: Into<u128>>(self, value: Option<T>, payload: &mut Vec<u8>) {
        if let Some(value) = value {
            self.encode([value.into()], payload)
        }
    }
}

impl From<Tag> for u128 {
    fn from(tag: Tag) -> Self {
        tag as u128
    }
}

impl PartialEq<u128> for Tag {
    fn eq(&self, other: &u128) -> bool {
        u128::from(*self) == *other
    }
}

fn integers(payload: &[u8]) -> Result<Vec<u128>, RuneParseError> {
    let mut integers = Vec::new();
    let mut i = 0;

    while i < payload.len() {
        let (integer, length) = varint::decode(&payload[i..])
            .map_err(|err| RuneParseError::DecodePayload { error_message: err.to_string() })?;
        integers.push(integer);
        i += length;
    }

    Ok(integers)
}

#[uniffi::export]
pub fn extract_rune_from_script(script: Arc<Script>) -> Result<Rune, RuneParseError> {
    let mut instructions = script.0.instructions();
    if instructions.next() != Some(Ok(Instruction::Op(opcodes::all::OP_RETURN))) {
        return Err(RuneParseError::NoOpReturn);
    }

    if instructions.next() != Some(Ok(Instruction::Op(opcodes::all::OP_PUSHNUM_13))) {
        return Err(RuneParseError::NoMagicNumber);
    }
    // construct the payload by concatenating remaining data pushes
    let mut payload = Vec::new();

    for result in instructions {
        match result {
            Ok(Instruction::PushBytes(push)) => {
                payload.extend_from_slice(push.as_bytes());
            }
            Ok(Instruction::Op(_)) => {
                continue;
            }
            Err(_) => {
                continue;
            }
        }
    }

    let Ok(integers) = integers(&payload) else {
        return Err(RuneParseError::NoRune)
    };
    let mut edicts = Vec::new();
    let mut fields = HashMap::<u128, VecDeque<u128>>::new();

    for i in (0..integers.len()).step_by(2) {
        let tag = integers[i];

        if Tag::Body == tag {
            let mut id = RuneId::default();
            for chunk in integers[i + 1..].chunks(4) {
                if chunk.len() != 4 {
                    // flaws |= Flaw::TrailingIntegers.flag();
                    break;
                }

                let Some(next) = id.next(chunk[0], chunk[1]) else {
                    // flaws |= Flaw::EdictRuneId.flag();
                    break;
                };

                let edict = Edict {
                    id: Arc::new(next.clone()),
                    amount: chunk[2] as u64,
                    output: chunk[3].try_into().map_err(|err| RuneParseError::U128Tou32)?,
                };

                id = next.clone();
                edicts.push(edict)
            }
            break;
        }

        let Some(&value) = integers.get(i + 1) else {
            break;
        };

        fields.entry(tag).or_default().push_back(value);
    }
    if !edicts.is_empty() {
        return Ok(Rune::Edicts { edicts });
    }

    if let Some(mint) = Tag::Mint.take(&mut fields, |[block, tx]| {
        RuneId::new(block.try_into().ok()?, tx.try_into().ok()?).ok()
    }) {
        return Ok(Rune::Etching { rune_id: Arc::new(mint) });
    }

    Ok(Rune::Nothing)
}

//
// pub(crate) fn extract_rune_mint(script_buf: Script) -> Result<Option<RuneId>, RuneParseError> {
//     let mut instructions = script_buf.0.instructions();
//     if instructions.next() != Some(Ok(Instruction::Op(opcodes::all::OP_RETURN))) {
//         return Err(RuneParseError::NoOpReturn);
//     }
//
//     if instructions.next() != Some(Ok(Instruction::Op(opcodes::all::OP_PUSHNUM_13))) {
//         return Err(RuneParseError::NoMagicNumber);
//     }
//     // construct the payload by concatenating remaining data pushes
//     let mut payload = Vec::new();
//
//     for result in instructions {
//         match result {
//             Ok(Instruction::PushBytes(push)) => {
//                 payload.extend_from_slice(push.as_bytes());
//             }
//             Ok(Instruction::Op(_)) => {
//                 continue;
//             }
//             Err(_) => {
//                 continue;
//             }
//         }
//     }
//
//     let Ok(integers) = integers(&payload) else {
//         return Err(RuneParseError::NoRune)
//     };
//     let mut edicts = Vec::new();
//     let mut fields = HashMap::<u128, VecDeque<u128>>::new();
//
//     for i in (0..integers.len()).step_by(2) {
//         let tag = integers[i];
//
//         if Tag::Body == tag {
//             let mut id = RuneId::default();
//             for chunk in integers[i + 1..].chunks(4) {
//                 if chunk.len() != 4 {
//                     // flaws |= Flaw::TrailingIntegers.flag();
//                     break;
//                 }
//
//                 let Some(next) = id.next(chunk[0], chunk[1]) else {
//                     // flaws |= Flaw::EdictRuneId.flag();
//                     break;
//                 };
//
//                 let edict = Edict {
//                     id: next,
//                     amount: chunk[2] as u64,
//                     output: chunk[3].try_into().map_err(|err| RuneParseError::U128Tou32)?,
//                 };
//
//                 id = next;
//                 edicts.push(edict)
//             }
//             break;
//         }
//
//         let Some(&value) = integers.get(i + 1) else {
//             break;
//         };
//
//         fields.entry(tag).or_default().push_back(value);
//     }
//
//     let mint = Tag::Mint.take(&mut fields, |[block, tx]| {
//         RuneId::new(block.try_into().ok()?, tx.try_into().ok()?)
//     });
//
//     Ok(mint)
// }
//
// pub(crate) fn build_edict_script_buf(mut edicts: Vec<Edict>) -> ScriptBuf {
//     let mut payload = Vec::new();
//     varint::encode_to_vec(Tag::Body.into(), &mut payload);
//     edicts.sort_by_key(|edict| edict.id);
//     let mut previous = RuneId::default();
//     for edict in edicts {
//         let (block, tx) = previous.delta(edict.id).unwrap();
//         varint::encode_to_vec(block, &mut payload);
//         varint::encode_to_vec(tx, &mut payload);
//         varint::encode_to_vec(edict.amount as u128, &mut payload);
//         varint::encode_to_vec(edict.output.into(), &mut payload);
//         previous = edict.id;
//     }
//
//     let mut builder = script::Builder::new()
//         .push_opcode(opcodes::all::OP_RETURN)
//         .push_opcode(opcodes::all::OP_PUSHNUM_13);
//
//     for chunk in payload.chunks(MAX_SCRIPT_ELEMENT_SIZE) {
//         let push: &script::PushBytes = chunk.try_into().unwrap();
//         builder = builder.push_slice(push);
//     }
//
//     builder.into_script()
// }
