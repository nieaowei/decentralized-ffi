use std::convert::TryInto;
use std::iter::Peekable;

use bdk_wallet::bitcoin::blockdata::{
    opcodes,
    script::{
        self,
        Instruction::{self, Op, PushBytes},
        Instructions,
    },
};

use super::*;

pub(crate) const PROTOCOL_ID: [u8; 3] = *b"ord";

pub(crate) const BODY_TAG: [u8; 0] = [];
pub(crate) const CONTENT_TYPE_TAG: [u8; 1] = [1];
pub(crate) const POINTER_TAG: [u8; 1] = [2];
pub(crate) const PARENT_TAG: [u8; 1] = [3];
pub(crate) const METADATA_TAG: [u8; 1] = [5];
pub(crate) const METAPROTOCOL_TAG: [u8; 1] = [7];
pub(crate) const CONTENT_ENCODING_TAG: [u8; 1] = [9];

type Result<T> = std::result::Result<T, script::Error>;
type RawEnvelope = Envelope<Vec<Vec<u8>>>;
pub(crate) type ParsedEnvelope = Envelope<Inscription>;

#[derive(Debug, Default, PartialEq, Clone)]
pub(crate) struct Envelope<T> {
    pub(crate) input: u32,
    pub(crate) offset: u32,
    pub(crate) payload: T,
    pub(crate) pushnum: bool,
    pub(crate) stutter: bool,
}

fn remove_field(fields: &mut BTreeMap<&[u8], Vec<&[u8]>>, field: &[u8]) -> Option<Vec<u8>> {
    let values = fields.get_mut(field)?;

    if values.is_empty() {
        None
    } else {
        let value = values.remove(0).to_vec();

        if values.is_empty() {
            fields.remove(field);
        }

        Some(value)
    }
}

fn remove_and_concatenate_field(
    fields: &mut BTreeMap<&[u8], Vec<&[u8]>>,
    field: &[u8],
) -> Option<Vec<u8>> {
    let value = fields.remove(field)?;

    if value.is_empty() {
        None
    } else {
        Some(value.into_iter().flatten().cloned().collect())
    }
}

impl From<RawEnvelope> for ParsedEnvelope {
    fn from(envelope: RawEnvelope) -> Self {
        let body = envelope
            .payload
            .iter()
            .enumerate()
            .position(|(i, push)| i % 2 == 0 && push.is_empty());

        let mut fields: BTreeMap<&[u8], Vec<&[u8]>> = BTreeMap::new();

        let mut incomplete_field = false;

        for item in envelope.payload[..body.unwrap_or(envelope.payload.len())].chunks(2) {
            match item {
                [key, value] => fields.entry(key).or_default().push(value),
                _ => incomplete_field = true,
            }
        }

        let duplicate_field = fields.iter().any(|(_key, values)| values.len() > 1);

        let content_encoding = remove_field(&mut fields, &CONTENT_ENCODING_TAG);
        let content_type = remove_field(&mut fields, &CONTENT_TYPE_TAG);
        let metadata = remove_and_concatenate_field(&mut fields, &METADATA_TAG);
        let metaprotocol = remove_field(&mut fields, &METAPROTOCOL_TAG);
        let parent = remove_field(&mut fields, &PARENT_TAG);
        let pointer = remove_field(&mut fields, &POINTER_TAG);

        let unrecognized_even_field = fields
            .keys()
            .any(|tag| tag.first().map(|lsb| lsb % 2 == 0).unwrap_or_default());

        Self {
            payload: Inscription {
                body: body.map(|i| {
                    envelope.payload[i + 1..]
                        .iter()
                        .flatten()
                        .cloned()
                        .collect()
                }),
                content_encoding,
                content_type,
                duplicate_field,
                incomplete_field,
                metadata,
                metaprotocol,
                parent,
                pointer,
                unrecognized_even_field,
            },
            input: envelope.input,
            offset: envelope.offset,
            pushnum: envelope.pushnum,
            stutter: envelope.stutter,
        }
    }
}

impl ParsedEnvelope {
    pub(crate) fn from_transaction(transaction: &Transaction) -> Vec<Self> {
        RawEnvelope::from_transaction(transaction)
            .into_iter()
            .map(|envelope| envelope.into())
            .collect()
    }
}

impl RawEnvelope {
    pub(crate) fn from_transaction(transaction: &Transaction) -> Vec<Self> {
        let mut envelopes = Vec::new();

        for (i, input) in transaction.input.iter().enumerate() {
            if let Some(tapscript) = input.witness.taproot_leaf_script() {
                if let Ok(input_envelopes) = Self::from_tapscript(tapscript.script, i) {
                    envelopes.extend(input_envelopes);
                }
            }
        }

        envelopes
    }

    fn from_tapscript(tapscript: &Script, input: usize) -> Result<Vec<Self>> {
        let mut envelopes = Vec::new();

        let mut instructions = tapscript.instructions().peekable();

        let mut stuttered = false;
        while let Some(instruction) = instructions.next().transpose()? {
            if instruction == PushBytes((&[]).into()) {
                let (stutter, envelope) =
                    Self::from_instructions(&mut instructions, input, envelopes.len(), stuttered)?;
                if let Some(envelope) = envelope {
                    envelopes.push(envelope);
                } else {
                    stuttered = stutter;
                }
            }
        }

        Ok(envelopes)
    }

    fn accept(instructions: &mut Peekable<Instructions>, instruction: Instruction) -> Result<bool> {
        if instructions.peek() == Some(&Ok(instruction)) {
            instructions.next().transpose()?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    fn from_instructions(
        instructions: &mut Peekable<Instructions>,
        input: usize,
        offset: usize,
        stutter: bool,
    ) -> Result<(bool, Option<Self>)> {
        if !Self::accept(instructions, Op(opcodes::all::OP_IF))? {
            let stutter = instructions.peek() == Some(&Ok(PushBytes((&[]).into())));
            return Ok((stutter, None));
        }

        if !Self::accept(instructions, PushBytes((&PROTOCOL_ID).into()))? {
            let stutter = instructions.peek() == Some(&Ok(PushBytes((&[]).into())));
            return Ok((stutter, None));
        }

        let mut pushnum = false;

        let mut payload = Vec::new();

        loop {
            match instructions.next().transpose()? {
                None => return Ok((false, None)),
                Some(Op(opcodes::all::OP_ENDIF)) => {
                    return Ok((
                        false,
                        Some(Envelope {
                            input: input.try_into().unwrap(),
                            offset: offset.try_into().unwrap(),
                            payload,
                            pushnum,
                            stutter,
                        }),
                    ));
                }
                Some(Op(opcodes::all::OP_PUSHNUM_NEG1)) => {
                    pushnum = true;
                    payload.push(vec![0x81]);
                }
                Some(Op(opcodes::all::OP_PUSHNUM_1)) => {
                    pushnum = true;
                    payload.push(vec![1]);
                }
                Some(Op(opcodes::all::OP_PUSHNUM_2)) => {
                    pushnum = true;
                    payload.push(vec![2]);
                }
                Some(Op(opcodes::all::OP_PUSHNUM_3)) => {
                    pushnum = true;
                    payload.push(vec![3]);
                }
                Some(Op(opcodes::all::OP_PUSHNUM_4)) => {
                    pushnum = true;
                    payload.push(vec![4]);
                }
                Some(Op(opcodes::all::OP_PUSHNUM_5)) => {
                    pushnum = true;
                    payload.push(vec![5]);
                }
                Some(Op(opcodes::all::OP_PUSHNUM_6)) => {
                    pushnum = true;
                    payload.push(vec![6]);
                }
                Some(Op(opcodes::all::OP_PUSHNUM_7)) => {
                    pushnum = true;
                    payload.push(vec![7]);
                }
                Some(Op(opcodes::all::OP_PUSHNUM_8)) => {
                    pushnum = true;
                    payload.push(vec![8]);
                }
                Some(Op(opcodes::all::OP_PUSHNUM_9)) => {
                    pushnum = true;
                    payload.push(vec![9]);
                }
                Some(Op(opcodes::all::OP_PUSHNUM_10)) => {
                    pushnum = true;
                    payload.push(vec![10]);
                }
                Some(Op(opcodes::all::OP_PUSHNUM_11)) => {
                    pushnum = true;
                    payload.push(vec![11]);
                }
                Some(Op(opcodes::all::OP_PUSHNUM_12)) => {
                    pushnum = true;
                    payload.push(vec![12]);
                }
                Some(Op(opcodes::all::OP_PUSHNUM_13)) => {
                    pushnum = true;
                    payload.push(vec![13]);
                }
                Some(Op(opcodes::all::OP_PUSHNUM_14)) => {
                    pushnum = true;
                    payload.push(vec![14]);
                }
                Some(Op(opcodes::all::OP_PUSHNUM_15)) => {
                    pushnum = true;
                    payload.push(vec![15]);
                }
                Some(Op(opcodes::all::OP_PUSHNUM_16)) => {
                    pushnum = true;
                    payload.push(vec![16]);
                }
                Some(PushBytes(push)) => {
                    payload.push(push.as_bytes().to_vec());
                }
                Some(_) => return Ok((false, None)),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ordinal::inscription::common::Output;
    //
    // #[test]
    // fn test_witness() {
    //     let a = hex::decode(b"ce2f92f30a46030a9f5090dac22e436895714f2fce018af774454d7ad96abd6416ca471d8af97adcd5df763d67e6554c79b844462205f2866de2746bdcdfe566").unwrap();
    //     let b = hex::decode(b"206117b470117e585a194e437a543309dbfe7b90dc25ce4e979856ad4f8c3187ddac0063036f7264010117746578742f68746d6c3b636861727365743d7574662d38004d08023c6d657461766572736520703d276272632d34323027207372633d272f636f6e74656e742f6464303333316531643134366164633834333538343437643165343065346337393631353739396130383532333830386136353563313534666338363461366569302720737263747970653d27696d6167652f706e67272069737368656574616e696d6174653d2774727565272073686565746c61796f75743d275b332c335d273e3c616e696d61746520206e616d653d276927202072616e67653d275b302c325d2720206475726174696f6e3d2731272f3e3c616e696d61746520206e616d653d276c6927202072616e67653d275b332c355d2720206475726174696f6e3d2731272f3e3c616e696d61746520206e616d653d276d27202072616e67653d275b362c385d2720206475726174696f6e3d2731272f3e3c2f6d65746176657273653e0a3c6269746d61702d6578706c6f7265722063617465676f72793d276f776e65722720747970653d27617661746172272075736561626c653d27312720636f6e737472756374696f6e3d2766616c7365272073686170653d27636972636c652720736861706572616e67653d275b302e312c302e315d27207069766f743d275b302e352c302e355d272073697a653d275b302e322c302e325d27206865696768743d27302e31272073706565643d2733273e3c616e696d6174696f6e206e616d654dc3013d2769646c6527207372636e616d653d276927207065726672616d6573706565643d273127206c6f6f703d2774727565272f3e3c616e696d6174696f6e206e616d653d2769646c652d726967687427207372636e616d653d276927207065726672616d6573706565643d273127206c6f6f703d2774727565272f3e3c616e696d6174696f6e206e616d653d2769646c652d6c65667427207372636e616d653d276c6927207065726672616d6573706565643d273127206c6f6f703d2774727565272f3e3c616e696d6174696f6e206e616d653d276d6f76652d726967687427207372636e616d653d276d27207065726672616d6573706565643d27302e3227206c6f6f703d2774727565272f3e3c2f6269746d61702d6578706c6f7265723e0a3c6d657461766572736570726576696577206261636b67726f756e64636f6c6f723d2723663263653836273e3c2f6d6574617665727365707265766965773e0a3c736372697074207372633d272f636f6e74656e742f356431626337393463633861376532633063316231303466356331306635333139623638373936616335376562613032666533396231303736313333343139326930273e3c2f7363726970743e68").unwrap();
    //     let c = hex::decode(b"c0684f8f660d051429163cc4ac963a206a80c0cb8ef450623a005fd77786ecaef7")
    //         .unwrap();
    //
    //     let w = Witness::from(vec![a, b, c]);
    //
    //     let tx = Transaction {
    //         version: 2,
    //         lock_time: LockTime::ZERO,
    //         input: vec![TxIn {
    //             previous_output: OutPoint::new(
    //                 Txid::from_str(
    //                     "18265e43dd304e1f3efbf6208d67e2074d3522f75e28cc5f3c31f06796c856b5",
    //                 )
    //                 .unwrap(),
    //                 0,
    //             ),
    //             script_sig: ScriptBuf::new(),
    //             sequence: Sequence::from_consensus(4294967293),
    //             witness: w,
    //         }],
    //         output: vec![],
    //     };
    //     let en = ParsedEnvelope::from_transaction(&tx);
    //
    //     for envelope in en {
    //         println!("{}", envelope.payload.metaprotocol().unwrap());
    //         // envelope.payload.print_json();
    //     }
    // }
}
