use std::{fs, io, path::Path, str};

use anyhow::{bail, ensure, Context, Error};
use bdk_wallet::bitcoin::{
    blockdata::{
        opcodes,
        script::{self, PushBytesBuf},
    },
    hashes::Hash,
    Network, ScriptBuf, Txid, Witness,
};
use brotli::enc::{writer::CompressorWriter, BrotliEncoderParams};
use ciborium::Value;
use http::header::HeaderValue;
use io::{Cursor, Read, Write};
use lazy_static::lazy_static;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::convert::TryFrom;

use crate::ordinal::inscription::{envelope, inscription_id::InscriptionId, media::Media};

#[derive(Debug, PartialEq, Clone, Serialize, Deserialize, Eq, Default)]
pub struct Inscription {
    pub body: Option<Vec<u8>>,
    pub content_encoding: Option<Vec<u8>>,
    pub content_type: Option<Vec<u8>>,
    pub duplicate_field: bool,
    pub incomplete_field: bool,
    pub metadata: Option<Vec<u8>>,
    pub metaprotocol: Option<Vec<u8>>,
    pub parent: Option<Vec<u8>>,
    pub pointer: Option<Vec<u8>>,
    pub unrecognized_even_field: bool,
}

fn get_inscription_content_size_limit(network: &Network) -> Option<usize> {
    match network {
        Network::Bitcoin | Network::Regtest => None,
        Network::Signet | Network::Testnet | Network::Testnet4 => Some(1024),
        _ => unreachable!(),
    }
}

impl Inscription {
    #[cfg(test)]
    pub(crate) fn new(content_type: Option<Vec<u8>>, body: Option<Vec<u8>>) -> Self {
        Self {
            content_type,
            body,
            ..Default::default()
        }
    }

    pub(crate) fn from_bytes(
        network: Network,
        file: (String, Vec<u8>),
        parent: Option<InscriptionId>,
        pointer: Option<u64>,
        metaprotocol: Option<String>,
        metadata: Option<Vec<u8>>,
        compress: bool,
    ) -> Result<Self, Error> {
        let fp = Path::new(&file.0);
        let (content_type, compression_mode) = Media::content_type_for_path(fp, &file.1)?;

        let (body, content_encoding) = if compress {
            let mut compressed = Vec::new();

            {
                CompressorWriter::with_params(
                    &mut compressed,
                    file.1.len(),
                    &BrotliEncoderParams {
                        lgblock: 24,
                        lgwin: 24,
                        mode: compression_mode,
                        quality: 11,
                        size_hint: file.1.len(),
                        ..Default::default()
                    },
                )
                .write_all(&file.1)?;

                let mut decompressor =
                    brotli::Decompressor::new(compressed.as_slice(), compressed.len());

                let mut decompressed = Vec::new();

                decompressor.read_to_end(&mut decompressed)?;

                ensure!(decompressed == file.1, "decompression roundtrip failed");
            }

            if compressed.len() < file.1.len() {
                (compressed, Some("br".as_bytes().to_vec()))
            } else {
                (file.1, None)
            }
        } else {
            (file.1, None)
        };

        if let Some(limit) = get_inscription_content_size_limit(&network) {
            let len = body.len();
            if len > limit {
                bail!("content size of {len} bytes exceeds {limit} byte limit for {network} inscriptions");
            }
        }

        Ok(Self {
            body: Some(body),
            content_type: Some(content_type.into()),
            content_encoding,
            metadata,
            metaprotocol: metaprotocol.map(|metaprotocol| metaprotocol.into_bytes()),
            parent: parent.map(|id| id.parent_value()),
            pointer: pointer.map(Self::pointer_value),
            ..Default::default()
        })
    }

    pub(crate) fn from_file(
        network: Network,
        path: impl AsRef<Path>,
        parent: Option<InscriptionId>,
        pointer: Option<u64>,
        metaprotocol: Option<String>,
        metadata: Option<Vec<u8>>,
        compress: bool,
    ) -> Result<Self, Error> {
        let path = path.as_ref();

        let body =
            fs::read(path).with_context(|| format!("io error reading {}", path.display()))?;

        let (content_type, compression_mode) = Media::content_type_for_path(path, &[])?; // todo

        let (body, content_encoding) = if compress {
            let mut compressed = Vec::new();

            {
                CompressorWriter::with_params(
                    &mut compressed,
                    body.len(),
                    &BrotliEncoderParams {
                        lgblock: 24,
                        lgwin: 24,
                        mode: compression_mode,
                        quality: 11,
                        size_hint: body.len(),
                        ..Default::default()
                    },
                )
                .write_all(&body)?;

                let mut decompressor =
                    brotli::Decompressor::new(compressed.as_slice(), compressed.len());

                let mut decompressed = Vec::new();

                decompressor.read_to_end(&mut decompressed)?;

                ensure!(decompressed == body, "decompression roundtrip failed");
            }

            if compressed.len() < body.len() {
                (compressed, Some("br".as_bytes().to_vec()))
            } else {
                (body, None)
            }
        } else {
            (body, None)
        };

        if let Some(limit) = get_inscription_content_size_limit(&network) {
            let len = body.len();
            if len > limit {
                bail!("content size of {len} bytes exceeds {limit} byte limit for {network} inscriptions");
            }
        }

        Ok(Self {
            body: Some(body),
            content_type: Some(content_type.into()),
            content_encoding,
            metadata,
            metaprotocol: metaprotocol.map(|metaprotocol| metaprotocol.into_bytes()),
            parent: parent.map(|id| id.parent_value()),
            pointer: pointer.map(Self::pointer_value),
            ..Default::default()
        })
    }

    pub(crate) fn pointer_value(pointer: u64) -> Vec<u8> {
        let mut bytes = pointer.to_le_bytes().to_vec();

        while bytes.last().copied() == Some(0) {
            bytes.pop();
        }

        bytes
    }

    pub(crate) fn append_reveal_script_to_builder(
        &self,
        mut builder: script::Builder,
    ) -> script::Builder {
        builder = builder
            .push_opcode(opcodes::OP_FALSE)
            .push_opcode(opcodes::all::OP_IF)
            .push_slice(envelope::PROTOCOL_ID);

        if let Some(content_type) = self.content_type.clone() {
            builder = builder
                .push_slice(envelope::CONTENT_TYPE_TAG)
                .push_slice(PushBytesBuf::try_from(content_type).unwrap());
        }

        if let Some(content_encoding) = self.content_encoding.clone() {
            builder = builder
                .push_slice(envelope::CONTENT_ENCODING_TAG)
                .push_slice(PushBytesBuf::try_from(content_encoding).unwrap());
        }

        if let Some(protocol) = self.metaprotocol.clone() {
            builder = builder
                .push_slice(envelope::METAPROTOCOL_TAG)
                .push_slice(PushBytesBuf::try_from(protocol).unwrap());
        }

        if let Some(parent) = self.parent.clone() {
            builder = builder
                .push_slice(envelope::PARENT_TAG)
                .push_slice(PushBytesBuf::try_from(parent).unwrap());
        }

        if let Some(pointer) = self.pointer.clone() {
            builder = builder
                .push_slice(envelope::POINTER_TAG)
                .push_slice(PushBytesBuf::try_from(pointer).unwrap());
        }

        if let Some(metadata) = &self.metadata {
            for chunk in metadata.chunks(520) {
                builder = builder.push_slice(envelope::METADATA_TAG);
                builder = builder.push_slice(PushBytesBuf::try_from(chunk.to_vec()).unwrap());
            }
        }

        if let Some(body) = &self.body {
            builder = builder.push_slice(envelope::BODY_TAG);
            for chunk in body.chunks(520) {
                builder = builder.push_slice(PushBytesBuf::try_from(chunk.to_vec()).unwrap());
            }
        }

        builder.push_opcode(opcodes::all::OP_ENDIF)
    }

    #[cfg(test)]
    pub(crate) fn append_reveal_script(&self, builder: script::Builder) -> ScriptBuf {
        self.append_reveal_script_to_builder(builder).into_script()
    }

    pub(crate) fn append_batch_reveal_script_to_builder(
        inscriptions: &[Inscription],
        mut builder: script::Builder,
    ) -> script::Builder {
        for inscription in inscriptions {
            builder = inscription.append_reveal_script_to_builder(builder);
        }

        builder
    }

    pub(crate) fn append_batch_reveal_script(
        inscriptions: &[Inscription],
        builder: script::Builder,
    ) -> ScriptBuf {
        Inscription::append_batch_reveal_script_to_builder(inscriptions, builder).into_script()
    }

    pub(crate) fn media(&self) -> Media {
        if self.body.is_none() {
            return Media::Unknown;
        }

        let Some(content_type) = self.content_type() else {
            return Media::Unknown;
        };

        content_type.parse().unwrap_or(Media::Unknown)
    }

    pub(crate) fn body(&self) -> Option<&[u8]> {
        Some(self.body.as_ref()?)
    }

    pub(crate) fn into_body(self) -> Option<Vec<u8>> {
        self.body
    }

    pub(crate) fn content_length(&self) -> Option<usize> {
        Some(self.body()?.len())
    }

    pub(crate) fn content_type(&self) -> Option<&str> {
        str::from_utf8(self.content_type.as_ref()?).ok()
    }

    pub(crate) fn content_encoding(&self) -> Option<HeaderValue> {
        HeaderValue::from_str(str::from_utf8(self.content_encoding.as_ref()?).unwrap_or_default())
            .ok()
    }

    pub(crate) fn metadata(&self) -> Option<Value> {
        ciborium::from_reader(Cursor::new(self.metadata.as_ref()?)).ok()
    }

    pub(crate) fn metaprotocol(&self) -> Option<&str> {
        str::from_utf8(self.metaprotocol.as_ref()?).ok()
    }

    pub(crate) fn parent(&self) -> Option<InscriptionId> {
        let value = self.parent.as_ref()?;

        if value.len() < Txid::LEN {
            return None;
        }

        if value.len() > Txid::LEN + 4 {
            return None;
        }

        let (txid, index) = value.split_at(Txid::LEN);

        if let Some(last) = index.last() {
            // Accept fixed length encoding with 4 bytes (with potential trailing zeroes)
            // or variable length (no trailing zeroes)
            if index.len() != 4 && *last == 0 {
                return None;
            }
        }

        let txid = Txid::from_slice(txid).unwrap();

        let index = [
            index.first().copied().unwrap_or(0),
            index.get(1).copied().unwrap_or(0),
            index.get(2).copied().unwrap_or(0),
            index.get(3).copied().unwrap_or(0),
        ];

        let index = u32::from_le_bytes(index);

        Some(InscriptionId { txid, index })
    }

    pub(crate) fn pointer(&self) -> Option<u64> {
        let value = self.pointer.as_ref()?;

        if value.iter().skip(8).copied().any(|byte| byte != 0) {
            return None;
        }

        let pointer = [
            value.first().copied().unwrap_or(0),
            value.get(1).copied().unwrap_or(0),
            value.get(2).copied().unwrap_or(0),
            value.get(3).copied().unwrap_or(0),
            value.get(4).copied().unwrap_or(0),
            value.get(5).copied().unwrap_or(0),
            value.get(6).copied().unwrap_or(0),
            value.get(7).copied().unwrap_or(0),
        ];

        Some(u64::from_le_bytes(pointer))
    }

    #[cfg(test)]
    pub(crate) fn to_witness(&self) -> Witness {
        let builder = script::Builder::new();

        let script = self.append_reveal_script(builder);

        let mut witness = Witness::new();

        witness.push(script);
        witness.push([]);

        witness
    }

    pub(crate) fn hidden(&self) -> bool {
        lazy_static! {
            static ref CONTENT: Regex =
                Regex::new(r"^\s*/content/[[:xdigit:]]{64}i\d+\s*$").unwrap();
        }

        let Some(content_type) = self.content_type() else {
            return true;
        };

        if content_type.starts_with("text/html")
            && self
                .body()
                .and_then(|body| str::from_utf8(body).ok())
                .map(|body| CONTENT.is_match(body))
                .unwrap_or_default()
        {
            return true;
        }

        if self.metaprotocol.is_some() {
            return true;
        }

        if let Media::Code(_) | Media::Text | Media::Unknown = self.media() {
            return true;
        }

        false
    }
}
