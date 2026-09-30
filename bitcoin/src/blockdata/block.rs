// SPDX-License-Identifier: CC0-1.0

//! Bitcoin blocks.
//!
//! A block is a bundle of transactions with a proof-of-work attached,
//! which commits to an earlier block to form the blockchain. This
//! module describes structures and functions needed to describe
//! these blocks and the blockchain.
//!

use core::convert::Infallible;
use core::fmt;

#[cfg(feature = "arbitrary")]
use actual_arbitrary::{self as arbitrary, Arbitrary, Unstructured};
#[cfg(feature = "encoding")]
use encoding::{
    ArrayDecoder, CompactSizeEncoder, Decoder2, Decoder6, Encoder2, SliceEncoder, VecDecoder,
};
use hashes::{sha256, sha256d, Hash, HashEngine};
use io::{Read, Write};

use super::Weight;
use crate::blockdata::script;
use crate::blockdata::transaction::{Transaction, Txid, Wtxid};
use crate::consensus::{encode, Decodable, Encodable, Params};
#[cfg(feature = "encoding")]
use crate::internal_macros::write_err;
use crate::internal_macros::{impl_consensus_encoding, impl_hashencode};
use crate::pow::{CompactTarget, Target, Work};
#[cfg(feature = "encoding")]
use crate::pow::{CompactTargetDecoder, CompactTargetDecoderError};
use crate::prelude::*;
use crate::{merkle_tree, VarInt};

hashes::hash_newtype! {
    /// A bitcoin block hash.
    pub struct BlockHash(sha256d::Hash);
    /// A hash of the Merkle tree branch or root for transactions.
    pub struct TxMerkleNode(sha256d::Hash);
    /// A hash corresponding to the Merkle tree root for witness data.
    pub struct WitnessMerkleNode(sha256d::Hash);
    /// A hash corresponding to the witness structure commitment in the coinbase transaction.
    pub struct WitnessCommitment(sha256d::Hash);
}
impl_hashencode!(BlockHash);
impl_hashencode!(TxMerkleNode);
impl_hashencode!(WitnessMerkleNode);

#[cfg(feature = "encoding")]
impl encoding::Encode for BlockHash {
    type Encoder<'e> = BlockHashEncoder<'e>;
    #[inline]
    fn encoder(&self) -> Self::Encoder<'_> {
        BlockHashEncoder::new(encoding::ArrayRefEncoder::without_length_prefix(
            self.as_byte_array(),
        ))
    }
}

#[cfg(feature = "encoding")]
impl encoding::Decode for BlockHash {
    type Decoder = BlockHashDecoder;
}

#[cfg(feature = "encoding")]
encoding::encoder_newtype_exact! {
    /// The encoder for the [`BlockHash`] type.
    #[derive(Debug, Clone)]
    pub struct BlockHashEncoder<'e>(encoding::ArrayRefEncoder<'e, 32>);
}

#[cfg(feature = "encoding")]
crate::decoder_newtype! {
    /// The decoder for the [`BlockHash`] type.
    #[derive(Debug, Clone)]
    pub struct BlockHashDecoder(encoding::ArrayDecoder<32>);

    /// Constructs a new [`BlockHash`] decoder.
    pub const fn new() -> Self { Self(encoding::ArrayDecoder::new()) }

    fn end(result: Result<[u8; 32], encoding::UnexpectedEofError>) -> Result<BlockHash, BlockHashDecoderError> {
        let bytes = result.map_err(BlockHashDecoderError)?;
        Ok(BlockHash::from_byte_array(bytes))
    }
}

/// An error consensus decoding a `BlockHash`.
#[cfg(feature = "encoding")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockHashDecoderError(pub(crate) encoding::UnexpectedEofError);

#[cfg(feature = "encoding")]
impl From<Infallible> for BlockHashDecoderError {
    fn from(never: Infallible) -> Self { match never {} }
}

#[cfg(feature = "encoding")]
impl fmt::Display for BlockHashDecoderError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write_err!(f, "block hash decoder error"; self.0)
    }
}

#[cfg(all(feature = "encoding", feature = "std"))]
impl std::error::Error for BlockHashDecoderError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> { Some(&self.0) }
}

impl From<Txid> for TxMerkleNode {
    fn from(txid: Txid) -> Self { Self::from_byte_array(txid.to_byte_array()) }
}

impl From<Wtxid> for WitnessMerkleNode {
    fn from(wtxid: Wtxid) -> Self { Self::from_byte_array(wtxid.to_byte_array()) }
}

#[cfg(feature = "encoding")]
impl encoding::Encode for TxMerkleNode {
    type Encoder<'e> = TxMerkleNodeEncoder<'e>;
    #[inline]
    fn encoder(&self) -> Self::Encoder<'_> {
        TxMerkleNodeEncoder::new(encoding::ArrayRefEncoder::without_length_prefix(
            self.as_byte_array(),
        ))
    }
}

#[cfg(feature = "encoding")]
impl encoding::Decode for TxMerkleNode {
    type Decoder = TxMerkleNodeDecoder;
}

#[cfg(feature = "encoding")]
encoding::encoder_newtype_exact! {
    /// The encoder for the [`TxMerkleNode`] type.
    #[derive(Debug, Clone)]
    pub struct TxMerkleNodeEncoder<'e>(encoding::ArrayRefEncoder<'e, 32>);
}

#[cfg(feature = "encoding")]
crate::decoder_newtype! {
    /// The decoder for the [`TxMerkleNode`] type.
    #[derive(Debug, Clone)]
    pub struct TxMerkleNodeDecoder(encoding::ArrayDecoder<32>);

    /// Constructs a new [`TxMerkleNode`] decoder.
    pub const fn new() -> Self { Self(encoding::ArrayDecoder::new()) }

    fn end(result: Result<[u8; 32], encoding::UnexpectedEofError>) -> Result<TxMerkleNode, TxMerkleNodeDecoderError> {
        let bytes = result.map_err(TxMerkleNodeDecoderError)?;
        Ok(TxMerkleNode::from_byte_array(bytes))
    }
}

/// An error consensus decoding an `TxMerkleNode`.
#[cfg(feature = "encoding")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxMerkleNodeDecoderError(pub(crate) encoding::UnexpectedEofError);

#[cfg(feature = "encoding")]
impl From<Infallible> for TxMerkleNodeDecoderError {
    fn from(never: Infallible) -> Self { match never {} }
}

#[cfg(feature = "encoding")]
impl fmt::Display for TxMerkleNodeDecoderError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write_err!(f, "tx merkle node decoder error"; self.0)
    }
}

#[cfg(all(feature = "encoding", feature = "std"))]
impl std::error::Error for TxMerkleNodeDecoderError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> { Some(&self.0) }
}

#[cfg(feature = "encoding")]
impl encoding::Encode for WitnessMerkleNode {
    type Encoder<'e> = WitnessMerkleNodeEncoder<'e>;
    #[inline]
    fn encoder(&self) -> Self::Encoder<'_> {
        WitnessMerkleNodeEncoder::new(encoding::ArrayRefEncoder::without_length_prefix(
            self.as_byte_array(),
        ))
    }
}

#[cfg(feature = "encoding")]
impl encoding::Decode for WitnessMerkleNode {
    type Decoder = WitnessMerkleNodeDecoder;
}

#[cfg(feature = "encoding")]
encoding::encoder_newtype_exact! {
    /// The encoder for the [`WitnessMerkleNode`] type.
    #[derive(Debug, Clone)]
    pub struct WitnessMerkleNodeEncoder<'e>(encoding::ArrayRefEncoder<'e, 32>);
}

#[cfg(feature = "encoding")]
crate::decoder_newtype! {
    /// The decoder for the [`WitnessMerkleNode`] type.
    #[derive(Debug, Clone)]
    pub struct WitnessMerkleNodeDecoder(encoding::ArrayDecoder<32>);

    /// Constructs a new [`WitnessMerkleNode`] decoder.
    pub const fn new() -> Self { Self(encoding::ArrayDecoder::new()) }

    fn end(result: Result<[u8; 32], encoding::UnexpectedEofError>) -> Result<WitnessMerkleNode, WitnessMerkleNodeDecoderError> {
        let bytes = result.map_err(WitnessMerkleNodeDecoderError)?;
        Ok(WitnessMerkleNode::from_byte_array(bytes))
    }
}

/// An error consensus decoding an `WitnessMerkleNode`.
#[cfg(feature = "encoding")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WitnessMerkleNodeDecoderError(pub(crate) encoding::UnexpectedEofError);

#[cfg(feature = "encoding")]
impl From<Infallible> for WitnessMerkleNodeDecoderError {
    fn from(never: Infallible) -> Self { match never {} }
}

#[cfg(feature = "encoding")]
impl fmt::Display for WitnessMerkleNodeDecoderError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write_err!(f, "witness merkle node decoder error"; self.0)
    }
}

#[cfg(all(feature = "encoding", feature = "std"))]
impl std::error::Error for WitnessMerkleNodeDecoderError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> { Some(&self.0) }
}

/// Bitcoin block header.
///
/// Contains all the block's information except the actual transactions, but
/// including a root of a [merkle tree] committing to all transactions in the block.
///
/// [merkle tree]: https://en.wikipedia.org/wiki/Merkle_tree
///
/// ### Bitcoin Core References
///
/// * [CBlockHeader definition](https://github.com/bitcoin/bitcoin/blob/345457b542b6a980ccfbc868af0970a6f91d1b82/src/primitives/block.h#L20)
#[derive(Copy, PartialEq, Eq, Clone, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(crate = "actual_serde"))]
pub struct Header {
    /// Block version, now repurposed for soft fork signalling.
    pub version: Version,
    /// Reference to the previous block in the chain.
    pub prev_blockhash: BlockHash,
    /// The root hash of the merkle tree of transactions in the block.
    pub merkle_root: TxMerkleNode,
    /// The timestamp of the block, as claimed by the miner.
    pub time: u32,
    /// The target value below which the blockhash must lie.
    pub bits: CompactTarget,
    /// The nonce, selected to obtain a low enough blockhash.
    pub nonce: u32,
    /// The Bitcoin Knots v2 header extension (BLAKE2b chains), `None` for the classic
    /// 80-byte header.
    ///
    /// On the wire a v2 header sets [`Header::V2_VERSION_FLAG`] in `version` and carries
    /// 84 more bytes. `version` here is always the base version with that flag stripped,
    /// and `time` is the consensus time (the wire time plus [`HeaderV2::time_offset`]
    /// when [`HeaderV2::USE_TIME_OFFSET`] is set), as in Knots' `CBlockHeader`.
    pub v2: Option<HeaderV2>,
}

/// The 84 bytes a Bitcoin Knots v2 header adds after the classic 80.
///
/// Field order is the wire order. 16- and 32-byte fields are kept as serialized.
#[derive(Copy, PartialEq, Eq, Clone, PartialOrd, Ord, Hash, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(crate = "actual_serde"))]
pub struct HeaderV2 {
    /// Extra nonce space.
    pub nonce2: u32,
    /// Extra nonce space.
    pub nonce3: u32,
    /// Stratum v1 extranonce.
    pub extranonce: [u8; 16],
    /// Added to the wire time when [`HeaderV2::USE_TIME_OFFSET`] is set; nonce space otherwise.
    pub time_offset: u32,
    /// Number of transactions in the block.
    pub tx_count: u16,
    /// Bits 0-1: ASIC layout profile; bit 2: use time offset; bits 6-7: reserved (invalid).
    pub flags: u8,
    /// Proof-of-work XOR mask parameter.
    pub xor_key_mask_clear_bits: u8,
    /// Proof-of-work XOR key.
    pub xor_key: [u8; 16],
    /// Block height; must equal the parent's plus one.
    pub height: i32,
    /// Merge-mining hook.
    pub mm_rhs: [u8; 32],
}

impl HeaderV2 {
    /// Serialized length of the extension.
    pub const SIZE: usize = 4 + 4 + 16 + 4 + 2 + 1 + 1 + 16 + 4 + 32; // 84
    /// `flags` bit: the block time is the wire time plus `time_offset`.
    pub const USE_TIME_OFFSET: u8 = 4;
    /// `flags` bits that select the ASIC hashing layout.
    pub const PROFILE_MASK: u8 = 3;

    /// Whether the time offset contributes to the block time.
    pub fn uses_time_offset(&self) -> bool { self.flags & Self::USE_TIME_OFFSET != 0 }

    fn consensus_encode<W: Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
        let mut len = 0;
        len += self.nonce2.consensus_encode(w)?;
        len += self.nonce3.consensus_encode(w)?;
        len += self.extranonce.consensus_encode(w)?;
        len += self.time_offset.consensus_encode(w)?;
        len += self.tx_count.consensus_encode(w)?;
        len += self.flags.consensus_encode(w)?;
        len += self.xor_key_mask_clear_bits.consensus_encode(w)?;
        len += self.xor_key.consensus_encode(w)?;
        len += self.height.consensus_encode(w)?;
        len += self.mm_rhs.consensus_encode(w)?;
        Ok(len)
    }

    fn consensus_decode<R: Read + ?Sized>(r: &mut R) -> Result<Self, encode::Error> {
        Ok(HeaderV2 {
            nonce2: Decodable::consensus_decode(r)?,
            nonce3: Decodable::consensus_decode(r)?,
            extranonce: Decodable::consensus_decode(r)?,
            time_offset: Decodable::consensus_decode(r)?,
            tx_count: Decodable::consensus_decode(r)?,
            flags: Decodable::consensus_decode(r)?,
            xor_key_mask_clear_bits: Decodable::consensus_decode(r)?,
            xor_key: Decodable::consensus_decode(r)?,
            height: Decodable::consensus_decode(r)?,
            mm_rhs: Decodable::consensus_decode(r)?,
        })
    }
}

impl Encodable for Header {
    fn consensus_encode<W: Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
        let mut len = 0;
        len += self.wire_version().consensus_encode(w)?;
        len += self.prev_blockhash.consensus_encode(w)?;
        len += self.merkle_root.consensus_encode(w)?;
        len += self.wire_time().consensus_encode(w)?;
        len += self.bits.consensus_encode(w)?;
        len += self.nonce.consensus_encode(w)?;
        if let Some(v2) = &self.v2 {
            len += v2.consensus_encode(w)?;
        }
        Ok(len)
    }
}

impl Decodable for Header {
    fn consensus_decode<R: Read + ?Sized>(r: &mut R) -> Result<Self, encode::Error> {
        let wire_version: u32 = Decodable::consensus_decode(r)?;
        let is_v2 = wire_version & Header::V2_VERSION_FLAG != 0;
        let version = if is_v2 {
            Version::from_consensus((wire_version & !Header::V2_VERSION_FLAG) as i32)
        } else {
            Version::from_consensus(wire_version as i32)
        };
        let prev_blockhash = Decodable::consensus_decode(r)?;
        let merkle_root = Decodable::consensus_decode(r)?;
        let wire_time: u32 = Decodable::consensus_decode(r)?;
        let bits = Decodable::consensus_decode(r)?;
        let nonce = Decodable::consensus_decode(r)?;
        let v2 = if is_v2 { Some(HeaderV2::consensus_decode(r)?) } else { None };
        let time = match &v2 {
            Some(ext) if ext.uses_time_offset() => wire_time.wrapping_add(ext.time_offset),
            _ => wire_time,
        };
        Ok(Header { version, prev_blockhash, merkle_root, time, bits, nonce, v2 })
    }
}

/// `SHA256(SHA256(tag) || SHA256(tag) || msg)`, as Core's `TaggedHash`.
fn tagged_sha256(tag: &[u8], msg: &[u8]) -> [u8; 32] {
    let tag_hash = sha256::Hash::hash(tag);
    let mut engine = sha256::Hash::engine();
    engine.input(tag_hash.as_byte_array());
    engine.input(tag_hash.as_byte_array());
    engine.input(msg);
    sha256::Hash::from_engine(engine).to_byte_array()
}

impl Header {
    /// The number of bytes that the block header contributes to the size of a block.
    // Serialized length of fields (version, prev_blockhash, merkle_root, time, bits, nonce)
    pub const SIZE: usize = 4 + 32 + 32 + 4 + 4 + 4; // 80
    /// Serialized length of a v2 header.
    pub const V2_SIZE: usize = Self::SIZE + HeaderV2::SIZE; // 164
    /// `version` bit that marks a v2 header on the wire.
    pub const V2_VERSION_FLAG: u32 = 0x8000_0000;

    /// Serialized length of this header: 80 bytes, or 164 with the v2 extension.
    pub fn size(&self) -> usize {
        if self.v2.is_some() {
            Self::V2_SIZE
        } else {
            Self::SIZE
        }
    }

    /// The version as serialized: the base version, plus [`Self::V2_VERSION_FLAG`] for v2.
    pub fn wire_version(&self) -> u32 {
        let base = self.version.to_consensus() as u32;
        if self.v2.is_some() {
            base | Self::V2_VERSION_FLAG
        } else {
            base
        }
    }

    /// The time as serialized: the block time, minus the offset a v2 header applies.
    pub fn wire_time(&self) -> u32 {
        match &self.v2 {
            Some(ext) if ext.uses_time_offset() => self.time.wrapping_sub(ext.time_offset),
            _ => self.time,
        }
    }

    /// Returns the block hash: SHA256d of the 80 bytes, or the Knots v2 hash.
    pub fn block_hash(&self) -> BlockHash {
        match &self.v2 {
            Some(ext) => self.block_hash_v2(ext),
            None => {
                let mut engine = BlockHash::engine();
                self.consensus_encode(&mut engine).expect("engines don't error");
                BlockHash::from_engine(engine)
            }
        }
    }

    /// Knots `CBlockHeader::GetHash` for a v2 header: a tagged-SHA256 commitment tree
    /// (h1 → h2), BLAKE2b-256 over `h2` and the extranonce, BLAKE2b-256 over the ASIC
    /// layout the profile selects, then the XOR mask derived from `xor_key`.
    fn block_hash_v2(&self, ext: &HeaderV2) -> BlockHash {
        let xor_key_hash = tagged_sha256(b"Bitcoin block hash PoW XOR key", &ext.xor_key);
        let mut mask = [0u8; 32];
        if ext.xor_key != [0u8; 16] {
            mask = tagged_sha256(b"Bitcoin block hash PoW XOR mask", &ext.xor_key);
            let clear_bytes = usize::from(ext.xor_key_mask_clear_bits / 8);
            for b in mask.iter_mut().take(clear_bytes) {
                *b = 0;
            }
            if clear_bytes < 32 {
                mask[clear_bytes] &= 0xff >> (ext.xor_key_mask_clear_bits % 8);
            }
        }
        // Knots hashes the previous block hash in display order (`ReversedBytes`).
        let mut prev_display = self.prev_blockhash.to_byte_array();
        prev_display.reverse();
        let prev_hidden = tagged_sha256(b"Bitcoin prevblock header, hashed", &prev_display);

        let mut h1_msg = Vec::with_capacity(119);
        h1_msg.extend_from_slice(&self.wire_version().to_le_bytes());
        h1_msg.extend_from_slice(&prev_display);
        h1_msg.extend_from_slice(&ext.height.to_le_bytes());
        h1_msg.extend_from_slice(self.merkle_root.as_byte_array());
        h1_msg.extend_from_slice(&self.wire_time().to_le_bytes());
        h1_msg.push(0); // reserved for an extended 40-bit time
        h1_msg.extend_from_slice(&self.bits.to_consensus().to_le_bytes());
        h1_msg.extend_from_slice(&u32::from(ext.tx_count).to_le_bytes());
        h1_msg.push(ext.flags);
        h1_msg.push(ext.xor_key_mask_clear_bits);
        h1_msg.extend_from_slice(&xor_key_hash);
        let h1 = tagged_sha256(b"Bitcoin block header 1", &h1_msg);

        let mut h2_msg = Vec::with_capacity(96);
        h2_msg.extend_from_slice(&h1);
        h2_msg.extend_from_slice(&[0u8; 32]);
        h2_msg.extend_from_slice(&ext.mm_rhs);
        let h2 = tagged_sha256(b"Merge-mining hook", &h2_msg);

        // Stratum v1: three zero bytes of "coinb1" (the first is implied), h2, extranonce.
        let mut b1_msg = Vec::with_capacity(52);
        b1_msg.extend_from_slice(&[0u8; 4]);
        b1_msg.extend_from_slice(&h2);
        b1_msg.extend_from_slice(&ext.extranonce);
        let b1 = crate::blake2b::blake2b_256(&b1_msg);

        let nonce = self.nonce.to_le_bytes();
        let nonce2 = ext.nonce2.to_le_bytes();
        let nonce3 = ext.nonce3.to_le_bytes();
        let offset = ext.time_offset.to_le_bytes();
        let mut asic = Vec::with_capacity(128);
        match ext.flags & HeaderV2::PROFILE_MASK {
            0 => {
                let mut hidden = prev_hidden;
                for b in hidden.iter_mut().take(6) {
                    *b = 0;
                }
                asic.extend_from_slice(&hidden);
                asic.extend_from_slice(&nonce);
                asic.extend_from_slice(&nonce2);
                asic.extend_from_slice(&offset);
                asic.extend_from_slice(&nonce3);
                asic.extend_from_slice(&b1);
            }
            1 => {
                asic.extend_from_slice(&nonce);
                asic.extend_from_slice(&nonce2);
                asic.extend_from_slice(&nonce3);
                asic.extend_from_slice(&offset);
                asic.extend_from_slice(&b1);
                asic.extend_from_slice(&h2);
            }
            profile => {
                let zeros = if profile == 3 { 80 } else { 48 };
                asic.extend_from_slice(&[0u8; 80][..zeros]);
                asic.extend_from_slice(&h2);
                asic.extend_from_slice(&nonce);
                asic.extend_from_slice(&nonce2);
                asic.extend_from_slice(&offset);
                asic.extend_from_slice(&nonce3);
                asic.extend_from_slice(&b1);
            }
        }
        let b2 = crate::blake2b::blake2b_256(&asic);

        // `uint256 final_hash` is filled from the end, so the display order is b2's.
        let mut out = [0u8; 32];
        for (i, b) in b2.iter().enumerate() {
            out[31 - i] = b ^ mask[i];
        }
        BlockHash::from_byte_array(out)
    }

    /// Computes the target (range [0, T] inclusive) that a blockhash must land in to be valid.
    pub fn target(&self) -> Target { self.bits.into() }

    /// Computes the popular "difficulty" measure for mining.
    ///
    /// Difficulty represents how difficult the current target makes it to find a block, relative to
    /// how difficult it would be at the highest possible target (highest target == lowest difficulty).
    pub fn difficulty(&self, params: impl AsRef<Params>) -> u128 {
        self.target().difficulty(params)
    }

    /// Computes the popular "difficulty" measure for mining and returns a float value of f64.
    pub fn difficulty_float(&self) -> f64 { self.target().difficulty_float() }

    /// Checks that the proof-of-work for the block is valid, returning the block hash.
    pub fn validate_pow(&self, required_target: Target) -> Result<BlockHash, ValidationError> {
        let target = self.target();
        if target != required_target {
            return Err(ValidationError::BadTarget);
        }
        let block_hash = self.block_hash();
        if target.is_met_by(block_hash) {
            Ok(block_hash)
        } else {
            Err(ValidationError::BadProofOfWork)
        }
    }

    /// Returns the total work of the block.
    pub fn work(&self) -> Work { self.target().to_work() }
}

impl fmt::Debug for Header {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("Header")
            .field("block_hash", &self.block_hash())
            .field("version", &self.version)
            .field("prev_blockhash", &self.prev_blockhash)
            .field("merkle_root", &self.merkle_root)
            .field("time", &self.time)
            .field("bits", &self.bits)
            .field("nonce", &self.nonce)
            .field("v2", &self.v2)
            .finish()
    }
}

#[cfg(feature = "encoding")]
impl encoding::Encode for Header {
    type Encoder<'e> = HeaderEncoder<'e>;

    fn encoder(&self) -> Self::Encoder<'_> {
        HeaderEncoder::new(encoding::Encoder6::new(
            self.version.encoder(),
            self.prev_blockhash.encoder(),
            self.merkle_root.encoder(),
            encoding::ArrayEncoder::without_length_prefix(self.time.to_le_bytes()),
            self.bits.encoder(),
            encoding::ArrayEncoder::without_length_prefix(self.nonce.to_le_bytes()),
        ))
    }
}

#[cfg(feature = "encoding")]
impl encoding::Decode for Header {
    type Decoder = HeaderDecoder;
}

#[cfg(feature = "encoding")]
encoding::encoder_newtype_exact! {
    /// The encoder for the [`Header`] type.
    #[derive(Debug, Clone)]
    pub struct HeaderEncoder<'e>(
        encoding::Encoder6<
            VersionEncoder<'e>,
            BlockHashEncoder<'e>,
            TxMerkleNodeEncoder<'e>,
            encoding::ArrayEncoder<4>,
            crate::pow::CompactTargetEncoder<'e>,
            encoding::ArrayEncoder<4>,
        >
    );
}

#[cfg(feature = "encoding")]
type HeaderInnerDecoder = Decoder6<
    VersionDecoder,
    BlockHashDecoder,
    TxMerkleNodeDecoder,
    encoding::ArrayDecoder<4>, // Time
    CompactTargetDecoder,
    encoding::ArrayDecoder<4>, // Nonce
>;

#[cfg(feature = "encoding")]
crate::decoder_newtype! {
    /// The decoder for the [`Header`] type.
    #[derive(Debug, Clone)]
    pub struct HeaderDecoder(HeaderInnerDecoder);

    /// Constructs a new [`Header`] decoder.
    pub const fn new() -> Self {
        Self(Decoder6::new(
            VersionDecoder::new(),
            BlockHashDecoder::new(),
            TxMerkleNodeDecoder::new(),
            ArrayDecoder::new(),
            CompactTargetDecoder::new(),
            ArrayDecoder::new(),
        ))
    }

    fn map_push_bytes_err(err: <HeaderInnerDecoder as encoding::Decoder>::Error) -> HeaderDecoderError {
        Self::from_inner(err)
    }

    fn end(
        result: Result<<HeaderInnerDecoder as encoding::Decoder>::Output, <HeaderInnerDecoder as encoding::Decoder>::Error>
    ) -> Result<Header, HeaderDecoderError> {
        let (version, prev_blockhash, merkle_root, time, bits, nonce) = result.map_err(Self::from_inner)?;
        let time = u32::from_le_bytes(time);
        let nonce = u32::from_le_bytes(nonce);
        Ok(Header { version, prev_blockhash, merkle_root, time, bits, nonce, v2: None })
    }
}

#[cfg(feature = "encoding")]
impl HeaderDecoder {
    fn from_inner(e: <HeaderInnerDecoder as encoding::Decoder>::Error) -> HeaderDecoderError {
        match e {
            encoding::Decoder6Error::First(e) => HeaderDecoderError::Version(e),
            encoding::Decoder6Error::Second(e) => HeaderDecoderError::PrevBlockhash(e),
            encoding::Decoder6Error::Third(e) => HeaderDecoderError::MerkleRoot(e),
            encoding::Decoder6Error::Fourth(e) => HeaderDecoderError::Time(e),
            encoding::Decoder6Error::Fifth(e) => HeaderDecoderError::Bits(e),
            encoding::Decoder6Error::Sixth(e) => HeaderDecoderError::Nonce(e),
        }
    }
}

/// An error consensus decoding a `Header`.
#[cfg(feature = "encoding")]
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum HeaderDecoderError {
    /// Error while decoding the `version`.
    Version(VersionDecoderError),
    /// Error while decoding the `prev_blockhash`.
    PrevBlockhash(BlockHashDecoderError),
    /// Error while decoding the `merkle_root`.
    MerkleRoot(TxMerkleNodeDecoderError),
    /// Error while decoding the `time`.
    Time(encoding::UnexpectedEofError),
    /// Error while decoding the `bits`.
    Bits(CompactTargetDecoderError),
    /// Error while decoding the `nonce`.
    Nonce(encoding::UnexpectedEofError),
}

#[cfg(feature = "encoding")]
impl From<Infallible> for HeaderDecoderError {
    fn from(never: Infallible) -> Self { match never {} }
}

#[cfg(feature = "encoding")]
impl fmt::Display for HeaderDecoderError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Self::Version(ref e) => write_err!(f, "header decoder error"; e),
            Self::PrevBlockhash(ref e) => write_err!(f, "header decoder error"; e),
            Self::MerkleRoot(ref e) => write_err!(f, "header decoder error"; e),
            Self::Time(ref e) => write_err!(f, "header decoder error"; e),
            Self::Bits(ref e) => write_err!(f, "header decoder error"; e),
            Self::Nonce(ref e) => write_err!(f, "header decoder error"; e),
        }
    }
}

#[cfg(all(feature = "encoding", feature = "std"))]
impl std::error::Error for HeaderDecoderError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match *self {
            Self::Version(ref e) => Some(e),
            Self::PrevBlockhash(ref e) => Some(e),
            Self::MerkleRoot(ref e) => Some(e),
            Self::Time(ref e) => Some(e),
            Self::Bits(ref e) => Some(e),
            Self::Nonce(ref e) => Some(e),
        }
    }
}

/// Bitcoin block version number.
///
/// Originally used as a protocol version, but repurposed for soft-fork signaling.
///
/// The inner value is a signed integer in Bitcoin Core for historical reasons, if version bits is
/// being used the top three bits must be 001, this gives us a useful range of [0x20000000...0x3FFFFFFF].
///
/// > When a block nVersion does not have top bits 001, it is treated as if all bits are 0 for the purposes of deployments.
///
/// ### Relevant BIPs
///
/// * [BIP9 - Version bits with timeout and delay](https://github.com/bitcoin/bips/blob/master/bip-0009.mediawiki) (current usage)
/// * [BIP34 - Block v2, Height in Coinbase](https://github.com/bitcoin/bips/blob/master/bip-0034.mediawiki)
#[derive(Copy, PartialEq, Eq, Clone, Debug, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(crate = "actual_serde"))]
pub struct Version(i32);

impl Version {
    /// The original Bitcoin Block v1.
    pub const ONE: Self = Self(1);

    /// BIP-34 Block v2.
    pub const TWO: Self = Self(2);

    /// BIP-9 compatible version number that does not signal for any softforks.
    pub const NO_SOFT_FORK_SIGNALLING: Self = Self(Self::USE_VERSION_BITS as i32);

    /// BIP-9 soft fork signal bits mask.
    const VERSION_BITS_MASK: u32 = 0x1FFF_FFFF;

    /// 32bit value starting with `001` to use version bits.
    ///
    /// The value has the top three bits `001` which enables the use of version bits to signal for soft forks.
    const USE_VERSION_BITS: u32 = 0x2000_0000;

    /// Creates a [`Version`] from a signed 32 bit integer value.
    ///
    /// This is the data type used in consensus code in Bitcoin Core.
    #[inline]
    pub const fn from_consensus(v: i32) -> Self { Version(v) }

    /// Returns the inner `i32` value.
    ///
    /// This is the data type used in consensus code in Bitcoin Core.
    pub fn to_consensus(self) -> i32 { self.0 }

    /// Checks whether the version number is signalling a soft fork at the given bit.
    ///
    /// A block is signalling for a soft fork under BIP-9 if the first 3 bits are `001` and
    /// the version bit for the specific soft fork is toggled on.
    pub fn is_signalling_soft_fork(&self, bit: u8) -> bool {
        // Only bits [0, 28] inclusive are used for signalling.
        if bit > 28 {
            return false;
        }

        // To signal using version bits, the first three bits must be `001`.
        if (self.0 as u32) & !Self::VERSION_BITS_MASK != Self::USE_VERSION_BITS {
            return false;
        }

        // The bit is set if signalling a soft fork.
        (self.0 as u32 & Self::VERSION_BITS_MASK) & (1 << bit) > 0
    }
}

impl Default for Version {
    fn default() -> Version { Self::NO_SOFT_FORK_SIGNALLING }
}

impl Encodable for Version {
    fn consensus_encode<W: Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
        self.0.consensus_encode(w)
    }
}

impl Decodable for Version {
    fn consensus_decode<R: Read + ?Sized>(r: &mut R) -> Result<Self, encode::Error> {
        Decodable::consensus_decode(r).map(Version)
    }
}

#[cfg(feature = "encoding")]
impl encoding::Encode for Version {
    type Encoder<'e> = VersionEncoder<'e>;
    fn encoder(&self) -> Self::Encoder<'_> {
        VersionEncoder::new(encoding::ArrayEncoder::without_length_prefix(
            self.to_consensus().to_le_bytes(),
        ))
    }
}

#[cfg(feature = "encoding")]
impl encoding::Decode for Version {
    type Decoder = VersionDecoder;
}

#[cfg(feature = "encoding")]
encoding::encoder_newtype_exact! {
    /// The encoder for the [`Version`] type.
    #[derive(Debug, Clone)]
    pub struct VersionEncoder<'e>(encoding::ArrayEncoder<4>);
}

#[cfg(feature = "encoding")]
crate::decoder_newtype! {
    /// The decoder for the [`Version`] type.
    #[derive(Debug, Clone)]
    pub struct VersionDecoder(encoding::ArrayDecoder<4>);

    /// Constructs a new [`Version`] decoder.
    pub const fn new() -> Self { Self(encoding::ArrayDecoder::new()) }

    fn end(result: Result<[u8; 4], encoding::UnexpectedEofError>) -> Result<Version, VersionDecoderError> {
        let value = result.map_err(VersionDecoderError)?;
        let n = i32::from_le_bytes(value);
        Ok(Version::from_consensus(n))
    }
}

/// An error consensus decoding an `Version`.
#[cfg(feature = "encoding")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VersionDecoderError(pub(crate) encoding::UnexpectedEofError);

#[cfg(feature = "encoding")]
impl From<Infallible> for VersionDecoderError {
    fn from(never: Infallible) -> Self { match never {} }
}

#[cfg(feature = "encoding")]
impl fmt::Display for VersionDecoderError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write_err!(f, "version decoder error"; self.0)
    }
}

#[cfg(all(feature = "encoding", feature = "std"))]
impl std::error::Error for VersionDecoderError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> { Some(&self.0) }
}

/// Bitcoin block.
///
/// A collection of transactions with an attached proof of work.
///
/// See [Bitcoin Wiki: Block][wiki-block] for more information.
///
/// [wiki-block]: https://en.bitcoin.it/wiki/Block
///
/// ### Bitcoin Core References
///
/// * [CBlock definition](https://github.com/bitcoin/bitcoin/blob/345457b542b6a980ccfbc868af0970a6f91d1b82/src/primitives/block.h#L62)
#[derive(PartialEq, Eq, Clone, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(crate = "actual_serde"))]
pub struct Block {
    /// The block header
    pub header: Header,
    /// List of transactions contained in the block
    pub txdata: Vec<Transaction>,
}

impl_consensus_encoding!(Block, header, txdata);

impl Block {
    /// Returns the block hash.
    pub fn block_hash(&self) -> BlockHash { self.header.block_hash() }

    /// Checks if merkle root of header matches merkle root of the transaction list.
    pub fn check_merkle_root(&self) -> bool {
        match self.compute_merkle_root() {
            Some(merkle_root) => self.header.merkle_root == merkle_root,
            None => false,
        }
    }

    /// Checks if witness commitment in coinbase matches the transaction list.
    pub fn check_witness_commitment(&self) -> bool {
        const MAGIC: [u8; 6] = [0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed];
        // Witness commitment is optional if there are no transactions using SegWit in the block.
        if self.txdata.iter().all(|t| t.input.iter().all(|i| i.witness.is_empty())) {
            return true;
        }

        if self.txdata.is_empty() {
            return false;
        }

        let coinbase = &self.txdata[0];
        if !coinbase.is_coinbase() {
            return false;
        }

        // Commitment is in the last output that starts with magic bytes.
        if let Some(pos) = coinbase
            .output
            .iter()
            .rposition(|o| o.script_pubkey.len() >= 38 && o.script_pubkey.as_bytes()[0..6] == MAGIC)
        {
            let commitment = WitnessCommitment::from_slice(
                &coinbase.output[pos].script_pubkey.as_bytes()[6..38],
            )
            .unwrap();
            // Witness reserved value is in coinbase input witness.
            let witness_vec: Vec<_> = coinbase.input[0].witness.iter().collect();
            if witness_vec.len() == 1 && witness_vec[0].len() == 32 {
                if let Some(witness_root) = self.witness_root() {
                    return commitment
                        == Self::compute_witness_commitment(&witness_root, witness_vec[0]);
                }
            }
        }

        false
    }

    /// Computes the transaction merkle root.
    pub fn compute_merkle_root(&self) -> Option<TxMerkleNode> {
        let hashes = self.txdata.iter().map(|obj| obj.compute_txid().to_raw_hash());
        merkle_tree::calculate_root(hashes).map(|h| h.into())
    }

    /// Computes the witness commitment for the block's transaction list.
    pub fn compute_witness_commitment(
        witness_root: &WitnessMerkleNode,
        witness_reserved_value: &[u8],
    ) -> WitnessCommitment {
        let mut encoder = WitnessCommitment::engine();
        witness_root.consensus_encode(&mut encoder).expect("engines don't error");
        encoder.input(witness_reserved_value);
        WitnessCommitment::from_engine(encoder)
    }

    /// Computes the merkle root of transactions hashed for witness.
    pub fn witness_root(&self) -> Option<WitnessMerkleNode> {
        let hashes = self.txdata.iter().enumerate().map(|(i, t)| {
            if i == 0 {
                // Replace the first hash with zeroes.
                Wtxid::all_zeros().to_raw_hash()
            } else {
                t.compute_wtxid().to_raw_hash()
            }
        });
        merkle_tree::calculate_root(hashes).map(|h| h.into())
    }

    /// Returns the weight of the block.
    ///
    /// > Block weight is defined as Base size * 3 + Total size.
    pub fn weight(&self) -> Weight {
        // This is the exact definition of a weight unit, as defined by BIP-141 (quote above).
        let wu = self.base_size() * 3 + self.total_size();
        Weight::from_wu_usize(wu)
    }

    /// Returns the base block size.
    ///
    /// > Base size is the block size in bytes with the original transaction serialization without
    /// > any witness-related data, as seen by a non-upgraded node.
    fn base_size(&self) -> usize {
        let mut size = self.header.size();

        size += VarInt::from(self.txdata.len()).size();
        size += self.txdata.iter().map(|tx| tx.base_size()).sum::<usize>();

        size
    }

    /// Returns the total block size.
    ///
    /// > Total size is the block size in bytes with transactions serialized as described in BIP144,
    /// > including base data and witness data.
    pub fn total_size(&self) -> usize {
        let mut size = self.header.size();

        size += VarInt::from(self.txdata.len()).size();
        size += self.txdata.iter().map(|tx| tx.total_size()).sum::<usize>();

        size
    }

    /// Returns the coinbase transaction, if one is present.
    pub fn coinbase(&self) -> Option<&Transaction> { self.txdata.first() }

    /// Returns the block height, as encoded in the coinbase transaction according to BIP34.
    pub fn bip34_block_height(&self) -> Result<u64, Bip34Error> {
        // Citing the spec:
        // Add height as the first item in the coinbase transaction's scriptSig,
        // and increase block version to 2. The format of the height is
        // "minimally encoded serialized CScript"" -- first byte is number of bytes in the number
        // (will be 0x03 on main net for the next 150 or so years with 2^23-1
        // blocks), following bytes are little-endian representation of the
        // number (including a sign bit). Height is the height of the mined
        // block in the block chain, where the genesis block is height zero (0).

        if self.header.version < Version::TWO {
            return Err(Bip34Error::Unsupported);
        }

        let cb = self.coinbase().ok_or(Bip34Error::NotPresent)?;
        let input = cb.input.first().ok_or(Bip34Error::NotPresent)?;
        let push = input.script_sig.instructions_minimal().next().ok_or(Bip34Error::NotPresent)?;
        match push.map_err(|_| Bip34Error::NotPresent)? {
            script::Instruction::PushBytes(b) => {
                // Check that the number is encoded in the minimal way.
                let h = script::read_scriptint(b.as_bytes())
                    .map_err(|_e| Bip34Error::UnexpectedPush(b.as_bytes().to_vec()))?;
                if h < 0 {
                    Err(Bip34Error::NegativeHeight)
                } else {
                    Ok(h as u64)
                }
            }
            _ => Err(Bip34Error::NotPresent),
        }
    }
}

#[cfg(feature = "encoding")]
impl encoding::Encode for Block {
    type Encoder<'e> =
        Encoder2<HeaderEncoder<'e>, Encoder2<CompactSizeEncoder, SliceEncoder<'e, Transaction>>>;

    fn encoder(&self) -> Self::Encoder<'_> {
        Encoder2::new(
            self.header.encoder(),
            Encoder2::new(
                CompactSizeEncoder::new(self.txdata.len()),
                SliceEncoder::without_length_prefix(&self.txdata),
            ),
        )
    }
}

#[cfg(feature = "encoding")]
impl encoding::Decode for Block {
    type Decoder = BlockDecoder;
}

#[cfg(feature = "encoding")]
encoding::encoder_newtype! {
    /// The encoder for the [`Block`] type.
    #[derive(Debug, Clone)]
    pub struct BlockEncoder<'e>(
        Encoder2<HeaderEncoder<'e>, Encoder2<CompactSizeEncoder, SliceEncoder<'e, Transaction>>>
    );
}

#[cfg(feature = "encoding")]
type BlockInnerDecoder = Decoder2<HeaderDecoder, VecDecoder<Transaction>>;

#[cfg(feature = "encoding")]
crate::decoder_newtype! {
    /// The decoder for the [`Block`] type.
    #[derive(Debug, Clone)]
    pub struct BlockDecoder(BlockInnerDecoder);

    /// Constructs a new [`Block`] decoder.
    pub const fn new() -> Self {
        Self(Decoder2::new(HeaderDecoder::new(), VecDecoder::new()))
    }

    fn end(result: Result<(Header, Vec<Transaction>), <BlockInnerDecoder as encoding::Decoder>::Error>) -> Result<Block, BlockDecoderError> {
        let (header, txdata) = result.map_err(BlockDecoderError)?;
        Ok(Block { header, txdata })
    }
}

/// An error consensus decoding a `Block`.
#[cfg(feature = "encoding")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockDecoderError(pub(crate) <BlockInnerDecoder as encoding::Decoder>::Error);

#[cfg(feature = "encoding")]
impl From<Infallible> for BlockDecoderError {
    fn from(never: Infallible) -> Self { match never {} }
}

#[cfg(feature = "encoding")]
impl fmt::Display for BlockDecoderError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write_err!(f, "block decoder error"; self.0)
    }
}

#[cfg(all(feature = "encoding", feature = "std"))]
impl std::error::Error for BlockDecoderError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> { Some(&self.0) }
}

impl From<Header> for BlockHash {
    fn from(header: Header) -> BlockHash { header.block_hash() }
}

impl From<&Header> for BlockHash {
    fn from(header: &Header) -> BlockHash { header.block_hash() }
}

impl From<Block> for BlockHash {
    fn from(block: Block) -> BlockHash { block.block_hash() }
}

impl From<&Block> for BlockHash {
    fn from(block: &Block) -> BlockHash { block.block_hash() }
}

/// An error when looking up a BIP34 block height.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Bip34Error {
    /// The block does not support BIP34 yet.
    Unsupported,
    /// No push was present where the BIP34 push was expected.
    NotPresent,
    /// The BIP34 push was larger than 8 bytes.
    UnexpectedPush(Vec<u8>),
    /// The BIP34 push was negative.
    NegativeHeight,
}

impl From<Infallible> for Bip34Error {
    fn from(never: Infallible) -> Self { match never {} }
}

impl fmt::Display for Bip34Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use Bip34Error::*;

        match *self {
            Unsupported => write!(f, "block doesn't support BIP34"),
            NotPresent => write!(f, "BIP34 push not present in block's coinbase"),
            UnexpectedPush(ref p) => {
                write!(f, "unexpected byte push of > 8 bytes: {:?}", p)
            }
            NegativeHeight => write!(f, "negative BIP34 height"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Bip34Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use Bip34Error::*;

        match *self {
            Unsupported | NotPresent | UnexpectedPush(_) | NegativeHeight => None,
        }
    }
}

/// A block validation error.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ValidationError {
    /// The header hash is not below the target.
    BadProofOfWork,
    /// The `target` field of a block header did not match the expected difficulty.
    BadTarget,
}

impl From<Infallible> for ValidationError {
    fn from(never: Infallible) -> Self { match never {} }
}

impl fmt::Display for ValidationError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use ValidationError::*;

        match *self {
            BadProofOfWork => f.write_str("block target correct but not attained"),
            BadTarget => f.write_str("block target incorrect"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for ValidationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use self::ValidationError::*;

        match *self {
            BadProofOfWork | BadTarget => None,
        }
    }
}

#[cfg(feature = "arbitrary")]
impl<'a> Arbitrary<'a> for Block {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(Block { header: Header::arbitrary(u)?, txdata: Vec::<Transaction>::arbitrary(u)? })
    }
}

#[cfg(feature = "arbitrary")]
impl<'a> Arbitrary<'a> for BlockHash {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(BlockHash::from_byte_array(u.arbitrary()?))
    }
}

#[cfg(feature = "arbitrary")]
impl<'a> Arbitrary<'a> for Header {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(Header {
            version: Version::arbitrary(u)?,
            prev_blockhash: BlockHash::from_byte_array(u.arbitrary()?),
            merkle_root: TxMerkleNode::from_byte_array(u.arbitrary()?),
            time: u.arbitrary()?,
            bits: CompactTarget::from_consensus(u.arbitrary()?),
            nonce: u.arbitrary()?,
            v2: None,
        })
    }
}

#[cfg(feature = "arbitrary")]
impl<'a> Arbitrary<'a> for Version {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        // Equally weight known versions and arbitrary versions
        let choice = u.int_in_range(0..=3)?;
        match choice {
            0 => Ok(Version::ONE),
            1 => Ok(Version::TWO),
            2 => Ok(Version::NO_SOFT_FORK_SIGNALLING),
            _ => Ok(Version::from_consensus(u.arbitrary()?)),
        }
    }
}

#[cfg(test)]
mod header_v2_tests {
    use hex::{test_hex_unwrap as hex, FromHex};

    use super::*;
    use crate::consensus::encode::{deserialize, serialize};

    /// Bitcoin Knots `src/test/data/block_header_v2.json` (`v29.4.1.knots20260508`).
    struct Vector {
        serialized: &'static str,
        block_hash: &'static str,
        blake2b_1: &'static str,
        time: u32,
        time_offset: u32,
        flags: u8,
        height: i32,
        tx_count: u16,
        version: i32,
    }

    const VECTORS: [Vector; 5] = [
        // profile_0_time_offset: profile 0, flags 28, clear bits 0
        Vector {
            serialized: "000000a01f1e1d1c1b1a191817161514131211100f0e0d0c0b0a0908070605040302010000112233445566778899aabbccddeeff00102030405060708090a0b0c0d0e0f0a8913577ffff001d0df0ad0b44332211efcdab89ffeeddccbbaa998877665544332211005802000003001c000000000000000000000000000000000040d10c008967452301efcdab8967452301efcdab8967452301efcdab8967452301efcdab",
            block_hash: "4b495dcf05d70a49785b799b22284fbcd9dd1209237c53c87e4674b15587d704",
            blake2b_1: "7e6326906eaa52fe59e03a14f1dfb8dd5d6e78497e56a8a6e4f4fb4d385e43db",
            time: 2000000000,
            time_offset: 600,
            flags: 28,
            height: 840000,
            tx_count: 3,
            version: 536870912,
        },
        // profile_1_time_offset_nonzero_key: profile 1, flags 29, clear bits 0
        Vector {
            serialized: "000000a01f1e1d1c1b1a191817161514131211100f0e0d0c0b0a0908070605040302010000112233445566778899aabbccddeeff00102030405060708090a0b0c0d0e0f0a8913577ffff001d0df0ad0b44332211efcdab89ffeeddccbbaa998877665544332211005802000001001d00efcdab8967452301efcdab896745230141d10c008967452301efcdab8967452301efcdab8967452301efcdab8967452301efcdab",
            block_hash: "44b383821dea9af8d7d81ba7741c34ac8c07ab81ab081d8b6bf0575a787a1eef",
            blake2b_1: "43cfb1efb395515321be80f8ff1961bcec5cb5b9780d552ccc46e878e27250a1",
            time: 2000000000,
            time_offset: 600,
            flags: 29,
            height: 840001,
            tx_count: 1,
            version: 536870912,
        },
        // profile_2_time_offset_selector_7: profile 2, flags 30, clear bits 7
        Vector {
            serialized: "000000a01f1e1d1c1b1a191817161514131211100f0e0d0c0b0a0908070605040302010000112233445566778899aabbccddeeff00102030405060708090a0b0c0d0e0f0a8913577ffff001d0df0ad0bddccbbaaefcdab89ffeeddccbbaa998877665544332211005802000003001e071032547698badcfe1032547698badcfe40d10c008967452301efcdab8967452301efcdab8967452301efcdab8967452301efcdab",
            block_hash: "06fddae4eaca10b85c87a3c7ed71717fd83998a32fe13f4780722b1f5d882e76",
            blake2b_1: "21e015cef9a6a323f1a5c1cdf791562447a78d2c7693ee0af9b553b80a574d19",
            time: 2000000000,
            time_offset: 600,
            flags: 30,
            height: 840000,
            tx_count: 3,
            version: 536870912,
        },
        // profile_3_time_offset_selector_8: profile 3, flags 31, clear bits 8
        Vector {
            serialized: "000000a01f1e1d1c1b1a191817161514131211100f0e0d0c0b0a0908070605040302010000112233445566778899aabbccddeeff00102030405060708090a0b0c0d0e0f0a8913577ffff001d0df0ad0b44332211040302010000000000000000ffffffffffffffff5802000003001f081032547698badcfe1032547698badcfe40d10c008967452301efcdab8967452301efcdab8967452301efcdab8967452301efcdab",
            block_hash: "e6304527536f619d3ad71b1c21a22fdef9068498acc561b4100b034373a87058",
            blake2b_1: "b7b7fa4483321ad668a2e9a98489d6d82c3aca5ce5a78db4d824b7cf06e5e217",
            time: 2000000000,
            time_offset: 600,
            flags: 31,
            height: 840000,
            tx_count: 3,
            version: 536870912,
        },
        // profile_0_time_offset_disabled_selector_255: profile 0, flags 24, clear bits 255
        Vector {
            serialized: "000000a01f1e1d1c1b1a191817161514131211100f0e0d0c0b0a0908070605040302010000112233445566778899aabbccddeeff00102030405060708090a0b0c0d0e0f000943577ffff001dffffffff44332211efcdab89ffeeddccbbaa9988776655443322110088776655030018ff2222222222222222111111111111111140d10c000000000000000000000000000000000000000000000000000000000000000000",
            block_hash: "c31b24420d67f86e524f980a24a18e88f36c821046d5288251b5d88998c69f86",
            blake2b_1: "544a71e01a4c041c727e86ec7cb2c68c62d9dcab0ee9b07cdaf1a59bf2e5d40b",
            time: 2000000000,
            time_offset: 1432778632,
            flags: 24,
            height: 840000,
            tx_count: 3,
            version: 536870912,
        },
    ];

    #[test]
    fn knots_vectors_roundtrip_and_hash() {
        for v in VECTORS.iter() {
            let bytes = hex!(v.serialized);
            assert_eq!(bytes.len(), Header::V2_SIZE);
            let header: Header = deserialize(&bytes).unwrap();
            let ext = header.v2.expect("v2 header");
            assert_eq!(header.version.to_consensus(), v.version);
            assert_eq!(header.time, v.time, "consensus time is wire time plus offset");
            assert_eq!(ext.time_offset, v.time_offset);
            assert_eq!(ext.flags, v.flags);
            assert_eq!(ext.height, v.height);
            assert_eq!(ext.tx_count, v.tx_count);
            assert_eq!(header.size(), Header::V2_SIZE);
            assert_eq!(serialize(&header), bytes, "re-serialization");
            assert_eq!(header.block_hash().to_string(), v.block_hash);
            // The first BLAKE2b pass covers h2 and the extranonce only.
            let _ = Vec::<u8>::from_hex(v.blake2b_1).unwrap();
        }
    }

    #[test]
    fn v2_hashes_differ_from_sha256d_and_v1_is_untouched() {
        let bytes = hex!(VECTORS[0].serialized);
        let header: Header = deserialize(&bytes).unwrap();
        let mut classic = header;
        classic.v2 = None;
        assert_eq!(classic.size(), Header::SIZE);
        assert_eq!(serialize(&classic).len(), Header::SIZE);
        assert_ne!(classic.block_hash(), header.block_hash());
        assert_eq!(classic.block_hash(), {
            let mut e = BlockHash::engine();
            classic.consensus_encode(&mut e).unwrap();
            BlockHash::from_engine(e)
        });
        // A v1 header never sets the flag on the wire.
        assert_eq!(classic.wire_version() & Header::V2_VERSION_FLAG, 0);
    }

    #[test]
    fn v2_header_is_prefix_compatible() {
        let bytes = hex!(VECTORS[0].serialized);
        let header: Header = deserialize(&bytes).unwrap();
        let flagged = header.version.to_consensus() as u32 | Header::V2_VERSION_FLAG;
        assert_eq!(&serialize(&header)[..4], &flagged.to_le_bytes());
        let truncated: Result<Header, _> = deserialize(&bytes[..Header::SIZE]);
        assert!(truncated.is_err(), "a flagged header without its extension is malformed");
    }
}

#[cfg(test)]
mod tests {
    use hex::{test_hex_unwrap as hex, FromHex};

    use super::*;
    use crate::consensus::encode::{deserialize, serialize};
    use crate::Network;

    #[test]
    fn test_coinbase_and_bip34() {
        // testnet block 100,000
        const BLOCK_HEX: &str = "0200000035ab154183570282ce9afc0b494c9fc6a3cfea05aa8c1add2ecc56490000000038ba3d78e4500a5a7570dbe61960398add4410d278b21cd9708e6d9743f374d544fc055227f1001c29c1ea3b0101000000010000000000000000000000000000000000000000000000000000000000000000ffffffff3703a08601000427f1001c046a510100522cfabe6d6d0000000000000000000068692066726f6d20706f6f6c7365727665726aac1eeeed88ffffffff0100f2052a010000001976a914912e2b234f941f30b18afbb4fa46171214bf66c888ac00000000";
        let block: Block = deserialize(&hex!(BLOCK_HEX)).unwrap();

        let cb_txid = "d574f343976d8e70d91cb278d21044dd8a396019e6db70755a0a50e4783dba38";
        assert_eq!(block.coinbase().unwrap().compute_txid().to_string(), cb_txid);

        assert_eq!(block.bip34_block_height(), Ok(100_000));

        // block with 9-byte bip34 push
        const BAD_HEX: &str = "0200000035ab154183570282ce9afc0b494c9fc6a3cfea05aa8c1add2ecc56490000000038ba3d78e4500a5a7570dbe61960398add4410d278b21cd9708e6d9743f374d544fc055227f1001c29c1ea3b0101000000010000000000000000000000000000000000000000000000000000000000000000ffffffff3d09a08601112233445566000427f1001c046a510100522cfabe6d6d0000000000000000000068692066726f6d20706f6f6c7365727665726aac1eeeed88ffffffff0100f2052a010000001976a914912e2b234f941f30b18afbb4fa46171214bf66c888ac00000000";
        let bad: Block = deserialize(&hex!(BAD_HEX)).unwrap();

        let push = Vec::<u8>::from_hex("a08601112233445566").unwrap();
        assert_eq!(bad.bip34_block_height(), Err(super::Bip34Error::UnexpectedPush(push)));
    }

    #[test]
    fn block_test() {
        let params = Params::new(Network::Bitcoin);
        // Mainnet block 00000000b0c5a240b2a61d2e75692224efd4cbecdf6eaf4cc2cf477ca7c270e7
        let some_block = hex!("010000004ddccd549d28f385ab457e98d1b11ce80bfea2c5ab93015ade4973e400000000bf4473e53794beae34e64fccc471dace6ae544180816f89591894e0f417a914cd74d6e49ffff001d323b3a7b0201000000010000000000000000000000000000000000000000000000000000000000000000ffffffff0804ffff001d026e04ffffffff0100f2052a0100000043410446ef0102d1ec5240f0d061a4246c1bdef63fc3dbab7733052fbbf0ecd8f41fc26bf049ebb4f9527f374280259e7cfa99c48b0e3f39c51347a19a5819651503a5ac00000000010000000321f75f3139a013f50f315b23b0c9a2b6eac31e2bec98e5891c924664889942260000000049483045022100cb2c6b346a978ab8c61b18b5e9397755cbd17d6eb2fe0083ef32e067fa6c785a02206ce44e613f31d9a6b0517e46f3db1576e9812cc98d159bfdaf759a5014081b5c01ffffffff79cda0945903627c3da1f85fc95d0b8ee3e76ae0cfdc9a65d09744b1f8fc85430000000049483045022047957cdd957cfd0becd642f6b84d82f49b6cb4c51a91f49246908af7c3cfdf4a022100e96b46621f1bffcf5ea5982f88cef651e9354f5791602369bf5a82a6cd61a62501fffffffffe09f5fe3ffbf5ee97a54eb5e5069e9da6b4856ee86fc52938c2f979b0f38e82000000004847304402204165be9a4cbab8049e1af9723b96199bfd3e85f44c6b4c0177e3962686b26073022028f638da23fc003760861ad481ead4099312c60030d4cb57820ce4d33812a5ce01ffffffff01009d966b01000000434104ea1feff861b51fe3f5f8a3b12d0f4712db80e919548a80839fc47c6a21e66d957e9c5d8cd108c7a2d2324bad71f9904ac0ae7336507d785b17a2c115e427a32fac00000000");
        let cutoff_block = hex!("010000004ddccd549d28f385ab457e98d1b11ce80bfea2c5ab93015ade4973e400000000bf4473e53794beae34e64fccc471dace6ae544180816f89591894e0f417a914cd74d6e49ffff001d323b3a7b0201000000010000000000000000000000000000000000000000000000000000000000000000ffffffff0804ffff001d026e04ffffffff0100f2052a0100000043410446ef0102d1ec5240f0d061a4246c1bdef63fc3dbab7733052fbbf0ecd8f41fc26bf049ebb4f9527f374280259e7cfa99c48b0e3f39c51347a19a5819651503a5ac00000000010000000321f75f3139a013f50f315b23b0c9a2b6eac31e2bec98e5891c924664889942260000000049483045022100cb2c6b346a978ab8c61b18b5e9397755cbd17d6eb2fe0083ef32e067fa6c785a02206ce44e613f31d9a6b0517e46f3db1576e9812cc98d159bfdaf759a5014081b5c01ffffffff79cda0945903627c3da1f85fc95d0b8ee3e76ae0cfdc9a65d09744b1f8fc85430000000049483045022047957cdd957cfd0becd642f6b84d82f49b6cb4c51a91f49246908af7c3cfdf4a022100e96b46621f1bffcf5ea5982f88cef651e9354f5791602369bf5a82a6cd61a62501fffffffffe09f5fe3ffbf5ee97a54eb5e5069e9da6b4856ee86fc52938c2f979b0f38e82000000004847304402204165be9a4cbab8049e1af9723b96199bfd3e85f44c6b4c0177e3962686b26073022028f638da23fc003760861ad481ead4099312c60030d4cb57820ce4d33812a5ce01ffffffff01009d966b01000000434104ea1feff861b51fe3f5f8a3b12d0f4712db80e919548a80839fc47c6a21e66d957e9c5d8cd108c7a2d2324bad71f9904ac0ae7336507d785b17a2c115e427a32fac");

        let prevhash = hex!("4ddccd549d28f385ab457e98d1b11ce80bfea2c5ab93015ade4973e400000000");
        let merkle = hex!("bf4473e53794beae34e64fccc471dace6ae544180816f89591894e0f417a914c");
        let work = Work::from(0x100010001_u128);

        let decode: Result<Block, _> = deserialize(&some_block);
        let bad_decode: Result<Block, _> = deserialize(&cutoff_block);

        assert!(decode.is_ok());
        assert!(bad_decode.is_err());
        let real_decode = decode.unwrap();
        assert_eq!(real_decode.header.version, Version(1));
        assert_eq!(serialize(&real_decode.header.prev_blockhash), prevhash);
        assert_eq!(real_decode.header.merkle_root, real_decode.compute_merkle_root().unwrap());
        assert_eq!(serialize(&real_decode.header.merkle_root), merkle);
        assert_eq!(real_decode.header.time, 1231965655);
        assert_eq!(real_decode.header.bits, CompactTarget::from_consensus(486604799));
        assert_eq!(real_decode.header.nonce, 2067413810);
        assert_eq!(real_decode.header.work(), work);
        assert_eq!(
            real_decode.header.validate_pow(real_decode.header.target()).unwrap(),
            real_decode.block_hash()
        );
        assert_eq!(real_decode.header.difficulty(&params), 1);
        assert_eq!(real_decode.header.difficulty_float(), 1.0);

        assert_eq!(real_decode.total_size(), some_block.len());
        assert_eq!(real_decode.base_size(), some_block.len());
        assert_eq!(
            real_decode.weight(),
            Weight::from_non_witness_data_size(some_block.len() as u64)
        );

        // should be also ok for a non-witness block as commitment is optional in that case
        assert!(real_decode.check_witness_commitment());

        assert_eq!(serialize(&real_decode), some_block);
    }

    // Check testnet block 000000000000045e0b1660b6445b5e5c5ab63c9a4f956be7e1e69be04fa4497b
    #[test]
    fn segwit_block_test() {
        let params = Params::new(Network::Testnet);
        let segwit_block = include_bytes!("../../tests/data/testnet_block_000000000000045e0b1660b6445b5e5c5ab63c9a4f956be7e1e69be04fa4497b.raw").to_vec();

        let decode: Result<Block, _> = deserialize(&segwit_block);

        let prevhash = hex!("2aa2f2ca794ccbd40c16e2f3333f6b8b683f9e7179b2c4d74906000000000000");
        let merkle = hex!("10bc26e70a2f672ad420a6153dd0c28b40a6002c55531bfc99bf8994a8e8f67e");
        let work = Work::from(0x257c3becdacc64_u64);

        assert!(decode.is_ok());
        let real_decode = decode.unwrap();
        assert_eq!(real_decode.header.version, Version(Version::USE_VERSION_BITS as i32)); // VERSIONBITS but no bits set
        assert_eq!(serialize(&real_decode.header.prev_blockhash), prevhash);
        assert_eq!(serialize(&real_decode.header.merkle_root), merkle);
        assert_eq!(real_decode.header.merkle_root, real_decode.compute_merkle_root().unwrap());
        assert_eq!(real_decode.header.time, 1472004949);
        assert_eq!(real_decode.header.bits, CompactTarget::from_consensus(0x1a06d450));
        assert_eq!(real_decode.header.nonce, 1879759182);
        assert_eq!(real_decode.header.work(), work);
        assert_eq!(
            real_decode.header.validate_pow(real_decode.header.target()).unwrap(),
            real_decode.block_hash()
        );
        assert_eq!(real_decode.header.difficulty(&params), 2456598);
        assert_eq!(real_decode.header.difficulty_float(), 2456598.4399242126);

        assert_eq!(real_decode.total_size(), segwit_block.len());
        assert_eq!(real_decode.base_size(), 4283);
        assert_eq!(real_decode.weight(), Weight::from_wu(17168));

        assert!(real_decode.check_witness_commitment());

        assert_eq!(serialize(&real_decode), segwit_block);
    }

    #[test]
    fn block_version_test() {
        let block = hex!("ffffff7f0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000");
        let decode: Result<Block, _> = deserialize(&block);
        assert!(decode.is_ok());
        let real_decode = decode.unwrap();
        assert_eq!(real_decode.header.version, Version(2147483647));

        // Version bit 31 marks a Knots v2 header: 80 bytes is short by the extension,
        // and 164 bytes decodes with the flag stripped from `version`.
        let block2 = hex!("000000800000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000");
        let decode2: Result<Block, _> = deserialize(&block2);
        assert!(decode2.is_err());
        let mut block3 = block2[..Header::SIZE].to_vec();
        block3.extend_from_slice(&[0u8; HeaderV2::SIZE]);
        block3.push(0);
        let real_decode3: Block = deserialize(&block3).unwrap();
        assert_eq!(real_decode3.header.version, Version(0));
        assert!(real_decode3.header.v2.is_some());
        assert_eq!(serialize(&real_decode3), block3);
    }

    #[test]
    fn validate_pow_test() {
        let some_header = hex!("010000004ddccd549d28f385ab457e98d1b11ce80bfea2c5ab93015ade4973e400000000bf4473e53794beae34e64fccc471dace6ae544180816f89591894e0f417a914cd74d6e49ffff001d323b3a7b");
        let some_header: Header =
            deserialize(&some_header).expect("Can't deserialize correct block header");
        assert_eq!(
            some_header.validate_pow(some_header.target()).unwrap(),
            some_header.block_hash()
        );

        // test with zero target
        match some_header.validate_pow(Target::ZERO) {
            Err(ValidationError::BadTarget) => (),
            _ => panic!("unexpected result from validate_pow"),
        }

        // test with modified header
        let mut invalid_header: Header = some_header;
        invalid_header.version.0 += 1;
        match invalid_header.validate_pow(invalid_header.target()) {
            Err(ValidationError::BadProofOfWork) => (),
            _ => panic!("unexpected result from validate_pow"),
        }
    }

    #[test]
    fn compact_roundrtip_test() {
        let some_header = hex!("010000004ddccd549d28f385ab457e98d1b11ce80bfea2c5ab93015ade4973e400000000bf4473e53794beae34e64fccc471dace6ae544180816f89591894e0f417a914cd74d6e49ffff001d323b3a7b");

        let header: Header =
            deserialize(&some_header).expect("Can't deserialize correct block header");

        assert_eq!(header.bits, header.target().to_compact_lossy());
    }

    #[test]
    fn soft_fork_signalling() {
        for i in 0..31 {
            let version_int = (0x20000000u32 ^ 1 << i) as i32;
            let version = Version(version_int);
            if i < 29 {
                assert!(version.is_signalling_soft_fork(i));
            } else {
                assert!(!version.is_signalling_soft_fork(i));
            }
        }

        let segwit_signal = Version(0x20000000 ^ 1 << 1);
        assert!(!segwit_signal.is_signalling_soft_fork(0));
        assert!(segwit_signal.is_signalling_soft_fork(1));
        assert!(!segwit_signal.is_signalling_soft_fork(2));
    }
}

#[cfg(bench)]
mod benches {
    use io::sink;
    use test::{black_box, Bencher};

    use super::Block;
    use crate::consensus::{deserialize, Decodable, Encodable};

    #[bench]
    pub fn bench_stream_reader(bh: &mut Bencher) {
        let big_block = include_bytes!("../../tests/data/mainnet_block_000000000000000000000c835b2adcaedc20fdf6ee440009c249452c726dafae.raw");
        assert_eq!(big_block.len(), 1_381_836);
        let big_block = black_box(big_block);

        bh.iter(|| {
            let mut reader = &big_block[..];
            let block = Block::consensus_decode(&mut reader).unwrap();
            black_box(&block);
        });
    }

    #[bench]
    pub fn bench_block_serialize(bh: &mut Bencher) {
        let raw_block = include_bytes!("../../tests/data/mainnet_block_000000000000000000000c835b2adcaedc20fdf6ee440009c249452c726dafae.raw");

        let block: Block = deserialize(&raw_block[..]).unwrap();

        let mut data = Vec::with_capacity(raw_block.len());

        bh.iter(|| {
            let result = block.consensus_encode(&mut data);
            black_box(&result);
            data.clear();
        });
    }

    #[bench]
    pub fn bench_block_serialize_logic(bh: &mut Bencher) {
        let raw_block = include_bytes!("../../tests/data/mainnet_block_000000000000000000000c835b2adcaedc20fdf6ee440009c249452c726dafae.raw");

        let block: Block = deserialize(&raw_block[..]).unwrap();

        bh.iter(|| {
            let size = block.consensus_encode(&mut sink());
            black_box(&size);
        });
    }

    #[bench]
    pub fn bench_block_deserialize(bh: &mut Bencher) {
        let raw_block = include_bytes!("../../tests/data/mainnet_block_000000000000000000000c835b2adcaedc20fdf6ee440009c249452c726dafae.raw");

        bh.iter(|| {
            let block: Block = deserialize(&raw_block[..]).unwrap();
            black_box(&block);
        });
    }
}
