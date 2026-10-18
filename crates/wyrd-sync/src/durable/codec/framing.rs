//! Commit envelope: hashing, encoding, and verification of the
//! commit file. Knows the tag registry and the fact decoder, never
//! what any fact means.

use super::facts::{decode_record, DecodedFact};
use super::tags::{
    COMMIT_HASH_DOMAIN, COMMIT_VERSION, HEADER_LEN, KNOWN_TAGS, MAX_RECORDS_PER_COMMIT,
    MAX_RECORD_BYTES,
};
use crate::durable::DurableError;
use wyrd_format::DriveId;

/// The chain hash of one commit: domain tag, drive id, sequence,
/// previous hash, and the exact serialized records section. Binds
/// integrity and ordering; confidentiality is not the point (secrets
/// carry their own AEAD inside capability records).
fn commit_hash(drive: &DriveId, seq: u64, prev: &[u8; 32], records: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(COMMIT_HASH_DOMAIN);
    hasher.update(drive.as_bytes());
    hasher.update(&seq.to_le_bytes());
    hasher.update(prev);
    hasher.update(records);
    *hasher.finalize().as_bytes()
}

/// Serialize one commit and hash it: header (version, sequence,
/// previous hash) + records + trailer hash. Crate-visible for the
/// raw-commit test seam alongside `TAG_SNAPSHOT_BODY`.
pub(crate) fn encode_commit(
    drive: &DriveId,
    seq: u64,
    prev: &[u8; 32],
    records: &[(u8, Vec<u8>)],
) -> (Vec<u8>, [u8; 32]) {
    let mut records_bytes = Vec::new();
    records_bytes.extend_from_slice(&(records.len() as u32).to_le_bytes());
    for (tag, record) in records {
        records_bytes.push(*tag);
        records_bytes.extend_from_slice(&(record.len() as u32).to_le_bytes());
        records_bytes.extend_from_slice(record);
    }
    let hash = commit_hash(drive, seq, prev, &records_bytes);
    let mut out = Vec::with_capacity(HEADER_LEN + records_bytes.len() + 32);
    out.push(COMMIT_VERSION);
    out.extend_from_slice(&seq.to_le_bytes());
    out.extend_from_slice(prev);
    out.extend_from_slice(&records_bytes);
    out.extend_from_slice(&hash);
    (out, hash)
}

/// Decode and verify one commit file, returning the decoded facts and
/// the verified trailer hash. Every structural failure — wrong version,
/// sequence or previous-hash mismatch, over-limit counts or lengths,
/// malformed known records, trailing bytes, a hash mismatch — fails the
/// file: inside the committed prefix there is no such thing as an
/// ignorable commit. Unknown record tags are the only skips, for
/// forward compatibility.
pub(crate) fn decode_commit_file(
    drive: &DriveId,
    store_key: &[u8],
    bytes: &[u8],
    seq: u64,
    prev_hash: &[u8; 32],
) -> Result<(Vec<DecodedFact>, [u8; 32]), DurableError> {
    let corrupt = || DurableError::CorruptCommit(seq);
    let mut pos = 0usize;
    let take = |pos: &mut usize, n: usize| -> Option<&[u8]> {
        let end = pos.checked_add(n)?;
        if end > bytes.len() {
            return None;
        }
        let slice = &bytes[*pos..end];
        *pos = end;
        Some(slice)
    };
    if take(&mut pos, 1).ok_or_else(&corrupt)? != [COMMIT_VERSION] {
        return Err(corrupt());
    }
    if u64::from_le_bytes(
        take(&mut pos, 8)
            .ok_or_else(&corrupt)?
            .try_into()
            .expect("take"),
    ) != seq
    {
        return Err(corrupt());
    }
    if take(&mut pos, 32).ok_or_else(&corrupt)? != prev_hash {
        return Err(corrupt());
    }
    let count = u32::from_le_bytes(
        take(&mut pos, 4)
            .ok_or_else(&corrupt)?
            .try_into()
            .expect("take"),
    ) as usize;
    if count > MAX_RECORDS_PER_COMMIT {
        return Err(corrupt());
    }
    let mut out = Vec::with_capacity(count.min(1024));
    for _ in 0..count {
        let tag = take(&mut pos, 1).ok_or_else(&corrupt)?[0];
        let len = u32::from_le_bytes(
            take(&mut pos, 4)
                .ok_or_else(&corrupt)?
                .try_into()
                .expect("take"),
        ) as usize;
        if len > MAX_RECORD_BYTES {
            return Err(corrupt());
        }
        let record = take(&mut pos, len).ok_or_else(&corrupt)?.to_vec();
        if !KNOWN_TAGS.contains(&tag) {
            continue;
        }
        let fact = decode_record(drive, store_key, tag, &record).ok_or_else(&corrupt)?;
        out.push(fact);
    }
    // The trailer hash sits exactly at the end: no trailing bytes.
    if pos.checked_add(32) != Some(bytes.len()) {
        return Err(corrupt());
    }
    let expected = commit_hash(drive, seq, prev_hash, &bytes[HEADER_LEN..pos]);
    let trailer: &[u8; 32] = bytes[pos..].try_into().expect("trailer bounds");
    if trailer != &expected {
        return Err(corrupt());
    }
    Ok((out, expected))
}
