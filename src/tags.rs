//! CBOR tags used to wrap SSKR shares.
//!
//! BCR-2020-011 describes two generations of the share encoding. They differ
//! only in the CBOR tag (and the UR type); the Bytewords alphabet, the CRC-32,
//! the share metadata and the Shamir scheme are the same.

/// Current tag, registered as `sskr`. Written by default and accepted on input.
/// This is the tag SeedTool and the Blockchain Commons libraries use.
pub const SSKR_SHARE: u64 = 40309;

/// Version 1 tag, registered as `crypto-sskr` (deprecated). Accepted on input
/// so that shares written by earlier versions of this tool can still be
/// recovered; written only with `--legacy`.
pub const SSKR_SHARE_V1: u64 = 309;

/// Whether `tag` is one of the two tags a share may carry.
pub fn is_share_tag(tag: u64) -> bool {
    tag == SSKR_SHARE || tag == SSKR_SHARE_V1
}
