use crate::bytewords::*;
use crate::sskr_shares::*;
use crate::tags;
use anyhow::{anyhow, bail, Error};
use bip39::{Language, Mnemonic};
use dcbor::CBOR;
use sskr::sskr_combine;
use std::collections::HashMap;

pub fn recover(lines: Vec<String>) -> Result<Mnemonic, Error> {
    let mut shares: Vec<Vec<u8>> = vec![];

    // Get shares from raw strings
    for line in lines {
        // Parse bytewords and strip byteword-level checksum
        let bytes = byteword_string_to_bytes(line)?;

        // Unwrap data from CBOR container
        // Both the current tag (40309) and the deprecated version 1 tag (309) are
        // accepted, each share independently, so older shares remain recoverable.
        let cbor = CBOR::from_data(bytes.as_slice())?;
        let Some((tag, cbor_bytes)) = cbor.as_tagged_value() else {
            bail!("Share is not a tagged CBOR value");
        };
        if !tags::is_share_tag(tag.value()) {
            bail!(
                "Unsupported CBOR tag {} (expected {} or {})",
                tag.value(),
                tags::SSKR_SHARE,
                tags::SSKR_SHARE_V1
            );
        }
        let share = cbor_bytes.expect_byte_string()?;

        // Retain share data
        shares.push(share.to_vec());
    }

    // Parse out metadata from each share
    let mut share_ids: Vec<u16> = vec![];
    let mut share_meta: Vec<[usize; 5]> = vec![];
    for share in shares.clone() {
        let (id, meta) = share_metadata(&share)?;
        share_ids.push(id);
        share_meta.push(meta);
    }

    // (id, threshold, count) => Vec<share_index>
    let mut shares_by_universe: HashMap<(u16, usize, usize), Vec<usize>> = HashMap::new();

    for i in 0..shares.len() {
        let key = (share_ids[i], share_meta[i][1], share_meta[i][2]);
        if !shares_by_universe.contains_key(&key) {
            shares_by_universe.insert(key, vec![]);
        }

        shares_by_universe.get_mut(&key).unwrap().push(i);
    }

    for ((identifier, group_threshold, _group_count), share_indices) in &shares_by_universe {
        // Group shares by group in the form { group_num => Vec<(share_index, share)> }
        let mut shares_by_group: HashMap<usize, Vec<(usize, Vec<u8>)>> = HashMap::new();
        for &i in share_indices {
            let share_group_num = share_meta[i][0];

            if !shares_by_group.contains_key(&share_group_num) {
                shares_by_group.insert(share_group_num, vec![]);
            }

            shares_by_group
                .get_mut(&share_group_num)
                .unwrap()
                .push((i, shares[i].to_vec()));
        }

        // See how many groups are recoverable
        let mut recoverable_groups: Vec<usize> = vec![];

        // Look through the groups one-by-one to validate and gather information
        for (group_num, shares) in &shares_by_group {
            // Make sure the member threshold is the same for all shares in the group
            let member_threshold = share_meta[shares[0].0][4];
            if shares
                .iter()
                .any(|(i, _share)| share_meta[*i][4] != member_threshold)
            {
                bail!(
                    "Mismatched share member thresholds in group {}, shares don't go together",
                    group_num + 1
                );
            }

            // See whether this group is recoverable
            if shares.len() >= member_threshold {
                recoverable_groups.push(*group_num);
            }
        }

        // Make sure there are enough groups to recover the secret
        if recoverable_groups.len() < *group_threshold {
            println!(
                "{}: Not enough groups, need to satisfy at least {} but only {} are satisfied ({})",
                identifier,
                group_threshold,
                recoverable_groups.len(),
                recoverable_groups
                    .iter()
                    .map(|g| (g + 1).to_string())
                    .collect::<Vec<String>>()
                    .join(" and ")
            );
            continue;
        }

        let mut shares_for_recovery: Vec<Vec<u8>> = vec![];

        // Gather shares from enough theoretically-recoverable groups
        for group_num in recoverable_groups.iter().take(*group_threshold) {
            // Get just the shares without the group number
            let group_shares = shares_by_group[&group_num]
                .iter()
                .map(|(_i, share)| share.to_vec())
                .collect::<Vec<Vec<u8>>>();

            for share in group_shares {
                shares_for_recovery.push(share);
            }
        }

        match sskr_combine(&shares_for_recovery) {
            Ok(secret) => match Mnemonic::from_entropy(secret.data(), Language::English) {
                Ok(mnemonic) => {
                    println!("{}: Successfully recovered!", identifier);
                    return Ok(mnemonic);
                }
                Err(e) => {
                    println!(
                        "{}: Recovered entropy 0x{} but unable to make mnemonic: {}",
                        identifier,
                        hex::encode(secret.data()),
                        e
                    );
                    continue;
                }
            },
            Err(e) => {
                println!("{}: Error during SSKR combination: {}", identifier, e);
                continue;
            }
        }
    }

    Err(anyhow!(
        "Not enough shares that belong together, unable to recover :("
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use dcbor::{CBOREncodable, CBOR};

    // BCR-2020-011 test vector: secret 7daa851251002874e1a1995f0897e6b1,
    // two groups (2 shares from the first, 3 from the second).
    const VECTOR_SHARES: [&str; 5] = [
        "4bbf1101003e990c1f0435e2b33c721535c74603d0",
        "4bbf1101010c8ba39a7502a325ed07b8d597d1b80f",
        "4bbf11120044ef453f66923d32653b377de5c94b39",
        "4bbf1112016ffb1b0cc5ab485f5a67136c802bc67b",
        "4bbf111202a3763155fcfdb5887abce6ee69c4bbcd",
    ];
    const VECTOR_ENTROPY: &str = "7daa851251002874e1a1995f0897e6b1";

    fn line(share_hex: &str, tag: u64) -> String {
        let share = hex::decode(share_hex).unwrap();
        let cbor = CBOR::tagged_value(tag, CBOR::byte_string(share));
        byteword_string(cbor.cbor_data().as_slice())
    }

    fn lines(tags: [u64; 5]) -> Vec<String> {
        VECTOR_SHARES
            .iter()
            .zip(tags)
            .map(|(share, tag)| line(share, tag))
            .collect()
    }

    #[test]
    fn recovers_official_vector_with_current_tag() {
        let m = recover(lines([tags::SSKR_SHARE; 5])).unwrap();
        assert_eq!(hex::encode(m.entropy()), VECTOR_ENTROPY);
    }

    #[test]
    fn recovers_official_vector_with_version_1_tag() {
        let m = recover(lines([tags::SSKR_SHARE_V1; 5])).unwrap();
        assert_eq!(hex::encode(m.entropy()), VECTOR_ENTROPY);
    }

    #[test]
    fn recovers_shares_mixing_both_tags() {
        let m = recover(lines([40309, 309, 40309, 309, 40309])).unwrap();
        assert_eq!(hex::encode(m.entropy()), VECTOR_ENTROPY);
    }

    #[test]
    fn rejects_unknown_tag() {
        let err = recover(lines([1000; 5])).unwrap_err().to_string();
        assert!(err.contains("Unsupported CBOR tag 1000"), "{}", err);
    }

    #[test]
    fn rejects_untagged_share() {
        let share = hex::decode(VECTOR_SHARES[0]).unwrap();
        let untagged = byteword_string(CBOR::byte_string(share).cbor_data().as_slice());
        let err = recover(vec![untagged]).unwrap_err().to_string();
        assert!(err.contains("not a tagged CBOR value"), "{}", err);
    }
}
