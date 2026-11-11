use crate::bytewords::byteword_string;
use crate::tags;
use anyhow::{anyhow, bail, Error};
use bip39::{Language, Mnemonic, MnemonicType};
use dcbor::{CBOREncodable, CBOR};
use lazy_static::lazy_static;
use regex::Regex;
use sskr::{sskr_generate, GroupSpec, Secret, Spec};

lazy_static! {
    static ref SPEC_REGEX: Regex = Regex::new(r"^((\d+of\d+),)*\d+of\d+$").unwrap();
    static ref SPEC_GROUP_REGEX: Regex = Regex::new(r"(?<m>\d+)of(?<n>\d+)").unwrap();
}

/// Splits `phrase`, wrapping the shares with the current tag (40309).
pub fn split(
    spec: &String,
    group_threshold: usize,
    phrase: &String,
) -> Result<(Mnemonic, Vec<Vec<String>>), Error> {
    split_with_tag(spec, group_threshold, phrase, tags::SSKR_SHARE)
}

/// Splits `phrase`, wrapping the shares with `tag`.
pub fn split_with_tag(
    spec: &String,
    group_threshold: usize,
    phrase: &String,
    tag: u64,
) -> Result<(Mnemonic, Vec<Vec<String>>), Error> {
    let sskr_spec = parse_spec(spec, group_threshold)?;
    let mnemonic = Mnemonic::from_phrase(phrase, Language::English)?;
    let entropy = mnemonic.entropy();
    let secret = Secret::new(entropy)?;
    let groups = sskr_generate(&sskr_spec, &secret)?;
    let byteword_groups = to_bytewords(&groups, tag);
    Ok((mnemonic, byteword_groups))
}

pub fn split_random_phrase(
    spec: &String,
    group_threshold: usize,
) -> Result<(Mnemonic, Vec<Vec<String>>), Error> {
    split_random_phrase_with_tag(spec, group_threshold, tags::SSKR_SHARE)
}

pub fn split_random_phrase_with_tag(
    spec: &String,
    group_threshold: usize,
    tag: u64,
) -> Result<(Mnemonic, Vec<Vec<String>>), Error> {
    let mnemonic = Mnemonic::new(MnemonicType::Words12, Language::English);
    split_with_tag(spec, group_threshold, &mnemonic.phrase().to_string(), tag)
}

fn to_bytewords(groups: &Vec<Vec<Vec<u8>>>, tag: u64) -> Vec<Vec<String>> {
    groups
        .iter()
        .map(|shares| {
            shares
                .iter()
                .map(|share| {
                    let cbor = CBOR::tagged_value(tag, CBOR::byte_string(share));
                    byteword_string(cbor.cbor_data().as_slice())
                })
                .collect()
        })
        .collect()
}

fn parse_spec(spec: &String, group_threshold: usize) -> Result<Spec, Error> {
    if !SPEC_REGEX.is_match(spec) {
        bail!("Invalid group spec");
    }

    let mut group_specs: Vec<GroupSpec> = vec![];

    for part in spec.split(",") {
        let Some(group_match) = SPEC_GROUP_REGEX.captures(&part) else {
            bail!("Invalid group \"{}\" in spec", &part);
        };

        let m = group_match["m"].parse()?;
        let n = group_match["n"].parse()?;

        if m > n {
            bail!(
                "Invalid group \"{}\" in spec ({} is greater than {})",
                &part,
                m,
                n
            );
        }

        if m == 1 && n > 1 {
            bail!(
                "Invalid group \"{}\" in spec: 1 of N groups (where N > 1) not supported",
                &part
            );
        }

        group_specs.push(
            GroupSpec::new(m, n)
                .map_err(|e| anyhow!("Error making group spec for group \"{}\": {}", &part, e))?,
        );
    }

    Ok(Spec::new(group_threshold, group_specs)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bytewords::byteword_string_to_bytes;
    use crate::recover::recover;

    fn tags_of(groups: &Vec<Vec<String>>) -> Vec<u64> {
        groups
            .iter()
            .flatten()
            .map(|line| {
                let bytes = byteword_string_to_bytes(line.clone()).unwrap();
                let cbor = CBOR::from_data(bytes.as_slice()).unwrap();
                cbor.as_tagged_value().unwrap().0.value()
            })
            .collect()
    }

    #[test]
    fn writes_current_tag_by_default() {
        let (_, groups) = split_random_phrase(&"2of3".to_string(), 1).unwrap();
        assert!(tags_of(&groups).iter().all(|t| *t == 40309));
    }

    #[test]
    fn writes_version_1_tag_when_asked() {
        let (_, groups) =
            split_random_phrase_with_tag(&"2of3".to_string(), 1, tags::SSKR_SHARE_V1).unwrap();
        assert!(tags_of(&groups).iter().all(|t| *t == 309));
    }

    #[test]
    fn shares_of_either_tag_recover_the_same_mnemonic() {
        for tag in [tags::SSKR_SHARE, tags::SSKR_SHARE_V1] {
            let (mnemonic, groups) =
                split_random_phrase_with_tag(&"2of3,2of3".to_string(), 2, tag).unwrap();
            let lines: Vec<String> = vec![
                groups[0][0].clone(),
                groups[0][1].clone(),
                groups[1][0].clone(),
                groups[1][2].clone(),
            ];
            assert_eq!(recover(lines).unwrap().phrase(), mnemonic.phrase());
        }
    }
}
