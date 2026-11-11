mod bytewords;
mod recover;
mod split;
mod sskr_shares;
mod tags;

use bip39::Mnemonic;
use clap::{Parser, Subcommand};
use std::fs::read_to_string;
use std::process;

/// ╭───────────────────────────────────────────────────────────────────────────────────────╮
/// │                   ONLY USE THIS TOOL ON A SECURE, OFFLINE COMPUTER!                   │
/// │                   ─────────────────────────────────────────────────                   │
/// │                                                                                       │
/// │ This tool can split and recombine a BIP-39 mnemonic according to the SSKR standard.   │
/// │ More information about SSKR may be found at the following URL:                        │
/// │                                                                                       │
/// │ https://github.com/BlockchainCommons/Research/blob/master/papers/bcr-2020-011-sskr.md │
/// ╰───────────────────────────────────────────────────────────────────────────────────────╯
#[derive(Parser, Debug)]
#[clap(verbatim_doc_comment)]
struct CLI {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Splits a BIP-39 mnemonic into SSKR shares according to the spec.
    Split {
        /// Comma-separated list of M-of-N groups specifications. There can only be
        /// a maximum of 16 groups, and a maximum of 16 shares in any one group.
        ///
        /// Example: "2of3,4of9,3of5" would create three groups:
        ///     Group 1 = 2 of 3
        ///     Group 2 = 4 of 9
        ///     Group 3 = 3 of 5
        #[clap(verbatim_doc_comment)]
        spec: String,

        /// The number of groups that need to be satisfied in order recover the seed
        group_threshold: usize,

        /// A valid BIP-39 seed phrase mnemonic (12 or 24 words); random if not specified
        mnemonic: Option<String>,

        /// Write the deprecated version 1 tag (309, crypto-sskr) instead of the
        /// current one (40309, sskr). Only needed for tools that cannot read 40309.
        /// Recovery accepts both tags.
        #[clap(long)]
        legacy: bool,
    },

    /// Recovers the original BIP-39 mnemonic from SSKR shares.
    Recover {
        /// The name of a file containing the SSKR shares as bytewords, one per line
        filename: String,
    },
}

fn main() {
    match &CLI::parse().command {
        Commands::Split {
            spec,
            group_threshold,
            mnemonic,
            legacy,
        } => split(spec, group_threshold, mnemonic, *legacy),
        Commands::Recover { filename } => recover(filename),
    }
}

fn split(spec: &String, group_threshold: &usize, mnemonic: &Option<String>, legacy: bool) {
    let result = match (mnemonic, legacy) {
        (Some(phrase), false) => split::split(spec, *group_threshold, phrase),
        (None, false) => split::split_random_phrase(spec, *group_threshold),
        (Some(phrase), true) => {
            split::split_with_tag(spec, *group_threshold, phrase, tags::SSKR_SHARE_V1)
        }
        (None, true) => {
            split::split_random_phrase_with_tag(spec, *group_threshold, tags::SSKR_SHARE_V1)
        }
    };

    match result {
        Ok((mnemonic, groups)) => split_success(spec, group_threshold, mnemonic, groups),
        Err(error) => {
            eprintln!("Error splitting mnemonic: {:?}", error);
            process::exit(1);
        }
    }
}

fn split_success(
    spec: &String,
    group_threshold: &usize,
    mnemonic: Mnemonic,
    groups: Vec<Vec<String>>,
) {
    println!("Entropy:  0x{}", hex::encode(mnemonic.entropy()));
    println!("Mnemonic: {}", mnemonic.phrase());
    println!();
    println!(
        "SSKR shares - need to recover at least {} group(s) to recover mnemonic\n",
        group_threshold
    );
    for ((group_num, group), group_spec) in groups.iter().enumerate().zip(spec.split(",")) {
        println!(
            "Group {} - need {} shares to recover group",
            group_num + 1,
            group_spec.replace("of", " of ")
        );
        for (share_num, share) in group.iter().enumerate() {
            println!(
                "  {}{}: {}",
                if group.len() > 9 && share_num < 9 {
                    " "
                } else {
                    ""
                },
                share_num + 1,
                share
            );
        }
        println!();
    }
}

fn recover(filename: &String) {
    let file_contents = read_to_string(filename);

    if let Err(error) = file_contents {
        eprintln!("Error reading file \"{}\": {}", filename, error);
        process::exit(1);
    }

    let lines = file_contents.unwrap().lines().map(String::from).collect();

    match recover::recover(lines) {
        Ok(mnemonic) => recover_success(mnemonic),
        Err(error) => {
            eprintln!("Error recovering mnemonic: {:?}", error);
            process::exit(1);
        }
    }
}

fn recover_success(mnemonic: Mnemonic) {
    println!("Entropy:  0x{}", hex::encode(mnemonic.entropy()));
    println!("Mnemonic: {}", mnemonic.phrase());
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Error;
    use rand::prelude::SliceRandom;
    use rand::seq::IteratorRandom;
    use rand::Rng;

    static TEST_ITERATIONS: usize = 50000;

    #[test]
    fn test_roundtrip_all_full_groups() -> Result<(), Error> {
        for _ in 0..TEST_ITERATIONS {
            let (spec, _sizes, group_threshold) = gen_random_params();
            let (mnemonic, groups) = split::split_random_phrase(&spec, group_threshold)?;
            ensure_recoverable(&mnemonic, groups.into_iter().flatten().collect())?;
        }
        Ok(())
    }

    #[test]
    fn test_roundtrip_all_sufficient_groups() -> Result<(), Error> {
        for _ in 0..TEST_ITERATIONS {
            let (spec, sizes, group_threshold) = gen_random_params();
            let (mnemonic, groups) = split::split_random_phrase(&spec, group_threshold)?;
            ensure_recoverable(
                &mnemonic,
                groups
                    .into_iter()
                    .zip(sizes.into_iter())
                    .map(|(group, (m, _n))| {
                        group
                            .into_iter()
                            .choose_multiple(&mut rand::thread_rng(), m)
                    })
                    .flatten()
                    .collect(),
            )?;
        }
        Ok(())
    }

    #[test]
    fn test_roundtrip_all_insufficient_groups() -> Result<(), Error> {
        for _ in 0..TEST_ITERATIONS {
            let (spec, sizes, group_threshold) = gen_random_params();
            let (_mnemonic, groups) = split::split_random_phrase(&spec, group_threshold)?;
            let mut shares: Vec<String> = groups
                .into_iter()
                .zip(sizes.into_iter())
                .map(|(group, (m, _n))| {
                    group
                        .into_iter()
                        .choose_multiple(&mut rand::thread_rng(), m - 1)
                })
                .flatten()
                .collect();
            if shares.len() == 0 {
                continue;
            }
            shares.shuffle(&mut rand::thread_rng());
            ensure_unrecoverable(shares);
        }
        Ok(())
    }

    #[test]
    fn test_roundtrip_enough_full_groups() -> Result<(), Error> {
        for _ in 0..TEST_ITERATIONS {
            let (spec, _sizes, group_threshold) = gen_random_params();
            let (mnemonic, groups) = split::split_random_phrase(&spec, group_threshold)?;
            ensure_recoverable(
                &mnemonic,
                groups
                    .into_iter()
                    .choose_multiple(&mut rand::thread_rng(), group_threshold)
                    .into_iter()
                    .flatten()
                    .collect(),
            )?;
        }
        Ok(())
    }

    #[test]
    fn test_roundtrip_enough_sufficient_groups() -> Result<(), Error> {
        for _ in 0..TEST_ITERATIONS {
            let (spec, sizes, group_threshold) = gen_random_params();
            let (mnemonic, groups) = split::split_random_phrase(&spec, group_threshold)?;
            let mut shares: Vec<String> = groups
                .into_iter()
                .zip(sizes.into_iter())
                .map(|(group, (m, _n))| {
                    group
                        .into_iter()
                        .choose_multiple(&mut rand::thread_rng(), m)
                })
                .choose_multiple(&mut rand::thread_rng(), group_threshold)
                .into_iter()
                .flatten()
                .collect();
            shares.shuffle(&mut rand::thread_rng());
            ensure_recoverable(&mnemonic, shares)?;
        }
        Ok(())
    }

    #[test]
    fn test_roundtrip_enough_sufficient_groups_minus_one() -> Result<(), Error> {
        for _ in 0..TEST_ITERATIONS {
            let (spec, sizes, group_threshold) = gen_random_params();
            let (_mnemonic, groups) = split::split_random_phrase(&spec, group_threshold)?;
            let mut shares = groups
                .into_iter()
                .zip(sizes.into_iter())
                .map(|(group, (m, _n))| {
                    group
                        .into_iter()
                        .choose_multiple(&mut rand::thread_rng(), m)
                })
                .choose_multiple(&mut rand::thread_rng(), group_threshold)
                .into_iter()
                .flatten()
                .collect::<Vec<String>>();
            if shares.len() == 1 {
                continue;
            }
            shares.shuffle(&mut rand::thread_rng());
            ensure_unrecoverable(shares.split_last().unwrap().1.to_vec());
        }
        Ok(())
    }

    #[test]
    fn test_roundtrip_enough_insufficient_groups() -> Result<(), Error> {
        for _ in 0..TEST_ITERATIONS {
            let (spec, sizes, group_threshold) = gen_random_params();
            let (_mnemonic, groups) = split::split_random_phrase(&spec, group_threshold)?;
            let mut shares: Vec<String> = groups
                .into_iter()
                .zip(sizes.into_iter())
                .map(|(group, (m, _n))| {
                    group
                        .into_iter()
                        .choose_multiple(&mut rand::thread_rng(), m - 1)
                })
                .choose_multiple(&mut rand::thread_rng(), group_threshold)
                .into_iter()
                .flatten()
                .collect();
            if shares.len() == 0 {
                continue;
            }
            shares.shuffle(&mut rand::thread_rng());
            ensure_unrecoverable(shares);
        }
        Ok(())
    }

    #[test]
    fn test_roundtrip_not_enough_full_groups() -> Result<(), Error> {
        for _ in 0..TEST_ITERATIONS {
            let (spec, _sizes, group_threshold) = gen_random_params();
            let (_mnemonic, groups) = split::split_random_phrase(&spec, group_threshold)?;
            let mut shares: Vec<String> = groups
                .into_iter()
                .choose_multiple(&mut rand::thread_rng(), group_threshold - 1)
                .into_iter()
                .flatten()
                .collect();
            if shares.len() == 0 {
                continue;
            }
            shares.shuffle(&mut rand::thread_rng());
            ensure_unrecoverable(shares);
        }
        Ok(())
    }

    #[test]
    fn test_roundtrip_not_enough_sufficient_groups() -> Result<(), Error> {
        for _ in 0..TEST_ITERATIONS {
            let (spec, sizes, group_threshold) = gen_random_params();
            let (_mnemonic, groups) = split::split_random_phrase(&spec, group_threshold)?;
            let mut shares: Vec<String> = groups
                .into_iter()
                .zip(sizes.into_iter())
                .map(|(group, (m, _n))| {
                    group
                        .into_iter()
                        .choose_multiple(&mut rand::thread_rng(), m)
                })
                .choose_multiple(&mut rand::thread_rng(), group_threshold - 1)
                .into_iter()
                .flatten()
                .collect();
            if shares.len() == 0 {
                continue;
            }
            shares.shuffle(&mut rand::thread_rng());
            ensure_unrecoverable(shares);
        }
        Ok(())
    }

    #[test]
    fn test_roundtrip_not_enough_insufficient_groups() -> Result<(), Error> {
        for _ in 0..TEST_ITERATIONS {
            let (spec, sizes, group_threshold) = gen_random_params();
            let (_mnemonic, groups) = split::split_random_phrase(&spec, group_threshold)?;
            let mut shares: Vec<String> = groups
                .into_iter()
                .zip(sizes.into_iter())
                .map(|(group, (m, _n))| {
                    group
                        .into_iter()
                        .choose_multiple(&mut rand::thread_rng(), m - 1)
                })
                .choose_multiple(&mut rand::thread_rng(), group_threshold - 1)
                .into_iter()
                .flatten()
                .collect();
            if shares.len() == 0 {
                continue;
            }
            shares.shuffle(&mut rand::thread_rng());
            ensure_unrecoverable(shares);
        }
        Ok(())
    }

    fn ensure_recoverable(expected: &Mnemonic, shares: Vec<String>) -> Result<(), Error> {
        let recovered = recover::recover(shares)?;
        assert_eq!(recovered.phrase(), expected.phrase());
        Ok(())
    }

    fn ensure_unrecoverable(shares: Vec<String>) {
        let recovered = recover::recover(shares);
        assert!(recovered.is_err());
    }

    fn gen_random_params() -> (String, Vec<(usize, usize)>, usize) {
        let total_groups = rand::thread_rng().gen_range(1..=16);
        let group_threshold = rand::thread_rng().gen_range(1..=total_groups);
        let sizes: Vec<_> = (0..total_groups)
            .map(|_| {
                let n = rand::thread_rng().gen_range(1..=16);
                let m = if n == 1 {
                    1
                } else {
                    rand::thread_rng().gen_range(2..=n)
                };
                (m, n)
            })
            .collect();
        let spec = sizes
            .iter()
            .map(|(m, n)| format!("{}of{}", m, n))
            .collect::<Vec<String>>()
            .join(",");
        (spec, sizes, group_threshold)
    }
}
