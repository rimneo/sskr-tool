# sskr-tool

This is a simple command-line wrapper for [bc-sskr-rust](https://github.com/BlockchainCommons/bc-sskr-rust),
which implements the [SSKR standard](https://github.com/BlockchainCommons/Research/blob/master/papers/bcr-2020-011-sskr.md)
for splitting and recombining secrets using Shamir's secret sharing algorithm.
Shares produced by this tool are interoperable with other SSKR implementations
such as [seedtool-cli](https://github.com/BlockchainCommons/seedtool-cli).

A common motivation for using this technique to back up a seed phrase is to
avoid storing it in a single place (thus introducing a single point of failure),
while ensuring recoverability by sufficient members of a trusted group. This is
useful for inheritance, so that family or friends can recover your funds only if
working together. This eliminates the possibility of a rogue individual stealing
the secured funds, since the group needs to work together to recover the seed
phrase.

One major downside of this approach over a multisig setup is that it requires
the mnemonic to be assembled in one place before being used. This risk is
minimized by only using this tool on an offline device and then moving the funds
after recovery, but if this is unacceptable other alternatives should be
explored.

## Installation

    $ cargo install sskr-tool

## Usage

The tool is intended to be used on a secure, offline computer. The generation
of a random mnemonic is there for convenience and testing, but should not be
relied upon for funds storage. The ideal usage of this tool is:

1. Install this tool on an offline-only computer that won't be used for anything
   else, possibly by compiling it on another computer and then copying over the
   binary.

2. Determine the group and threshold parameters that are appropriate for your
   use-case.

3. Test this tool on the offline computer, specifying the groups and group
   threshold but leaving off the mnemonic (a randomly-generated one will be used).
   For example, this invocation creates shares where either 2 from the first
   group or 3 from the second group may recover the mnemonic:

        $ sskr-tool 2of3,3of5 1

4. Attempt recovery of this random mnemonic using the tool to make sure the
   process is understood and the tool works on the intended device. For the
   example above, place a sufficient number of the generated shares in a file
   such as `shares.txt` (one per line), and then run:

        $ sskr-tool recover shares.txt

5. Verify that the mnemonic is recovered and that it matches the original.

3. Once you are comfortable with the process, generate a mnemonic using a
   dedicated hardware wallet device such as a [ColdCard](https://coldcard.com/).

3. Split the mnemonic using this tool using the same parameters as before, but
   adding the mnemonic from the hardware wallet (in quotes):

        $ sskr-tool 2of3,3of5 1 "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"

4. Engrave the shares in metal and distribute them according to your use-case,
   Making sure to indicate what they are for and provide instructions for
   recovery.

Tests are included that round-trip share splitting and recovery with a variety
of parameters. Before relying on the shares produced by this tool, test recovery
(ideally with multiple SSKR implementations).

## Share format and compatibility

Shares are written as standard Bytewords wrapping a CBOR byte string tagged
**40309** (`sskr`), the tag used by seedtool-cli and the other current
implementations of [BCR-2020-011](https://github.com/BlockchainCommons/Research/blob/master/papers/bcr-2020-011-sskr.md).

Versions up to 0.1.2 wrote tag **309** (`crypto-sskr`, version 1, now
deprecated), which seedtool-cli does not accept. Recovery accepts both tags, so
shares made by earlier versions of this tool are still recoverable. To produce
shares with the deprecated tag, for a tool that cannot read 40309, pass
`--legacy` to `split`:

    $ sskr-tool split --legacy 2of3 1

The two versions differ only in the tag; the Bytewords alphabet, the CRC, the
share metadata and the Shamir scheme are identical.
