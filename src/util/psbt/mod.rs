//! # Partially Signed Transactions
//!
//! Implementation of BIP174 Partially Signed Bitcoin Transaction Format as
//! defined at https://github.com/bitcoin/bips/blob/master/bip-0174.mediawiki
//! except we define PSBTs containing non-standard SigHash types as invalid.

use blockdata::transaction::Transaction;
use consensus::encode::{self, Encodable, Decodable, Encoder, Decoder};

mod error;
pub use self::error::Error;

pub mod raw;

#[macro_use]
mod macros;

pub mod serialize;

mod map;
pub use self::map::{Map, Global, Input, Output};

/// A Partially Signed Transaction.
#[derive(Debug, Clone, PartialEq)]
pub struct PartiallySignedTransaction {
    /// The key-value pairs for all global data.
    global: Global,
    /// The corresponding key-value map for each input in the unsigned
    /// transaction.
    inputs: Vec<Input>,
    /// The corresponding key-value map for each output in the unsigned
    /// transaction.
    outputs: Vec<Output>,
}

impl PartiallySignedTransaction {
    /// Create a PartiallySignedTransaction from an unsigned transaction, error
    /// if not unsigned
    pub fn from_unsigned_tx(tx: Transaction) -> Result<Self, encode::Error> {
        Ok(PartiallySignedTransaction {
            inputs: vec![Default::default(); tx.input.len()],
            outputs: vec![Default::default(); tx.output.len()],
            global: Global::from_unsigned_tx(tx)?,
        })
    }

    /// Extract a Transaction from a finalized PartiallySignedTransaction
    pub fn extract_tx(self) -> Transaction {
        let mut tx: Transaction = self.global.unsigned_tx;

        for (vin, psbtin) in tx.input.iter_mut().zip(self.inputs.into_iter()) {
            vin.script_sig = psbtin.final_script_sig.unwrap();
            vin.witness = psbtin.final_script_witness.unwrap();
        }

        tx
    }

    /// Attempt to merge with another `PartiallySignedTransaction`.
    pub fn merge(&mut self, other: Self) -> Result<(), self::Error> {
        self.global.merge(other.global)?;

        for (self_input, other_input) in self.inputs.iter_mut().zip(other.inputs.into_iter()) {
            self_input.merge(other_input)?;
        }

        for (self_output, other_output) in self.outputs.iter_mut().zip(other.outputs.into_iter()) {
            self_output.merge(other_output)?;
        }

        Ok(())
    }
}

impl<S: Encoder> Encodable<S> for PartiallySignedTransaction {
    fn consensus_encode(&self, s: &mut S) -> Result<(), encode::Error> {
        b"psbt".consensus_encode(s)?;

        0xff_u8.consensus_encode(s)?;

        self.global.consensus_encode(s)?;

        for i in &self.inputs {
            i.consensus_encode(s)?;
        }

        for i in &self.outputs {
            i.consensus_encode(s)?;
        }

        Ok(())
    }
}

impl<D: Decoder> Decodable<D> for PartiallySignedTransaction {
    fn consensus_decode(d: &mut D) -> Result<Self, encode::Error> {
        let magic: [u8; 4] = Decodable::consensus_decode(d)?;

        if *b"psbt" != magic {
            return Err(Error::InvalidMagic.into());
        }

        if 0xff_u8 != Decodable::consensus_decode(d)? {
            return Err(Error::InvalidSeparator.into());
        }

        let global: Global = Decodable::consensus_decode(d)?;

        let inputs: Vec<Input> = {
            let inputs_len: usize = (&global.unsigned_tx.input).len();

            let mut inputs: Vec<Input> = Vec::with_capacity(inputs_len);

            for _ in 0..inputs_len {
                inputs.push(Decodable::consensus_decode(d)?);
            }

            inputs
        };

        let outputs: Vec<Output> = {
            let outputs_len: usize = (&global.unsigned_tx.output).len();

            let mut outputs: Vec<Output> = Vec::with_capacity(outputs_len);

            for _ in 0..outputs_len {
                outputs.push(Decodable::consensus_decode(d)?);
            }

            outputs
        };

        Ok(PartiallySignedTransaction {
            global: global,
            inputs: inputs,
            outputs: outputs,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use hex::decode as hex_decode;

    use secp256k1::{PublicKey, Secp256k1};

    use blockdata::script::Script;
    use blockdata::transaction::{Transaction, TxIn, TxOut, OutPoint};
    use network::constants::Network::Bitcoin;
    use consensus::encode::{deserialize, serialize, serialize_hex};
    use util::bip32::{ChildNumber, ExtendedPrivKey, ExtendedPubKey, Fingerprint};
    use util::hash::Sha256dHash;
    use util::psbt::map::{Global, Output};
    use util::psbt::raw;

    use super::PartiallySignedTransaction;

    #[test]
    fn trivial_psbt() {
        let psbt = PartiallySignedTransaction {
            global: Global {
                unsigned_tx: Transaction {
                    version: 2,
                    lock_time: 0,
                    input: vec![],
                    output: vec![],
                },
                unknown: HashMap::new(),
            },
            inputs: vec![],
            outputs: vec![],
        };
        assert_eq!(
            serialize_hex(&psbt),
            "70736274ff01000a0200000000000000000000"
        );
    }

    #[test]
    fn serialize_then_deserialize_output() {
        let secp = &Secp256k1::new();
        let seed = hex_decode("000102030405060708090a0b0c0d0e0f").unwrap();

        let mut hd_keypaths: HashMap<PublicKey, (Fingerprint, Vec<ChildNumber>)> = Default::default();

        let mut sk: ExtendedPrivKey = ExtendedPrivKey::new_master(secp, Bitcoin, &seed).unwrap();

        let fprint: Fingerprint = sk.fingerprint(&secp);

        let dpath: Vec<ChildNumber> = vec![
            ChildNumber::from_normal_idx(0),
            ChildNumber::from_normal_idx(1),
            ChildNumber::from_normal_idx(2),
            ChildNumber::from_normal_idx(4),
            ChildNumber::from_normal_idx(42),
            ChildNumber::from_hardened_idx(69),
            ChildNumber::from_normal_idx(420),
            ChildNumber::from_normal_idx(31337),
        ];

        sk = sk.derive_priv(secp, &dpath).unwrap();

        let pk: ExtendedPubKey = ExtendedPubKey::from_private(&secp, &sk);

        hd_keypaths.insert(pk.public_key, (fprint, dpath));

        let expected: Output = Output {
            redeem_script: Some(hex_script!(
                "76a914d0c59903c5bac2868760e90fd521a4665aa7652088ac"
            )),
            witness_script: Some(hex_script!(
                "a9143545e6e33b832c47050f24d3eeb93c9c03948bc787"
            )),
            hd_keypaths: hd_keypaths,
            ..Default::default()
        };

        let actual: Output = deserialize(&serialize(&expected)).unwrap();

        assert_eq!(expected, actual);
    }

    #[test]
    fn serialize_then_deserialize_global() {
        let expected = Global {
            unsigned_tx: Transaction {
                version: 2,
                lock_time: 1257139,
                input: vec![TxIn {
                    previous_output: OutPoint {
                        txid: Sha256dHash::from_hex(
                            "f61b1742ca13176464adb3cb66050c00787bb3a4eead37e985f2df1e37718126",
                        ).unwrap(),
                        vout: 0,
                    },
                    script_sig: Script::new(),
                    sequence: 4294967294,
                    witness: vec![],
                }],
                output: vec![
                    TxOut {
                        value: 99999699,
                        script_pubkey: hex_script!(
                            "76a914d0c59903c5bac2868760e90fd521a4665aa7652088ac"
                        ),
                    },
                    TxOut {
                        value: 100000000,
                        script_pubkey: hex_script!(
                            "a9143545e6e33b832c47050f24d3eeb93c9c03948bc787"
                        ),
                    },
                ],
            },
            unknown: Default::default(),
        };

        let actual: Global = deserialize(&serialize(&expected)).unwrap();

        assert_eq!(expected, actual);
    }

    #[test]
    fn serialize_then_deserialize_psbtkvpair() {
        let expected = raw::Pair {
            key: raw::Key {
                type_value: 0u8,
                key: vec![42u8, 69u8],
            },
            value: vec![69u8, 42u8, 4u8],
        };

        let actual: raw::Pair = deserialize(&serialize(&expected)).unwrap();

        assert_eq!(expected, actual);
    }
}
