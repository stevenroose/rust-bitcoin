// Written in 2014 by Andrew Poelstra <apoelstra@wpsoftware.net>
// SPDX-License-Identifier: CC0-1.0

//! Bitcoin hash functions.
//!
//! This module provides utility functions related to hashing data, including
//! merkleization.
//!

use core::{fmt, iter};

use crate::prelude::*;

use crate::io;
use core::cmp::min;

use crate::hashes::Hash;
use crate::consensus::encode::Encodable;

/// Calculates the merkle root of a list of *hashes*, inline (in place) in `hashes`.
///
/// In most cases, you'll want to use [bitcoin_merkle_root] instead.
///
/// # Returns
/// - `None` if `hashes` is empty. The merkle root of an empty tree of hashes is undefined.
/// - `Some(hash)` if `hashes` contains one element. A single hash is by definition the merkle root.
/// - `Some(merkle_root)` if length of `hashes` is greater than one.
pub fn bitcoin_merkle_root_inline<T>(hashes: &mut [T]) -> Option<T>
where
    T: Hash + Encodable,
          <T as Hash>::Engine: io::Write,
{
    match hashes.len() {
        0 => None,
        1 => Some(hashes[0]),
        _ => Some(merkle_root_r(hashes)),
    }
}

/// Calculates the merkle root of an iterator of *hashes*.
///
/// # Returns
/// - `None` if `hashes` is empty. The merkle root of an empty tree of hashes is undefined.
/// - `Some(hash)` if `hashes` contains one element. A single hash is by definition the merkle root.
/// - `Some(merkle_root)` if length of `hashes` is greater than one.
pub fn bitcoin_merkle_root<T, I>(mut hashes: I) -> Option<T>
where
    T: Hash + Encodable,
    <T as Hash>::Engine: io::Write,
    I: Iterator<Item=T>,
{
    let first = hashes.next()?;
    let second = match hashes.next() {
        Some(second) => second,
        None => return Some(first),
    };

    let mut hashes = iter::once(first).chain(iter::once(second)).chain(hashes);

    // We need a local copy to pass to `merkle_root_r`. It's more efficient to do the first loop of
    // processing as we make the copy instead of copying the whole iterator.
    let (min, max) = hashes.size_hint();
    let mut alloc = Vec::with_capacity(max.unwrap_or(min) / 2 + 1);

    while let Some(hash1) = hashes.next() {
        // If the size is odd, use the last element twice.
        let hash2 = hashes.next().unwrap_or(hash1);
        let mut encoder = T::engine();
        hash1.consensus_encode(&mut encoder).expect("in-memory writers don't error");
        hash2.consensus_encode(&mut encoder).expect("in-memory writers don't error");
        alloc.push(T::from_engine(encoder));
    }

    Some(merkle_root_r(&mut alloc))
}

// `hashes` must contain at least one hash.
fn merkle_root_r<T>(hashes: &mut [T]) -> T
where
    T: Hash + Encodable,
    <T as Hash>::Engine: io::Write,
{
    if hashes.len() == 1 {
        return hashes[0]
    }

    for idx in 0..((hashes.len() + 1) / 2) {
        let idx1 = 2 * idx;
        let idx2 = min(idx1 + 1, hashes.len() - 1);
        let mut encoder = T::engine();
        hashes[idx1].consensus_encode(&mut encoder).expect("in-memory writers don't error");
        hashes[idx2].consensus_encode(&mut encoder).expect("in-memory writers don't error");
        hashes[idx] = T::from_engine(encoder);
    }
    let half_len = hashes.len() / 2 + hashes.len() % 2;

    merkle_root_r(&mut hashes[0..half_len])
}

/// A full merkle tree.
pub struct MerkleTree<T> {
    nb_leaves: usize,
    nodes: Vec<T>,
}

impl<T> MerkleTree<T>
where
    T: Hash + Encodable,
    <T as Hash>::Engine: io::Write,
{
    /// Construct a full merkle tree from the given iterator of hashes.
    /// This method panics:
    /// - for empty trees
    /// - if the iterater yields less than [nb_leaves] elements.
    pub fn new<I>(hashes: I, nb_leaves: usize) -> MerkleTree<T>
    where
        I: Iterator<Item=T>,
    {
        assert_ne!(nb_leaves, 0);

        let nb_nodes = {
            let mut ret = 0;
            let mut layer = nb_leaves;
            while layer > 1 {
                ret += layer;
                layer = layer / 2 + layer % 2
            }
            ret + 1
        };

        let mut nodes = Vec::with_capacity(nb_nodes);
        // First put the leaves in place.
        nodes.extend(hashes.take(nb_leaves));
        assert_eq!(nodes.len(), nb_leaves);

        let mut layer_init = 0;
        let mut layer_size = nb_leaves;
        while layer_size > 1 {
            for idx in 0..((layer_size + 1) / 2) {
                let idx1 = 2 * idx;
                let idx2 = min(idx1 + 1, layer_size - 1);
                let mut encoder = T::engine();
                nodes[layer_init + idx1].consensus_encode(&mut encoder).expect("in-memory writers don't error");
                nodes[layer_init + idx2].consensus_encode(&mut encoder).expect("in-memory writers don't error");
                nodes.push(T::from_engine(encoder));
            }
            layer_init = layer_init + layer_size;
            layer_size = layer_size / 2 + layer_size % 2;
        }

        assert_eq!(nodes.len(), nb_nodes);
        MerkleTree {
            nb_leaves: nb_leaves,
            nodes: nodes,
        }
    }

    /// Calculate the merkle root of the tree that is identical to this tree,
    /// but has leaf with index [idx] replaced by [replacement].
    /// Panics if idx is not a valid leaf index.
    /// This method uses constant memory and performs log(n) hash calculations.
    pub fn calculate_root_with_replaced_leaf(&self, mut idx: usize, mut replacement: T) -> T {
        assert!(idx < self.nb_leaves);

        let mut layer_init = 0;
        let mut layer_size = self.nb_leaves;
        while layer_size > 1 {
            replacement = {
                let mut engine = T::engine();
                if idx % 2 == 0 && idx == layer_size - 1 {
                    replacement.consensus_encode(&mut engine).expect("in-memory writers don't error");
                    replacement.consensus_encode(&mut engine).expect("in-memory writers don't error");
                } else if idx % 2 == 0 {
                    replacement.consensus_encode(&mut engine).expect("in-memory writers don't error");
                    self.nodes[layer_init + idx + 1].consensus_encode(&mut engine).expect("in-memory writers don't error");
                } else {
                    self.nodes[layer_init + idx - 1].consensus_encode(&mut engine).expect("in-memory writers don't error");
                    replacement.consensus_encode(&mut engine).expect("in-memory writers don't error");
                };
                T::from_engine(engine)
            };
            // on the next layer
            layer_init = layer_init + layer_size;
            layer_size = layer_size / 2 + layer_size % 2;
            idx = idx / 2;
        }
        replacement
    }
}

impl<T> MerkleTree<T> {
    /// The merkle root of the tree.
    ///
    /// Use [MerkleTree::root] instead to not get a reference.
    pub fn borrow_root(&self) -> &T {
        self.nodes.last().unwrap()
    }
}

impl<T: Copy> MerkleTree<T> {
    /// The merkle root of the tree.
    pub fn root(&self) -> T {
        *self.borrow_root()
    }
}

impl<T: fmt::Debug> fmt::Debug for MerkleTree<T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "MerkleTree(root={:?})", self.borrow_root())
    }
}

#[cfg(test)]
mod tests {
    use crate::consensus::encode::deserialize;
    use crate::hashes::{Hash, sha256, sha256d};

    use crate::blockdata::block::Block;
    use super::*;

    #[test]
    fn both_merkle_root_functions_return_the_same_result() {
        // testnet block 000000000000045e0b1660b6445b5e5c5ab63c9a4f956be7e1e69be04fa4497b
        let segwit_block = include_bytes!("../../test_data/testnet_block_000000000000045e0b1660b6445b5e5c5ab63c9a4f956be7e1e69be04fa4497b.raw");
        let block: Block = deserialize(&segwit_block[..]).expect("Failed to deserialize block");
        assert!(block.check_merkle_root()); // Sanity check.

        let hashes_iter = block.txdata.iter().map(|obj| obj.txid().as_hash());

        let mut hashes_array: [sha256d::Hash; 15] = [Hash::all_zeros(); 15];
        for (i, hash) in hashes_iter.clone().enumerate() {
            hashes_array[i] = hash;
        }

        let from_iter = bitcoin_merkle_root(hashes_iter);
        let from_array = bitcoin_merkle_root_inline(&mut hashes_array);
        assert_eq!(from_iter, from_array);
    }

    /// Just a bunch of interesting tree sizes to test for.
    const TEST_LENGTHS: [usize; 9] = [1, 2, 3, 4, 17, 31, 32, 33, 55];

    /// An easy way to get a series of [n] very-pseudo-random hashes.
    fn hash_series(n: usize) -> impl Iterator<Item = sha256::Hash> + Clone {
        (0..n).map(|i| sha256::Hash::hash(&i.to_be_bytes()))
    }

    #[test]
    fn compare_merkle_tree_root_with_fast_root() {
        //! Assuming the plain merkle root implementation is sound,
        //! compare the one from [MerkleTree] with the original one.

        for length in TEST_LENGTHS.iter().copied() {
            let hashes = hash_series(length);
            let root = bitcoin_merkle_root(hashes.clone()).unwrap();

            let tree = MerkleTree::new(hashes, length);
            assert_eq!(root, tree.root());
        }
    }

    #[test]
    fn test_calculate_root_with_replaced_leaf() {
        //! Brute force replace all possible indices with zero in all trees
        //! with lengths in [TEST_LENGTHS].

        let zero = sha256::Hash::all_zeros();
        for length in TEST_LENGTHS.iter().copied() {
            for idx in 0..length {
                let original_hashes = hash_series(length);
                let tweaked_hashes = original_hashes.clone().enumerate().map(|(i, h)| {
                    if i == idx {
                        zero
                    } else {
                        h
                    }
                });

                let tree = MerkleTree::new(original_hashes, length);
                let root = bitcoin_merkle_root(tweaked_hashes).unwrap();
                assert_eq!(root, tree.calculate_root_with_replaced_leaf(idx, zero));
            }
        }
    }
}
