// Rust Bitcoin Library
// Written in 2014 by
//     Andrew Poelstra <apoelstra@wpsoftware.net>
// To the extent possible under law, the author(s) have dedicated all
// copyright and related and neighboring rights to this software to
// the public domain worldwide. This software is distributed without
// any warranty.
//
// You should have received a copy of the CC0 Public Domain Dedication
// along with this software.
// If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
//

//! Hash functions
//!
//! Utility functions related to hashing data, including merkleization

use std::cmp::min;
use std::io;

use hashes::Hash;
use consensus::encode::Encodable;

/// Calculates the merkle root of a list of txids hashes directly
pub fn bitcoin_merkle_root<T>(data: Vec<T>) -> T
    where T: Hash + Encodable,
          <T as Hash>::Engine: io::Write,
{
    // Base case
    if data.len() < 1 {
        return Default::default();
    }
    if data.len() < 2 {
        return T::from_inner(data[0].into_inner());
    }
    // Recursion
    let mut next = vec![];
    for idx in 0..((data.len() + 1) / 2) {
        let idx1 = 2 * idx;
        let idx2 = min(idx1 + 1, data.len() - 1);
        let mut encoder = T::engine();
        data[idx1].consensus_encode(&mut encoder).unwrap();
        data[idx2].consensus_encode(&mut encoder).unwrap();
        next.push(T::from_engine(encoder));
    }
    bitcoin_merkle_root(next)
}

/// Objects which are referred to by hash
pub trait BitcoinHash<T: Hash> {
    /// Produces a Sha256dHash which can be used to refer to the object
    fn bitcoin_hash(&self) -> T;
}
