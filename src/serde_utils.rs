
//! Module for special serde serializations.

pub mod btreemap {
    //! Module for serialization of BTreeMaps because serde_json will
    //! not serialize hashmaps with non-string keys be default.
    #![allow(missing_docs)]

    // NOTE: This module can be exactly copied to use with HashMap.

    use ::std::collections::BTreeMap;
    use serde;

    pub fn serialize<S, T, U>(v: &BTreeMap<T, U>, s: S)
        -> Result<S::Ok, S::Error> where
        S: serde::Serializer,
        T: serde::Serialize + ::std::hash::Hash + Eq + Ord,
        U: serde::Serialize,
    {
        use serde::ser::SerializeSeq;

        let mut seq = s.serialize_seq(Some(v.len()))?;
        for pair in v.iter() {
            seq.serialize_element(&pair)?;
        }
        seq.end()
    }

    pub fn deserialize<'de, D, T, U>(d: D)
        -> Result<BTreeMap<T, U>, D::Error> where
        D: serde::Deserializer<'de>,
        T: serde::Deserialize<'de> + ::std::hash::Hash + Eq + Ord,
        U: serde::Deserialize<'de>,
    {
        use ::std::marker::PhantomData;

        struct Visitor<T, U>(PhantomData<(T, U)>);
        impl<'de, T, U> serde::de::Visitor<'de> for Visitor<T, U> where
            T: serde::Deserialize<'de> + ::std::hash::Hash + Eq + Ord,
            U: serde::Deserialize<'de>,
        {
            type Value = BTreeMap<T, U>;

            fn expecting(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
                write!(f, "a sequence of pairs")
            }

            fn visit_seq<A: serde::de::SeqAccess<'de>>(self, mut a: A)
                -> Result<Self::Value, A::Error>
            {
                let mut ret = BTreeMap::new();
                while let Some((key, value)) = a.next_element()? {
                    ret.insert(key, value);
                }
                Ok(ret)
            }
        }

        d.deserialize_seq(Visitor(PhantomData))
    }
}

pub mod hex_bytes {
    //! Module for serialization of byte arrays as hex strings.
    #![allow(missing_docs)]

    use hashes::hex::{FromHex, ToHex};
    use serde;

    pub fn serialize<T, S>(bytes: &T, serializer: S) -> Result<S::Ok, S::Error>
        where T: AsRef<[u8]>, S: serde::Serializer
    {
        serializer.serialize_str(&bytes.as_ref().to_hex())
    }

    pub fn deserialize<'de, D, B>(d: D) -> Result<B, D::Error>
        where D: serde::Deserializer<'de>, B: FromHex,
    {
        struct Visitor<B>(::std::marker::PhantomData<B>);

        impl<'de, B: FromHex> serde::de::Visitor<'de> for Visitor<B> {
            type Value = B;

            fn expecting(&self, formatter: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
                formatter.write_str("an ASCII hex string")
            }

            fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
                where E: serde::de::Error,
            {
                if let Ok(hex) = ::std::str::from_utf8(v) {
                    FromHex::from_hex(hex).map_err(E::custom)
                } else {
                    return Err(E::invalid_value(serde::de::Unexpected::Bytes(v), &self));
                }
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
                where E: serde::de::Error,
            {
                FromHex::from_hex(v).map_err(E::custom)
            }
        }

        d.deserialize_str(Visitor(::std::marker::PhantomData))
    }
}
