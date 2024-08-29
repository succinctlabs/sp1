use hashbrown::HashMap;

use nohash_hasher::BuildNoHashHasher;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

pub fn serialize_hashmap_as_vec<V: Serialize, S: Serializer>(
    map: &HashMap<u32, V, BuildNoHashHasher<u32>>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    Serialize::serialize(&map.iter().collect::<Vec<_>>(), serializer)
}

pub fn deserialize_hashmap_as_vec<'de, V: Deserialize<'de>, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<HashMap<u32, V, BuildNoHashHasher<u32>>, D::Error> {
    let seq: Vec<(u32, V)> = Deserialize::deserialize(deserializer)?;
    Ok(seq.into_iter().collect())
}
