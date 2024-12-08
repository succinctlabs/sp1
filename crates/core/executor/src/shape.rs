use std::fmt::Debug;
use std::{collections::BTreeMap, hash::Hash, str::FromStr, sync::Arc};

use hashbrown::hash_map::IntoIter;
use hashbrown::HashMap;
use p3_field::PrimeField;
use serde::{Deserialize, Serialize};
use sp1_stark::air::MachineAir;
use sp1_stark::shape::Shape;

use crate::{ExecutionRecord, Program, RiscvAirId};

/// A set of maximal shapes, under the normal ordering.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MaximalShapes<K: Eq + Hash> {
    pub shard_map: BTreeMap<usize, Vec<Shape<K>>>,
}

// impl IntoIterator for CoreShape {
//     type Item = (String, usize);

//     type IntoIter = hashbrown::hash_map::IntoIter<String, usize>;

//     fn into_iter(self) -> Self::IntoIter {
//         self.inner.into_iter()
//     }
// }

// impl From<ProofShape> for CoreShape {
//     fn from(value: ProofShape) -> Self {
//         Self { inner: value.into_iter().collect() }
//     }
// }

// impl From<CoreShape> for ProofShape {
//     fn from(value: CoreShape) -> Self {
//         value.inner.into_iter().collect()
//     }
// }

// impl PartialOrd for CoreShape {
//     fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
//         let set = self.inner.keys().collect::<HashSet<_>>();
//         let other_set = other.inner.keys().collect::<HashSet<_>>();

//         if self == other {
//             return Some(std::cmp::Ordering::Equal);
//         }

//         if set.is_subset(&other_set) {
//             let mut less_seen = false;
//             let mut greater_seen = false;
//             for (name, &height) in self.inner.iter() {
//                 let other_height = other.inner[name];
//                 match height.cmp(&other_height) {
//                     std::cmp::Ordering::Less => less_seen = true,
//                     std::cmp::Ordering::Greater => greater_seen = true,
//                     std::cmp::Ordering::Equal => {}
//                 }
//             }
//             if less_seen && greater_seen {
//                 return None;
//             }

//             if less_seen {
//                 return Some(std::cmp::Ordering::Less);
//             }
//         }

//         if other_set.is_subset(&set) {
//             let mut less_seen = false;
//             let mut greater_seen = false;
//             for (name, &other_height) in other.inner.iter() {
//                 let height = self.inner[name];
//                 match height.cmp(&other_height) {
//                     std::cmp::Ordering::Less => less_seen = true,
//                     std::cmp::Ordering::Greater => greater_seen = true,
//                     std::cmp::Ordering::Equal => {}
//                 }
//             }
//             if less_seen && greater_seen {
//                 return None;
//             }

//             if greater_seen {
//                 return Some(std::cmp::Ordering::Greater);
//             }
//         }

//         None
//     }
// }

// impl<T> Maximal<T>
// where
//     T: PartialOrd,
// {
//     /// Create a new empty set.
//     #[inline]
//     #[must_use]
//     pub fn new() -> Self {
//         Self { shapes: vec![] }
//     }

//     /// The number of shapes in the set.
//     #[inline]
//     #[must_use]
//     pub fn len(&self) -> usize {
//         self.shapes.len()
//     }

//     /// Returns whether or not the set is empty.
//     #[inline]
//     #[must_use]
//     pub fn is_empty(&self) -> bool {
//         self.shapes.is_empty()
//     }

//     /// Clear the set.
//     pub fn clear(&mut self) {
//         self.shapes.clear();
//     }

//     /// Insert a element to the set.
//     ///
//     /// If an element is larger than any element in the set, it will be inserted, and all elements
//     /// smaller than it will also be removed. Otherwise, the set remains unchanged.
//     pub fn insert(&mut self, element: T) {
//         let mut to_remove = vec![];
//         for (i, maximal_element) in self.shapes.iter().enumerate() {
//             match PartialOrd::partial_cmp(&element, maximal_element) {
//                 Some(Ordering::Greater) => {
//                     to_remove.push(i);
//                 }
//                 Some(Ordering::Less | Ordering::Equal) => {
//                     return;
//                 }
//                 None => {}
//             }
//         }
//         for i in to_remove.into_iter().rev() {
//             self.shapes.remove(i);
//         }
//         self.shapes.push(element);
//     }

//     /// Returns an iterator over the shapes.
//     #[inline]
//     pub fn iter(&self) -> std::slice::Iter<'_, T> {
//         self.shapes.iter()
//     }
// }

// impl<T: PartialOrd> FromIterator<T> for Maximal<T> {
//     fn from_iter<I: IntoIterator<Item = T>>(iter: I) -> Self {
//         Maximal { shapes: Vec::from_iter(iter) }
//     }
// }

// impl<T: PartialOrd> IntoIterator for Maximal<T> {
//     type Item = T;
//     type IntoIter = <Vec<T> as IntoIterator>::IntoIter;

//     #[inline]
//     fn into_iter(self) -> Self::IntoIter {
//         self.shapes.into_iter()
//     }
// }

// impl<T: PartialOrd> Extend<T> for Maximal<T> {
//     fn extend<I: IntoIterator<Item = T>>(&mut self, iter: I) {
//         for shape in iter {
//             self.insert(shape);
//         }
//     }
// }

// impl<'a, T: PartialOrd> IntoIterator for &'a Maximal<T> {
//     type Item = &'a T;
//     type IntoIter = std::slice::Iter<'a, T>;

//     fn into_iter(self) -> Self::IntoIter {
//         self.shapes.iter()
//     }
// }

// impl Index<usize> for MaximalShapes {
//     type Output = Maximal<CoreShape>;

//     fn index(&self, index: usize) -> &Self::Output {
//         &self.shard_map[&index]
//     }
// }

// impl IndexMut<usize> for MaximalShapes {
//     fn index_mut(&mut self, index: usize) -> &mut Self::Output {
//         self.shard_map.get_mut(&index).expect("No shapes for shard size")
//     }
// }
