use core::fmt;

use arrayvec::ArrayVec;
use itertools::Itertools;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use thiserror::Error;

const MAX_DIMENSIONS: usize = 3;

#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[repr(C)]
pub struct Dimensions {
    sizes: ArrayVec<usize, MAX_DIMENSIONS>,
    strides: ArrayVec<usize, MAX_DIMENSIONS>,
}

impl fmt::Display for Dimensions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Dimensions({})", self.sizes.iter().join(", "))
    }
}

#[derive(Debug, Clone, Copy, Error)]
pub enum DimensionsError {
    #[error("Too many dimensions {0}, maximum number allowed is {MAX_DIMENSIONS}")]
    TooManyDimensions(usize),
    #[error("dimension product overflows usize")]
    SizeOverflow,
    #[error("total number of elements must match, expected {0}, got {1}")]
    NumElementsMismatch(usize, usize),
}

impl Dimensions {
    fn new(sizes: ArrayVec<usize, MAX_DIMENSIONS>) -> Self {
        let mut strides = ArrayVec::new();
        let mut stride = 1;
        for size in sizes.iter().rev() {
            strides.push(stride);
            stride *= size;
        }
        strides.reverse();
        Self { sizes, strides }
    }

    fn check_size_product(sizes: &[usize]) -> Result<(), DimensionsError> {
        sizes
            .iter()
            .try_fold(1usize, |product, size| product.checked_mul(*size))
            .ok_or(DimensionsError::SizeOverflow)?;
        sizes
            .iter()
            .rev()
            .try_fold(1usize, |product, size| product.checked_mul(*size))
            .map(|_| ())
            .ok_or(DimensionsError::SizeOverflow)
    }

    #[inline]
    pub fn total_len(&self) -> usize {
        self.sizes.iter().product()
    }

    #[inline]
    pub(crate) fn compatible(&self, other: &Dimensions) -> Result<(), DimensionsError> {
        if self.total_len() != other.total_len() {
            return Err(DimensionsError::NumElementsMismatch(self.total_len(), other.total_len()));
        }
        Ok(())
    }

    #[inline]
    pub fn sizes(&self) -> &[usize] {
        &self.sizes
    }

    pub(crate) fn sizes_mut(&mut self) -> &mut ArrayVec<usize, MAX_DIMENSIONS> {
        &mut self.sizes
    }

    pub(crate) fn strides_mut(&mut self) -> &mut ArrayVec<usize, MAX_DIMENSIONS> {
        &mut self.strides
    }

    #[inline]
    pub fn strides(&self) -> &[usize] {
        &self.strides
    }

    /// Maps a multi-dimensional index to a single-dimensional buffer index.
    ///
    /// Panics if the index is out of bounds, or the length of the index does not match the number
    /// of dimensions.
    #[inline]
    pub(crate) fn index_map(&self, index: impl AsRef<[usize]>) -> usize {
        // The panic code path was put into a cold function to not bloat the
        // call site.
        #[inline(never)]
        #[cold]
        #[track_caller]
        fn index_length_mismatch(buffer_index: &[usize], dimensions: &Dimensions) -> ! {
            panic!(
                "Index tuple {buffer_index:?} has length {} which is out of bounds for dimensions 
                {dimensions} of length {}",
                buffer_index.len(),
                dimensions.sizes().len()
            );
        }

        // The panic code path was put into a cold function to not bloat the
        // call site.
        #[inline(never)]
        #[cold]
        #[track_caller]
        fn index_out_of_bounds_fail(buffer_index: &[usize], dimensions: &Dimensions) -> ! {
            panic!("Index {buffer_index:?} is out of bounds for dimensions {dimensions}",);
        }

        if index.as_ref().len() != self.sizes.len() {
            index_length_mismatch(index.as_ref(), self);
        }

        let mut buffer_index = 0;
        for ((idx, stride), len) in
            index.as_ref().iter().zip_eq(self.strides.iter()).zip_eq(self.sizes.iter())
        {
            if *idx >= *len {
                index_out_of_bounds_fail(index.as_ref(), self);
            }
            buffer_index += idx * stride;
        }

        buffer_index
    }
}

impl TryFrom<&[usize]> for Dimensions {
    type Error = DimensionsError;

    fn try_from(value: &[usize]) -> Result<Self, Self::Error> {
        let sizes = ArrayVec::try_from(value)
            .map_err(|_| DimensionsError::TooManyDimensions(value.len()))?;
        Self::check_size_product(&sizes)?;
        Ok(Self::new(sizes))
    }
}

impl TryFrom<Vec<usize>> for Dimensions {
    type Error = DimensionsError;

    fn try_from(value: Vec<usize>) -> Result<Self, Self::Error> {
        let sizes = ArrayVec::try_from(value.as_slice())
            .map_err(|_| DimensionsError::TooManyDimensions(value.len()))?;
        Self::check_size_product(&sizes)?;
        Ok(Self::new(sizes))
    }
}

impl<const N: usize> TryFrom<[usize; N]> for Dimensions {
    type Error = DimensionsError;

    fn try_from(value: [usize; N]) -> Result<Self, Self::Error> {
        let sizes = ArrayVec::try_from(value.as_slice())
            .map_err(|_| DimensionsError::TooManyDimensions(value.len()))?;
        Self::check_size_product(&sizes)?;
        Ok(Self::new(sizes))
    }
}

impl FromIterator<usize> for Dimensions {
    #[inline]
    fn from_iter<T: IntoIterator<Item = usize>>(iter: T) -> Self {
        let sizes = ArrayVec::from_iter(iter);
        Self::check_size_product(&sizes).expect("dimension product overflows usize");
        Self::new(sizes)
    }
}

impl Serialize for Dimensions {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.sizes.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for Dimensions {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let sizes = Vec::deserialize(deserializer)?;
        Self::try_from(sizes).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_too_many_dimensions_during_deserialization() {
        let result = serde_json::from_str::<Dimensions>("[1,1,1,1]");
        assert!(result.is_err());
    }

    #[test]
    fn rejects_overflowing_dimension_product() {
        assert!(matches!(
            Dimensions::try_from([usize::MAX, 2]),
            Err(DimensionsError::SizeOverflow)
        ));
    }
}
