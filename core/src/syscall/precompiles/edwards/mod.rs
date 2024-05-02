mod ed_add;
mod ed_decompress;

pub use ed_add::*;
pub use ed_decompress::*;

use crate::operations::field::params::NumWords;
use crate::utils::ec::edwards::ed25519::Ed25519BaseField;
use typenum::Unsigned;

pub(crate) type WordsFieldElement = <Ed25519BaseField as NumWords>::WordsFieldElement;
pub(crate) const WORDS_FIELD_ELEMENT: usize = WordsFieldElement::USIZE;

#[allow(unused)]
pub(crate) type WordsCurvePoint = <Ed25519BaseField as NumWords>::WordsCurvePoint;
pub(crate) const WORDS_CURVE_POINT: usize = WordsCurvePoint::USIZE;
