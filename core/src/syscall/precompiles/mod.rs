pub mod blake3;
pub mod edwards;
pub mod k256;
pub mod keccak256;
pub mod sha256;
pub mod weierstrass;
use crate::runtime::SyscallContext;
use core::fmt::Debug;
use generic_array::{ArrayLength, GenericArray};
use serde::{Deserialize, Serialize};
use typenum::Unsigned;

use crate::utils::ec::field::NumWords;
use crate::utils::ec::{AffinePoint, EllipticCurve};
use crate::{runtime::MemoryReadRecord, runtime::MemoryWriteRecord};

/// Elliptic curve add event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ECAddEvent<E: EllipticCurve>
where
    <E::BaseField as NumWords>::WordsCurvePoint: ArrayLength,
{
    pub shard: u32,
    pub clk: u32,
    pub p_ptr: u32,
    pub p: GenericArray<u32, <E::BaseField as NumWords>::WordsCurvePoint>,
    pub q_ptr: u32,
    pub q: GenericArray<u32, <E::BaseField as NumWords>::WordsCurvePoint>,
    pub p_memory_records:
        GenericArray<MemoryWriteRecord, <E::BaseField as NumWords>::WordsCurvePoint>,
    pub q_memory_records:
        GenericArray<MemoryReadRecord, <E::BaseField as NumWords>::WordsCurvePoint>,
}

pub fn create_ec_add_event<E: EllipticCurve>(
    rt: &mut SyscallContext,
    arg1: u32,
    arg2: u32,
) -> ECAddEvent<E> {
    let start_clk = rt.clk;
    let p_ptr = arg1;
    if p_ptr % 4 != 0 {
        panic!();
    }
    let q_ptr = arg2;
    if q_ptr % 4 != 0 {
        panic!();
    }

    let p = GenericArray::from_iter(
        rt.slice_unsafe(p_ptr, <E::BaseField as NumWords>::WordsCurvePoint::USIZE)
            .iter()
            .cloned(),
    );
    let (q_memory_records_vec, q_vec) =
        rt.mr_slice(q_ptr, <E::BaseField as NumWords>::WordsCurvePoint::USIZE);
    let q_memory_records = GenericArray::from_iter(q_memory_records_vec.into_iter());
    let q = GenericArray::from_iter(q_vec.into_iter());

    // When we write to p, we want the clk to be incremented because p and q could be the same.
    rt.clk += 1;

    let p_affine = AffinePoint::<E>::from_words_le(&p);
    let q_affine = AffinePoint::<E>::from_words_le(&q);
    let result_affine = p_affine + q_affine;

    let result_words = result_affine.to_words_le();

    let p_memory_records = rt.mw_slice(p_ptr, &result_words.0).try_into().unwrap();

    ECAddEvent {
        shard: rt.current_shard(),
        clk: start_clk,
        p_ptr,
        p,
        q_ptr,
        q,
        p_memory_records,
        q_memory_records,
    }
}

/// Define a trait that is meant to be implemented by `EcAddEvent<E>` for any `E` that implements
/// `EllipticCurve`. It acts as a common interface for the different `EcAddEvent` types.
/// During the trace generation, one can use this trait to handle events generically without
/// knowing the exact type of the event. It is used to abstract over the specific
/// curve type.
trait EcEventTrait: Debug {
    fn shard(&self) -> u32;
    fn clk(&self) -> u32;
    fn p_ptr(&self) -> u32;
    fn p(&self) -> &[u32];
    fn q_ptr(&self) -> u32;
    fn q(&self) -> &[u32];
    fn p_memory_records(&self) -> &[MemoryWriteRecord];
    fn q_memory_records(&self) -> &[MemoryReadRecord];
}

impl<E: EllipticCurve> EcEventTrait for ECAddEvent<E>
where
    <E::BaseField as NumWords>::WordsCurvePoint: ArrayLength,
{
    fn shard(&self) -> u32 {
        self.shard
    }

    fn clk(&self) -> u32 {
        self.clk
    }

    fn p_ptr(&self) -> u32 {
        self.p_ptr
    }

    fn p(&self) -> &[u32] {
        self.p.as_slice()
    }

    fn q_ptr(&self) -> u32 {
        self.q_ptr
    }

    fn q(&self) -> &[u32] {
        self.q.as_slice()
    }

    fn p_memory_records(&self) -> &[MemoryWriteRecord] {
        self.p_memory_records.as_slice()
    }

    fn q_memory_records(&self) -> &[MemoryReadRecord] {
        self.q_memory_records.as_slice()
    }
}

/// Elliptic curve double event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ECDoubleEvent<E: EllipticCurve>
where
    <E::BaseField as NumWords>::WordsCurvePoint: ArrayLength,
{
    pub shard: u32,
    pub clk: u32,
    pub p_ptr: u32,
    pub p: GenericArray<u32, <E::BaseField as NumWords>::WordsCurvePoint>,
    pub p_memory_records:
        GenericArray<MemoryWriteRecord, <E::BaseField as NumWords>::WordsCurvePoint>,
}

pub fn create_ec_double_event<E: EllipticCurve>(
    rt: &mut SyscallContext,
    arg1: u32,
    _: u32,
) -> ECDoubleEvent<E> {
    let start_clk = rt.clk;
    let p_ptr = arg1;
    if p_ptr % 4 != 0 {
        panic!();
    }

    let p = GenericArray::from_iter(
        rt.slice_unsafe(p_ptr, <E::BaseField as NumWords>::WordsCurvePoint::USIZE)
            .iter()
            .cloned(),
    );
    let p_affine = AffinePoint::<E>::from_words_le(&p);
    let result_affine = E::ec_double(&p_affine);
    let result_words = result_affine.to_words_le();
    let p_memory_records = rt.mw_slice(p_ptr, &result_words.0).try_into().unwrap();

    ECDoubleEvent {
        shard: rt.current_shard(),
        clk: start_clk,
        p_ptr,
        p,
        p_memory_records,
    }
}

trait ECDoubleTrait: Debug + Sync + Send {
    fn shard(&self) -> u32;
    fn clk(&self) -> u32;
    fn p_ptr(&self) -> u32;
    fn p(&self) -> &[u32];
    fn p_memory_records(&self) -> &[MemoryWriteRecord];
}

impl<E: EllipticCurve> ECDoubleTrait for ECDoubleEvent<E>
where
    <E::BaseField as NumWords>::WordsCurvePoint: ArrayLength,
{
    fn shard(&self) -> u32 {
        self.shard
    }

    fn clk(&self) -> u32 {
        self.clk
    }

    fn p_ptr(&self) -> u32 {
        self.p_ptr
    }

    fn p(&self) -> &[u32] {
        self.p.as_slice()
    }

    fn p_memory_records(&self) -> &[MemoryWriteRecord] {
        self.p_memory_records.as_slice()
    }
}
