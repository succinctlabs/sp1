pub mod blake3;
pub mod edwards;
pub mod k256;
pub mod keccak256;
pub mod sha256;
pub mod weierstrass;
use crate::runtime::SyscallContext;
use core::fmt::Debug;
use generic_array::{ArrayLength, GenericArray};
use serde::de::{SeqAccess, Visitor};
use serde::ser::SerializeStruct;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt::Formatter;
use typenum::Unsigned;

use crate::utils::ec::field::NumWords;
use crate::utils::ec::{AffinePoint, EllipticCurve};
use crate::{runtime::MemoryReadRecord, runtime::MemoryWriteRecord};

/// Elliptic curve add event.
#[derive(Debug, Clone)]
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
pub struct ECDoubleEvent {
    pub shard: u32,
    pub clk: u32,
    pub p_ptr: u32,
    pub p: [u32; 16],
    pub p_memory_records: [MemoryWriteRecord; 16],
}

pub fn create_ec_double_event<E: EllipticCurve>(
    rt: &mut SyscallContext,
    arg1: u32,
    _: u32,
) -> ECDoubleEvent {
    let start_clk = rt.clk;
    let p_ptr = arg1;
    if p_ptr % 4 != 0 {
        panic!();
    }

    let p: [u32; 16] = rt.slice_unsafe(p_ptr, 16).try_into().unwrap();
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

impl<E: EllipticCurve> Serialize for ECAddEvent<E>
where
    <E::BaseField as NumWords>::WordsCurvePoint: ArrayLength,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("ECAddEvent", 8)?;
        state.serialize_field("shard", &self.shard)?;
        state.serialize_field("clk", &self.clk)?;
        state.serialize_field("p_ptr", &self.p_ptr)?;
        state.serialize_field("p", &self.p.as_slice())?;
        state.serialize_field("q_ptr", &self.q_ptr)?;
        state.serialize_field("q", &self.q.as_slice())?;
        state.serialize_field("p_memory_records", &self.p_memory_records.as_slice())?;
        state.serialize_field("q_memory_records", &self.q_memory_records.as_slice())?;
        state.end()
    }
}

impl<'de, E: EllipticCurve> Deserialize<'de> for ECAddEvent<E>
where
    <E::BaseField as NumWords>::WordsCurvePoint: ArrayLength,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        // Define a custom visitor struct for deserializing ECAddEvent.
        struct ECAddEventVisitor<E: EllipticCurve>(std::marker::PhantomData<E>);

        impl<'de, E: EllipticCurve> Visitor<'de> for ECAddEventVisitor<E>
        where
            <E::BaseField as NumWords>::WordsCurvePoint: ArrayLength,
        {
            type Value = ECAddEvent<E>;

            // Provide an error message if the data format is not met.
            fn expecting(&self, formatter: &mut Formatter) -> std::fmt::Result {
                formatter.write_str("struct ECAddEvent")
            }

            // // Visit the sequence of fields and deserialize them.
            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                // Deserialize the `shard` field.
                let shard = seq
                    .next_element()?
                    .ok_or_else(|| serde::de::Error::invalid_length(0, &self))?;

                // Deserialize the `clk` field.
                let clk = seq
                    .next_element()?
                    .ok_or_else(|| serde::de::Error::invalid_length(1, &self))?;

                // Deserialize the `p_ptr` field.
                let p_ptr = seq
                    .next_element()?
                    .ok_or_else(|| serde::de::Error::invalid_length(2, &self))?;

                // Deserialize the `p` field as Vec<u32> and convert it to GenericArray.
                let p_slice: Vec<u32> = seq
                    .next_element()?
                    .ok_or_else(|| serde::de::Error::invalid_length(3, &self))?;
                let p = GenericArray::try_from(p_slice)
                    .map_err(|_| serde::de::Error::invalid_length(3, &self))?;

                // Deserialize the `q_ptr` field.
                let q_ptr = seq
                    .next_element()?
                    .ok_or_else(|| serde::de::Error::invalid_length(4, &self))?;

                // Deserialize the `q` field as Vec<u32> and convert it to GenericArray
                let q_slice: Vec<u32> = seq
                    .next_element()?
                    .ok_or_else(|| serde::de::Error::invalid_length(5, &self))?;
                let q = GenericArray::try_from(q_slice)
                    .map_err(|_| serde::de::Error::invalid_length(5, &self))?;

                // Deserialize the `p_memory_records` field as Vec<MemoryWriteRecord> and convert it to GenericArray.
                let p_memory_records_slice: Vec<MemoryWriteRecord> = seq
                    .next_element()?
                    .ok_or_else(|| serde::de::Error::invalid_length(6, &self))?;
                let p_memory_records = GenericArray::try_from(p_memory_records_slice)
                    .map_err(|_| serde::de::Error::invalid_length(6, &self))?;

                // Deserialize the `q_memory_records` field as Vec<MemoryReadRecord> and convert it to GenericArray.
                let q_memory_records_slice: Vec<MemoryReadRecord> = seq
                    .next_element()?
                    .ok_or_else(|| serde::de::Error::invalid_length(7, &self))?;
                let q_memory_records = GenericArray::try_from(q_memory_records_slice)
                    .map_err(|_| serde::de::Error::invalid_length(7, &self))?;

                // Construct and return the ECAddEvent struct with the deserialized fields.
                Ok(ECAddEvent {
                    shard,
                    clk,
                    p_ptr,
                    p,
                    q_ptr,
                    q,
                    p_memory_records,
                    q_memory_records,
                })
            }
        }

        // Call the deserializer's `deserialize_struct` method with the struct name, field names, and the custom visitor.
        deserializer.deserialize_struct(
            "ECAddEvent",
            &[
                "shard",
                "clk",
                "p_ptr",
                "p",
                "q_ptr",
                "q",
                "p_memory_records",
                "q_memory_records",
            ],
            ECAddEventVisitor(std::marker::PhantomData),
        )
    }
}
