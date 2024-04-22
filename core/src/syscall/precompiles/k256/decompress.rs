use core::borrow::{Borrow, BorrowMut};
use core::mem::size_of;
use std::fmt::Debug;
use std::str::FromStr;

use elliptic_curve::sec1::ToEncodedPoint;
use elliptic_curve::subtle::Choice;
use k256::elliptic_curve::point::DecompressPoint;
use num::BigUint;
use num::Zero;
use p3_air::AirBuilder;
use p3_air::{Air, BaseAir};
use p3_field::AbstractField;
use p3_field::PrimeField32;
use p3_matrix::dense::RowMajorMatrix;
use p3_matrix::Matrix;
use serde::{Deserialize, Serialize};
use sp1_derive::AlignedBorrow;
use typenum::U32;

use crate::air::BaseAirBuilder;
use crate::air::MachineAir;
use crate::air::SP1AirBuilder;
use crate::air::Word;
use crate::bytes::event::ByteRecord;
use crate::bytes::ByteLookupEvent;
use crate::memory::MemoryReadCols;
use crate::memory::MemoryReadWriteCols;
use crate::operations::field::field_op::FieldOpCols;
use crate::operations::field::field_op::FieldOperation;
use crate::operations::field::field_sqrt::FieldSqrtCols;
use crate::operations::field::params::FieldParameters;
use crate::operations::field::params::Limbs;
use crate::runtime::ExecutionRecord;
use crate::runtime::MemoryReadRecord;
use crate::runtime::MemoryWriteRecord;
use crate::runtime::Program;
use crate::runtime::Syscall;
use crate::runtime::SyscallCode;
use crate::syscall::precompiles::SyscallContext;
use crate::utils::bytes_to_words_le;
use crate::utils::ec::weierstrass::secp256k1::secp256k1_sqrt;
use crate::utils::ec::weierstrass::secp256k1::Secp256k1BaseField;
use crate::utils::ec::weierstrass::secp256k1::Secp256k1Parameters;
use crate::utils::ec::weierstrass::WeierstrassParameters;
use crate::utils::ec::COMPRESSED_POINT_BYTES;
use crate::utils::ec::NUM_BYTES_FIELD_ELEMENT;
use crate::utils::ec::NUM_WORDS_FIELD_ELEMENT;
use crate::utils::limbs_from_access;
use crate::utils::limbs_from_prev_access;
use crate::utils::pad_rows;
use crate::utils::words_to_bytes_le;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct K256DecompressEvent {
    pub shard: u32,
    pub clk: u32,
    pub ptr: u32,
    pub is_odd: bool,
    pub x_bytes: [u8; COMPRESSED_POINT_BYTES],
    pub decompressed_y_bytes: [u8; NUM_BYTES_FIELD_ELEMENT],
    pub x_memory_records: [MemoryReadRecord; NUM_WORDS_FIELD_ELEMENT],
    pub y_memory_records: [MemoryWriteRecord; NUM_WORDS_FIELD_ELEMENT],
}

pub const NUM_K256_DECOMPRESS_COLS: usize = size_of::<K256DecompressCols<u8>>();

/// A chip that computes `K256Decompress` given a pointer to a 16 word slice formatted as such:
/// input[0] is the sign bit. The second half of the slice is the compressed X in little endian.
///
/// After `K256Decompress`, the first 32 bytes of the slice are overwritten with the decompressed Y.
#[derive(Default)]
pub struct K256DecompressChip;

impl K256DecompressChip {
    pub fn new() -> Self {
        Self
    }
}

impl Syscall for K256DecompressChip {
    fn num_extra_cycles(&self) -> u32 {
        0
    }

    fn execute(&self, rt: &mut SyscallContext, slice_ptr: u32, is_odd: u32) -> Option<u32> {
        let start_clk = rt.clk;
        assert!(slice_ptr % 4 == 0, "slice_ptr must be 4-byte aligned");
        assert!(is_odd <= 1, "is_odd must be 0 or 1");

        let (x_memory_records_vec, x_vec) = rt.mr_slice(
            slice_ptr + (COMPRESSED_POINT_BYTES as u32),
            NUM_WORDS_FIELD_ELEMENT,
        );
        let x_memory_records: [MemoryReadRecord; 8] = x_memory_records_vec.try_into().unwrap();

        let x_bytes: [u8; COMPRESSED_POINT_BYTES] = words_to_bytes_le(&x_vec);
        let mut x_bytes_be = x_bytes;
        x_bytes_be.reverse();

        // Compute actual decompressed Y
        let computed_point =
            k256::AffinePoint::decompress((&x_bytes_be).into(), Choice::from(is_odd as u8))
                .unwrap();

        let decompressed_point = computed_point.to_encoded_point(false);
        let decompressed_point_bytes = decompressed_point.as_bytes();
        let mut decompressed_y_bytes = [0_u8; NUM_BYTES_FIELD_ELEMENT];
        decompressed_y_bytes
            .copy_from_slice(&decompressed_point_bytes[1 + NUM_BYTES_FIELD_ELEMENT..]);
        decompressed_y_bytes.reverse();
        let y_words: [u32; NUM_WORDS_FIELD_ELEMENT] = bytes_to_words_le(&decompressed_y_bytes);

        let y_memory_records_vec = rt.mw_slice(slice_ptr, &y_words);
        let y_memory_records: [MemoryWriteRecord; 8] = y_memory_records_vec.try_into().unwrap();

        let shard = rt.current_shard();
        rt.record_mut()
            .k256_decompress_events
            .push(K256DecompressEvent {
                shard,
                clk: start_clk,
                ptr: slice_ptr,
                is_odd: is_odd != 0,
                x_bytes,
                decompressed_y_bytes,
                x_memory_records,
                y_memory_records,
            });

        None
    }
}

#[derive(Debug, Clone, AlignedBorrow)]
#[repr(C)]
pub struct K256DecompressCols<T> {
    pub is_real: T,
    pub shard: T,
    pub clk: T,
    pub ptr: T,
    pub is_odd: T,
    pub x_access: [MemoryReadCols<T>; NUM_WORDS_FIELD_ELEMENT],
    pub y_access: [MemoryReadWriteCols<T>; NUM_WORDS_FIELD_ELEMENT],
    pub(crate) x_2: FieldOpCols<T, Secp256k1BaseField>,
    pub(crate) x_3: FieldOpCols<T, Secp256k1BaseField>,
    pub(crate) x_3_plus_b: FieldOpCols<T, Secp256k1BaseField>,
    pub(crate) y: FieldSqrtCols<T, Secp256k1BaseField>,
    pub(crate) neg_y: FieldOpCols<T, Secp256k1BaseField>,
    pub(crate) y_least_bits: [T; 8],
}

impl<F: PrimeField32> K256DecompressCols<F> {
    pub fn populate(&mut self, event: K256DecompressEvent, record: &mut ExecutionRecord) {
        let mut new_byte_lookup_events = Vec::new();
        self.is_real = F::from_bool(true);
        self.shard = F::from_canonical_u32(event.shard);
        self.clk = F::from_canonical_u32(event.clk);
        self.ptr = F::from_canonical_u32(event.ptr);
        self.is_odd = F::from_canonical_u32(event.is_odd as u32);
        for i in 0..8 {
            self.x_access[i].populate(event.x_memory_records[i], &mut new_byte_lookup_events);
            self.y_access[i].populate_write(event.y_memory_records[i], &mut new_byte_lookup_events);
        }

        let x = &BigUint::from_bytes_le(&event.x_bytes);
        self.populate_field_ops(&mut new_byte_lookup_events, event.shard, x);

        record.add_byte_lookup_events(new_byte_lookup_events);
    }

    fn populate_field_ops(
        &mut self,
        blu_events: &mut Vec<ByteLookupEvent>,
        shard: u32,
        x: &BigUint,
    ) {
        // Y = sqrt(x^3 + b)
        let x_2 = self.x_2.populate(
            blu_events,
            shard,
            &x.clone(),
            &x.clone(),
            FieldOperation::Mul,
        );
        let x_3 = self
            .x_3
            .populate(blu_events, shard, &x_2, x, FieldOperation::Mul);
        let b = Secp256k1Parameters::b_int();
        let x_3_plus_b = self
            .x_3_plus_b
            .populate(blu_events, shard, &x_3, &b, FieldOperation::Add);
        let y = self
            .y
            .populate(blu_events, shard, &x_3_plus_b, secp256k1_sqrt);
        let zero = BigUint::zero();
        self.neg_y
            .populate(blu_events, shard, &zero, &y, FieldOperation::Sub);
        // Decompose bits of least significant Y byte
        let y_bytes = y.to_bytes_le();
        let y_lsb = if y_bytes.is_empty() { 0 } else { y_bytes[0] };
        for i in 0..8 {
            self.y_least_bits[i] = F::from_canonical_u32(((y_lsb >> i) & 1) as u32);
        }
    }
}

impl<V: Copy> K256DecompressCols<V> {
    pub fn eval<AB: SP1AirBuilder<Var = V>>(&self, builder: &mut AB)
    where
        V: Into<AB::Expr>,
    {
        builder.assert_bool(self.is_odd);

        let x: Limbs<V, U32> = limbs_from_prev_access(&self.x_access);
        self.x_2.eval(
            builder,
            &x,
            &x,
            FieldOperation::Mul,
            self.shard,
            self.is_real,
        );
        self.x_3.eval(
            builder,
            &self.x_2.result,
            &x,
            FieldOperation::Mul,
            self.shard,
            self.is_real,
        );
        let b = Secp256k1Parameters::b_int();
        let b_const = Secp256k1BaseField::to_limbs_field::<AB::F, _>(&b);
        self.x_3_plus_b.eval(
            builder,
            &self.x_3.result,
            &b_const,
            FieldOperation::Add,
            self.shard,
            self.is_real,
        );
        self.y
            .eval(builder, &self.x_3_plus_b.result, self.shard, self.is_real);
        self.neg_y.eval(
            builder,
            &[AB::Expr::zero()].iter(),
            &self.y.multiplication.result,
            FieldOperation::Sub,
            self.shard,
            self.is_real,
        );

        // Constrain decomposition of least significant byte of Y into `y_least_bits`
        for i in 0..8 {
            builder.when(self.is_real).assert_bool(self.y_least_bits[i]);
        }
        let y_least_byte = self.y.multiplication.result.0[0];
        let powers_of_two = [1, 2, 4, 8, 16, 32, 64, 128].map(AB::F::from_canonical_u32);
        let recomputed_byte: AB::Expr = self
            .y_least_bits
            .iter()
            .zip(powers_of_two)
            .map(|(p, b)| (*p).into() * b)
            .sum();
        builder
            .when(self.is_real)
            .assert_eq(recomputed_byte, y_least_byte);

        // Interpret the lowest bit of Y as whether it is odd or not.
        let y_is_odd = self.y_least_bits[0];

        // Constrain that the result is written into the Y memory access.
        // When y_is_odd == should_be_odd, result is y
        // (Equivalent: y_is_odd != !should_be_odd)
        let y_limbs: Limbs<V, U32> = limbs_from_access(&self.y_access);
        builder
            .when(self.is_real)
            .when_ne(y_is_odd.into(), AB::Expr::one() - self.is_odd)
            .assert_all_eq(self.y.multiplication.result, y_limbs);
        // When y_is_odd != should_be_odd, result is -y.
        builder
            .when(self.is_real)
            .when_ne(y_is_odd, self.is_odd)
            .assert_all_eq(self.neg_y.result, y_limbs);

        for i in 0..NUM_WORDS_FIELD_ELEMENT {
            builder.eval_memory_access(
                self.shard,
                self.clk,
                self.ptr.into() + AB::F::from_canonical_u32((i as u32) * 4 + 32),
                &self.x_access[i],
                self.is_real,
            );
        }
        for i in 0..NUM_WORDS_FIELD_ELEMENT {
            builder.eval_memory_access(
                self.shard,
                self.clk,
                self.ptr.into() + AB::F::from_canonical_u32((i as u32) * 4),
                &self.y_access[i],
                self.is_real,
            );
        }

        builder.receive_syscall(
            self.shard,
            self.clk,
            AB::F::from_canonical_u32(SyscallCode::SECP256K1_DECOMPRESS.syscall_id()),
            self.ptr,
            self.is_odd,
            self.is_real,
        );
    }
}

impl<F: PrimeField32> MachineAir<F> for K256DecompressChip {
    type Record = ExecutionRecord;

    type Program = Program;

    fn name(&self) -> String {
        "K256Decompress".to_string()
    }

    fn generate_trace(
        &self,
        input: &ExecutionRecord,
        output: &mut ExecutionRecord,
    ) -> RowMajorMatrix<F> {
        let mut rows = Vec::new();

        for i in 0..input.k256_decompress_events.len() {
            let event = input.k256_decompress_events[i].clone();
            let mut row = [F::zero(); NUM_K256_DECOMPRESS_COLS];
            let cols: &mut K256DecompressCols<F> = row.as_mut_slice().borrow_mut();
            cols.populate(event.clone(), output);

            rows.push(row);
        }

        pad_rows(&mut rows, || {
            let mut row = [F::zero(); NUM_K256_DECOMPRESS_COLS];
            let cols: &mut K256DecompressCols<F> = row.as_mut_slice().borrow_mut();
            // This is a random X that has a valid result -> sqrt(X^3 + 7)
            let dummy_value = BigUint::from_str(
                "51105774234531842101418790951965073327923166504008437065779899608172467027456",
            )
            .unwrap();
            let dummy_bytes = dummy_value.to_bytes_le();
            // TODO: clean up into "bytes to words" util
            let mut full_dummy_bytes = [0u8; COMPRESSED_POINT_BYTES];
            full_dummy_bytes[0..32].copy_from_slice(&dummy_bytes);
            for i in 0..8 {
                let word_bytes = dummy_bytes[i * 4..(i + 1) * 4]
                    .iter()
                    .map(|x| F::from_canonical_u8(*x))
                    .collect::<Vec<_>>()
                    .try_into()
                    .unwrap();
                cols.x_access[i].access.value = Word(word_bytes);
            }
            cols.populate_field_ops(&mut vec![], 0, &dummy_value);
            row
        });

        RowMajorMatrix::new(
            rows.into_iter().flatten().collect::<Vec<_>>(),
            NUM_K256_DECOMPRESS_COLS,
        )
    }

    fn included(&self, shard: &Self::Record) -> bool {
        !shard.k256_decompress_events.is_empty()
    }
}

impl<F> BaseAir<F> for K256DecompressChip {
    fn width(&self) -> usize {
        NUM_K256_DECOMPRESS_COLS
    }
}

impl<AB> Air<AB> for K256DecompressChip
where
    AB: SP1AirBuilder,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let row = main.row_slice(0);
        let row: &K256DecompressCols<AB::Var> = (*row).borrow();
        row.eval::<AB>(builder);
    }
}

#[cfg(test)]
pub mod tests {

    use elliptic_curve::sec1::ToEncodedPoint;
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    use crate::utils::run_test;
    use crate::utils::run_test_io;
    use crate::utils::setup_logger;
    use crate::utils::tests::ECRECOVER_ELF;
    use crate::utils::tests::SECP256K1_DECOMPRESS_ELF;
    use crate::Program;
    use crate::SP1Stdin;

    #[test]
    fn test_k256_decompress() {
        setup_logger();
        let mut rng = StdRng::seed_from_u64(2);

        for _ in 0..1 {
            let secret_key = k256::SecretKey::random(&mut rng);
            let public_key = secret_key.public_key();
            let encoded = public_key.to_encoded_point(false);
            let decompressed = encoded.as_bytes();
            let compressed = public_key.to_sec1_bytes();

            let inputs = SP1Stdin::from(&compressed);

            let mut proof = run_test_io(Program::from(SECP256K1_DECOMPRESS_ELF), inputs).unwrap();
            let mut result = [0; 65];
            proof.public_values.read_slice(&mut result);
            assert_eq!(result, decompressed);
        }
    }

    #[test]
    fn test_ecrecover_program() {
        setup_logger();
        let program = Program::from(ECRECOVER_ELF);
        run_test(program).unwrap();
    }
}
