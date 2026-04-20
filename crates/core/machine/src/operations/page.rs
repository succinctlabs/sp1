use slop_air::AirBuilder;
use slop_algebra::{AbstractField, Field, PrimeField32};
use sp1_core_executor::{
    events::{ByteLookupEvent, ByteRecord, PageProtRecord},
    ByteOpcode,
};
use sp1_derive::AlignedBorrow;
use sp1_hypercube::air::{BaseAirBuilder, SP1AirBuilder};
use sp1_primitives::consts::{
    split_page_idx, PAGE_SIZE, PROT_FAILURE_READ, PROT_FAILURE_WRITE, PROT_READ, PROT_WRITE,
};

use crate::{air::MemoryAirBuilder, memory::PageProtAccessCols};

/// A set of columns needed to compute the page_idx from an address.
#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct PageOperation<T> {
    /// Split that least significant limb into a 4 bit limb and a 12 bit limb.
    pub addr_4_bits: T,
    pub addr_12_bits: T,
}

impl<F: Field> PageOperation<F> {
    pub fn populate(&mut self, record: &mut impl ByteRecord, addr: u64) {
        let addr_12_bits: u16 = (addr & 0xFFF).try_into().unwrap();
        let addr_4_bits: u16 = ((addr >> 12) & 0xF).try_into().unwrap();

        self.addr_12_bits = F::from_canonical_u16(addr_12_bits);
        self.addr_4_bits = F::from_canonical_u16(addr_4_bits);

        record.add_bit_range_check(addr_12_bits, 12);
        record.add_bit_range_check(addr_4_bits, 4);
    }

    /// Evaluate the calculation of the page idx from the address.
    pub fn eval<AB: SP1AirBuilder>(
        builder: &mut AB,
        addr: &[AB::Expr; 3],
        cols: PageOperation<AB::Var>,
        is_real: AB::Expr,
    ) -> [AB::Expr; 3] {
        builder.assert_bool(is_real.clone());

        // Check that the least significant address limb is correctly decomposed to the 4 bit limb
        // and the 12 bit limb.
        builder.when(is_real.clone()).assert_eq(
            addr[0].clone(),
            cols.addr_12_bits + cols.addr_4_bits * (AB::Expr::from_canonical_u32(1 << 12)),
        );
        // Range check the limbs.
        builder.send_byte(
            AB::Expr::from_canonical_u32(ByteOpcode::Range as u32),
            cols.addr_4_bits.into(),
            AB::Expr::from_canonical_u32(4),
            AB::Expr::zero(),
            is_real.clone(),
        );
        builder.send_byte(
            AB::Expr::from_canonical_u32(ByteOpcode::Range as u32),
            cols.addr_12_bits.into(),
            AB::Expr::from_canonical_u32(12),
            AB::Expr::zero(),
            is_real.clone(),
        );

        [cols.addr_4_bits.into(), addr[1].clone(), addr[2].clone()]
    }
}

/// A set of columns needed to retrieve the page permissions from an address.
#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct PageProtOperation<T> {
    /// The page operation to calculate page idx from address.
    pub page_op: PageOperation<T>,

    /// The page prot access columns.
    pub page_prot_access: PageProtAccessCols<T>,
}

impl<F: PrimeField32> PageProtOperation<F> {
    pub fn populate(
        &mut self,
        record: &mut impl ByteRecord,
        addr: u64,
        clk: u64,
        previous_page_prot_access: &PageProtRecord,
    ) {
        self.page_op.populate(record, addr);

        assert!(previous_page_prot_access.timestamp < clk);
        self.page_prot_access.populate(previous_page_prot_access, clk, record);
    }
}

impl<F: Field> PageProtOperation<F> {
    pub fn eval<AB: SP1AirBuilder>(
        builder: &mut AB,
        clk_high: AB::Expr,
        clk_low: AB::Expr,
        addr: &[AB::Expr; 3],
        cols: PageProtOperation<AB::Var>,
        is_real: AB::Expr,
    ) {
        builder.assert_bool(is_real.clone());

        let page_idx = PageOperation::<AB::F>::eval(builder, addr, cols.page_op, is_real.clone());

        builder.eval_page_prot_access_read(
            clk_high,
            clk_low,
            &page_idx,
            cols.page_prot_access,
            is_real.clone(),
        );
    }
}

/// A set of columns needed to check if two page indices are equal or adjacent.
#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct PageIsEqualOrAdjacentOperation<T> {
    pub is_overflow: T,

    // Bool flag that is set to 0 if equal, 1 if adjacent.
    pub is_adjacent: T,
}

impl<F: Field> PageIsEqualOrAdjacentOperation<F> {
    pub fn populate(&mut self, curr_page_idx: u64, next_page_idx: u64) {
        if curr_page_idx == next_page_idx {
            self.is_adjacent = F::zero();
        } else if curr_page_idx + 1 == next_page_idx {
            self.is_adjacent = F::one();
        } else {
            panic!("curr_page_idx and next_page_idx are not equal or adjacent");
        }

        // Check that the bottom 20 bits of the next page are 0, if so we know there's an overflow
        // into the third limb
        let next_page_limbs = split_page_idx(next_page_idx);
        let next_page_20_bits = next_page_limbs[0] as u64 + ((next_page_limbs[1] as u64) << 4);

        // Check for overflow.
        self.is_overflow = F::from_bool(next_page_20_bits == 0);
    }

    pub fn eval<AB: SP1AirBuilder>(
        builder: &mut AB,
        curr_page_idx: [AB::Expr; 3],
        next_page_idx: [AB::Expr; 3],
        cols: PageIsEqualOrAdjacentOperation<AB::Var>,
        is_real: AB::Expr,
    ) {
        builder.assert_bool(is_real.clone());
        builder.assert_bool(cols.is_adjacent);
        builder.assert_bool(cols.is_overflow);

        // Combine the 1st and 2nd limbs.  The 1st limb is 4 bits and the 2nd limb is 16 bits.
        let curr_page_20_bits = curr_page_idx[0].clone()
            + curr_page_idx[1].clone() * (AB::Expr::from_canonical_u32(1 << 4));
        let next_page_20_bits = next_page_idx[0].clone()
            + next_page_idx[1].clone() * (AB::Expr::from_canonical_u32(1 << 4));

        // First check for the case when they are equal.
        builder
            .when(is_real.clone())
            .when_not(cols.is_adjacent)
            .assert_eq(curr_page_20_bits.clone(), next_page_20_bits.clone());
        builder
            .when(is_real.clone())
            .when_not(cols.is_adjacent)
            .assert_eq(curr_page_idx[2].clone(), next_page_idx[2].clone());

        // Now check if they are adjacent.

        // First check to see is_adjacent == 1, then is_real == 1.
        // This is so that we don't need to check for is_real when is_adjacent == 1.
        builder.when(cols.is_adjacent).assert_one(is_real.clone());

        let mut is_adjacent_builder = builder.when(cols.is_adjacent);

        // Find out what each limb's relationship should be.
        // If !is_overflow -> (20bit limbs are adjacent, 3rd limb is equal).
        // if is_overflow -> (20bit limbs are at boundary, 3rd limb is adjacent).

        // Check that first page bottom 20 bits are adjacent to second page bottom 20 bits
        is_adjacent_builder
            .when_not(cols.is_overflow)
            .assert_eq(curr_page_20_bits.clone() + AB::Expr::one(), next_page_20_bits.clone());

        // Check that top limbs are equal
        is_adjacent_builder
            .when_not(cols.is_overflow)
            .assert_eq(curr_page_idx[2].clone(), next_page_idx[2].clone());

        // Check that first page bottom 20 bits are maxed out
        is_adjacent_builder
            .when(cols.is_overflow)
            .assert_eq(curr_page_20_bits, AB::Expr::from_canonical_u32((1 << 20) - 1));

        // Check that second page bottom 20 bits are 0
        is_adjacent_builder.when(cols.is_overflow).assert_eq(next_page_20_bits, AB::Expr::zero());

        // Check that top limb (top 16 bits) of second page is 1 more than top limb of first page
        is_adjacent_builder
            .when(cols.is_overflow)
            .assert_eq(curr_page_idx[2].clone() + AB::Expr::one(), next_page_idx[2].clone());
    }
}

/// A set of columns needed to check the page prot permissions and return the trap code.
#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct TrapPageProtOperation<T> {
    pub page_prot_access: PageProtAccessCols<T>,
    pub is_read_fail: T,
    pub is_write_fail: T,
    pub is_now_trap: T,
}

#[allow(clippy::too_many_arguments)]
impl<F: PrimeField32> TrapPageProtOperation<F> {
    #[allow(clippy::too_many_arguments)]
    pub fn populate(
        &mut self,
        record: &mut impl ByteRecord,
        clk: u64,
        permissions: u8,
        page_prot_access: PageProtRecord,
        is_not_trap: &mut bool,
        trap_code: &mut u8,
    ) {
        assert!(*is_not_trap);
        self.page_prot_access.populate(&page_prot_access, clk, record);
        let perm = page_prot_access.page_prot;
        if permissions == PROT_READ {
            self.is_read_fail = F::from_bool((perm & PROT_READ) == 0);
            self.is_write_fail = F::zero();
            self.is_now_trap = self.is_read_fail;
            if self.is_now_trap == F::one() {
                *trap_code = PROT_FAILURE_READ as u8;
            }
        }
        if permissions == PROT_WRITE {
            self.is_read_fail = F::zero();
            self.is_write_fail = F::from_bool((perm & PROT_WRITE) == 0);
            self.is_now_trap = self.is_write_fail;
            if self.is_now_trap == F::one() {
                *trap_code = PROT_FAILURE_WRITE as u8;
            }
        }
        if permissions == (PROT_READ | PROT_WRITE) {
            self.is_read_fail = F::from_bool((perm & PROT_READ) == 0);
            self.is_write_fail = F::from_bool((perm & PROT_WRITE) == 0);
            self.is_now_trap = F::from_bool((perm & permissions) != permissions);
            if self.is_read_fail == F::one() {
                *trap_code = PROT_FAILURE_READ as u8;
            } else if self.is_write_fail == F::one() {
                *trap_code = PROT_FAILURE_WRITE as u8;
            }
        }
        record.add_byte_lookup_event(ByteLookupEvent {
            opcode: ByteOpcode::AND,
            a: (perm & permissions) as u16,
            b: perm,
            c: permissions,
        });
        if self.is_now_trap == F::one() {
            *is_not_trap = false;
        }
    }
}

impl<F: Field> TrapPageProtOperation<F> {
    #[allow(clippy::too_many_arguments)]
    pub fn eval<AB: SP1AirBuilder>(
        builder: &mut AB,
        clk_high: AB::Expr,
        clk_low: AB::Expr,
        page_idx: &[AB::Expr; 3],
        permissions: u8,
        cols: &TrapPageProtOperation<AB::Var>,
        is_real: AB::Expr,
        is_not_trap: &mut AB::Expr,
        trap_code: &mut AB::Expr,
    ) {
        builder.assert_bool(is_real.clone());
        builder.when(is_real.clone()).assert_one(is_not_trap.clone());
        builder.eval_page_prot_access_read(
            clk_high.clone(),
            clk_low.clone(),
            page_idx,
            cols.page_prot_access,
            is_real.clone(),
        );

        let perm = cols.page_prot_access.prev_prot_bitmap;

        let mut permission_and = AB::Expr::zero();

        if permissions == PROT_READ {
            permission_and =
                (AB::Expr::one() - cols.is_read_fail) * AB::Expr::from_canonical_u8(PROT_READ);
            builder.assert_zero(cols.is_write_fail);
        }
        if permissions == PROT_WRITE {
            permission_and =
                (AB::Expr::one() - cols.is_write_fail) * AB::Expr::from_canonical_u8(PROT_WRITE);
            builder.assert_zero(cols.is_read_fail);
        }
        if permissions == (PROT_READ | PROT_WRITE) {
            permission_and = permission_and.clone()
                + (AB::Expr::one() - cols.is_read_fail) * AB::Expr::from_canonical_u8(PROT_READ);
            permission_and = permission_and.clone()
                + (AB::Expr::one() - cols.is_write_fail) * AB::Expr::from_canonical_u8(PROT_WRITE);
        }

        builder.send_byte(
            AB::Expr::from_canonical_u8(ByteOpcode::AND as u8),
            permission_and.clone(),
            perm.into(),
            AB::Expr::from_canonical_u8(permissions),
            is_real.clone(),
        );

        builder.when_not(is_real.clone()).assert_zero(cols.is_now_trap);
        builder.when_not(is_not_trap.clone()).assert_zero(cols.is_now_trap);
        builder.assert_bool(cols.is_now_trap);
        builder.assert_bool(cols.is_read_fail);
        builder.assert_bool(cols.is_write_fail);
        builder.assert_eq(
            cols.is_now_trap,
            cols.is_read_fail + cols.is_write_fail - cols.is_read_fail * cols.is_write_fail,
        );

        *is_not_trap = is_not_trap.clone() - cols.is_now_trap.into();
        *trap_code = trap_code.clone()
            + cols.is_read_fail * AB::Expr::from_canonical_u64(PROT_FAILURE_READ)
            + (cols.is_now_trap - cols.is_read_fail)
                * AB::Expr::from_canonical_u64(PROT_FAILURE_WRITE);
    }
}

/// A set of columns needed to check the page prot permissions for a range of addrs.
/// This operation only supports an addr range that spans at most 2 pages.
#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct AddressSlicePageProtOperation<T> {
    pub page_is_equal_or_adjacent: PageIsEqualOrAdjacentOperation<T>,
    pub page_operations: [PageOperation<T>; 2],
    pub trap_page_operations: [TrapPageProtOperation<T>; 2],
}

#[allow(clippy::too_many_arguments)]
impl<F: PrimeField32> AddressSlicePageProtOperation<F> {
    #[allow(clippy::too_many_arguments)]
    pub fn populate(
        &mut self,
        record: &mut impl ByteRecord,
        start_addr: u64,
        end_addr: u64,
        clk: u64,
        permissions: u8,
        page_prot_access: &[PageProtRecord],
        is_not_trap: &mut bool,
        trap_code: &mut u8,
    ) {
        if !(*is_not_trap) {
            assert_eq!(page_prot_access.len(), 0);
            *self = AddressSlicePageProtOperation::<F>::default();
            return;
        }

        let start_page_idx = start_addr / (PAGE_SIZE as u64);
        let end_page_idx = end_addr / (PAGE_SIZE as u64);
        assert!(start_page_idx == end_page_idx || start_page_idx + 1 == end_page_idx);

        self.page_operations[0].populate(record, start_addr);
        self.page_operations[1].populate(record, end_addr);

        assert!(!page_prot_access.is_empty());

        // Populate the first slice.
        self.trap_page_operations[0].populate(
            record,
            clk,
            permissions,
            page_prot_access[0],
            is_not_trap,
            trap_code,
        );

        if !(*is_not_trap) {
            self.trap_page_operations[1] = TrapPageProtOperation::<F>::default();
            self.page_is_equal_or_adjacent = PageIsEqualOrAdjacentOperation::<F>::default();
            return;
        }

        self.page_is_equal_or_adjacent.populate(start_page_idx, end_page_idx);

        if end_page_idx == start_page_idx + 1 {
            assert!(page_prot_access.len() == 2);
            self.trap_page_operations[1].populate(
                record,
                clk,
                permissions,
                page_prot_access[1],
                is_not_trap,
                trap_code,
            );
        } else {
            self.trap_page_operations[1] = TrapPageProtOperation::<F>::default();
        }
    }
}

impl<F: Field> AddressSlicePageProtOperation<F> {
    #[allow(clippy::too_many_arguments)]
    pub fn eval<AB: SP1AirBuilder>(
        builder: &mut AB,
        clk_high: AB::Expr,
        clk_low: AB::Expr,
        start_addr: &[AB::Expr; 3],
        end_addr: &[AB::Expr; 3],
        permissions: u8,
        cols: &AddressSlicePageProtOperation<AB::Var>,
        is_not_trap: &mut AB::Expr,
        trap_code: &mut AB::Expr,
    ) {
        builder.assert_bool(is_not_trap.clone());

        let start_page_idx = PageOperation::<AB::F>::eval(
            builder,
            start_addr,
            cols.page_operations[0],
            is_not_trap.clone(),
        );

        let end_page_idx = PageOperation::<AB::F>::eval(
            builder,
            &end_addr.clone(),
            cols.page_operations[1],
            is_not_trap.clone(),
        );

        TrapPageProtOperation::<AB::F>::eval(
            builder,
            clk_high.clone(),
            clk_low.clone(),
            &start_page_idx.clone(),
            permissions,
            &cols.trap_page_operations[0],
            is_not_trap.clone(),
            is_not_trap,
            trap_code,
        );

        PageIsEqualOrAdjacentOperation::<AB::F>::eval(
            builder,
            start_page_idx.map(Into::into),
            end_page_idx.clone().map(Into::into),
            cols.page_is_equal_or_adjacent,
            is_not_trap.clone(),
        );

        TrapPageProtOperation::<AB::F>::eval(
            builder,
            clk_high.clone(),
            clk_low.clone(),
            &end_page_idx.clone(),
            permissions,
            &cols.trap_page_operations[1],
            cols.page_is_equal_or_adjacent.is_adjacent.into(),
            is_not_trap,
            trap_code,
        );
    }
}
