use num::{One, Zero};
use powdr_autoprecompiles::memory_optimizer::{
    MemoryBusInteraction, MemoryBusInteractionConversionError, MemoryOp,
};
use powdr_constraint_solver::{
    constraint_system::BusInteraction, grouped_expression::GroupedExpression,
};
use powdr_number::KoalaBearField;
use std::{
    fmt::Display,
    hash::Hash,
    iter::{once, Chain},
};

pub struct Sp1MemoryBusInteraction<V> {
    addr: MemoryAddress<V>,
    data: Vec<GroupedExpression<KoalaBearField, V>>,
    timestamp: Vec<GroupedExpression<KoalaBearField, V>>,
    op: MemoryOp,
}

// We introduce an "artificial" address space to distinguish between register and RAM accesses.
// It is guaranteed by the constraints of SP1 that RAM accesses don't go to the register memory
// space (RAM access must go to addresses > 2^16), but the memory optimizer doesn't infer that.
// Luckily, we can easily detect register accesses, because they will always have the higher
// address limbs set to zero at compile time.
#[derive(Clone, Hash, Eq, PartialEq)]
pub enum ArtificialAddressSpace {
    Register,
    Ram,
}

#[derive(Clone, Hash, Eq, PartialEq)]
pub struct MemoryAddress<V> {
    address_space: ArtificialAddressSpace,
    /// The memory address, represented as 3 16-Bit limbs in little-endian order.
    addr: [GroupedExpression<KoalaBearField, V>; 3],
}

impl<V: Ord + Clone + Eq + Display + Hash> MemoryAddress<V> {
    pub fn new(addr: [GroupedExpression<KoalaBearField, V>; 3]) -> Self {
        let address_space = if addr[1].is_zero() && addr[2].is_zero() {
            ArtificialAddressSpace::Register
        } else {
            ArtificialAddressSpace::Ram
        };
        Self { address_space, addr }
    }
}

impl<V: Ord + Clone + Eq + Display + Hash> IntoIterator for MemoryAddress<V> {
    type Item = GroupedExpression<KoalaBearField, V>;
    type IntoIter = Chain<
        std::iter::Once<GroupedExpression<KoalaBearField, V>>,
        std::array::IntoIter<GroupedExpression<KoalaBearField, V>, 3>,
    >;

    fn into_iter(self) -> Self::IntoIter {
        let address_space = match self.address_space {
            ArtificialAddressSpace::Register => KoalaBearField::zero(),
            ArtificialAddressSpace::Ram => KoalaBearField::one(),
        };
        once(GroupedExpression::from_number(address_space)).chain(self.addr)
    }
}

impl<V: Ord + Clone + Eq + Display + Hash> MemoryBusInteraction<KoalaBearField, V>
    for Sp1MemoryBusInteraction<V>
{
    type Address = MemoryAddress<V>;

    fn try_from_bus_interaction(
        bus_interaction: &BusInteraction<GroupedExpression<KoalaBearField, V>>,
        memory_bus_id: u64,
    ) -> Result<Option<Self>, MemoryBusInteractionConversionError> {
        // Format is: (clk_high, clk_low, addr (3 limbs), value (4 limbs))
        // See: crates/core/machine/src/air/memory.rs

        match bus_interaction.bus_id.try_to_number() {
            None => return Err(MemoryBusInteractionConversionError),
            Some(id) if id == memory_bus_id.into() => {}
            Some(_) => return Ok(None),
        }

        let op = match bus_interaction.multiplicity.try_to_number() {
            // SP1 *sends* the previous values and *receives* the new values.
            Some(n) if n == 1.into() => MemoryOp::GetPrevious,
            Some(n) if n == (-1).into() => MemoryOp::SetNew,
            _ => return Err(MemoryBusInteractionConversionError),
        };

        let [clk_high, clk_low, addr0, addr1, addr2, data0, data1, data2, data3] =
            &bus_interaction.payload[..]
        else {
            panic!()
        };
        let addr = MemoryAddress::new([addr0.clone(), addr1.clone(), addr2.clone()]);
        let data = vec![data0.clone(), data1.clone(), data2.clone(), data3.clone()];
        let timestamp = vec![clk_high.clone(), clk_low.clone()];
        Ok(Some(Sp1MemoryBusInteraction { addr, data, timestamp, op }))
    }

    fn addr(&self) -> Self::Address {
        self.addr.clone()
    }

    fn data(&self) -> &[GroupedExpression<KoalaBearField, V>] {
        &self.data
    }

    fn op(&self) -> powdr_autoprecompiles::memory_optimizer::MemoryOp {
        self.op
    }

    fn timestamp_limbs(&self) -> &[GroupedExpression<KoalaBearField, V>] {
        &self.timestamp
    }
}
