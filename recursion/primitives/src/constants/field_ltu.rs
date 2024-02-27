use p3_air::VirtualPairCol;
use p3_baby_bear::BabyBear;
use sp1_core::stark::FieldLTUChip;
use sp1_core::{
    lookup::{Interaction, InteractionKind},
    stark::{Chip, RiscvAir},
};
use std::borrow::Cow;

const FIELD_LTU_RECEIVES: &[Interaction<BabyBear>] = &[];

const FIELD_LTU_SENDS: &[Interaction<BabyBear>] = &[Interaction {
    values: Cow::Borrowed(&[]),
    multiplicity: VirtualPairCol::new_borrowed(&[], BabyBear::new(0)),
    kind: InteractionKind::Memory,
}];

const FIELD_LTU_CHIP: Chip<BabyBear, RiscvAir<BabyBear>> = Chip::from_parts(
    RiscvAir::FieldLTU(FieldLTUChip),
    Cow::Borrowed(FIELD_LTU_SENDS),
    Cow::Borrowed(FIELD_LTU_RECEIVES),
    1,
);

// Chip: Chip { air: "MemoryFinalize", sends: [Interaction { values: [VirtualPairCol { column_weights: [(Main(0), 1)], constant: 0 }, VirtualPairCol { column_weights: [(Main(1), 1)], constant: 0 }, VirtualPairCol { column_weights: [(Main(2), 1)], constant: 0 }, VirtualPairCol { column_weights: [(Main(3), 1)], constant: 0 }, VirtualPairCol { column_weights: [(Main(4), 1)], constant: 0 }, VirtualPairCol { column_weights: [(Main(5), 1)], constant: 0 }, VirtualPairCol { column_weights: [(Main(6), 1)], constant: 0 }], multiplicity: VirtualPairCol { column_weights: [(Main(7), 1)], constant: 0 }, kind: Memory }], receives: [], log_quotient_degree: 1 }
