#include "babybear.hpp"
#include "sys.hpp"

using namespace sp1_core_machine_sys;

namespace sp1_recursion_core_sys
{
    extern void alu_base_event_to_row_babybear(const BaseAluIo<BabyBearP3> *io, BaseAluValueCols<BabyBearP3> *cols)
    {
        alu_base::event_to_row<BabyBear>(
            *reinterpret_cast<const BaseAluIo<BabyBear> *>(io),
            *reinterpret_cast<BaseAluValueCols<BabyBear> *>(cols));
    }
    extern void alu_base_instr_to_row_babybear(const BaseAluInstr<BabyBearP3> *instr, BaseAluAccessCols<BabyBearP3> *access)
    {
        alu_base::instr_to_row<BabyBear>(
            *reinterpret_cast<const BaseAluInstr<BabyBear> *>(instr),
            *reinterpret_cast<BaseAluAccessCols<BabyBear> *>(access));
    }

    extern void alu_ext_event_to_row_babybear(const ExtAluIo<Block<BabyBearP3>> *io, ExtAluValueCols<BabyBearP3> *cols)
    {
        alu_ext::event_to_row<BabyBear>(
            *reinterpret_cast<const ExtAluIo<Block<BabyBear>> *>(io),
            *reinterpret_cast<ExtAluValueCols<BabyBear> *>(cols));
    }
    extern void alu_ext_instr_to_row_babybear(const ExtAluInstr<BabyBearP3> *instr, ExtAluAccessCols<BabyBearP3> *access)
    {
        alu_ext::instr_to_row<BabyBear>(
            *reinterpret_cast<const ExtAluInstr<BabyBear> *>(instr),
            *reinterpret_cast<ExtAluAccessCols<BabyBear> *>(access));
    }

    extern void batch_fri_event_to_row_babybear(const BatchFRIEvent<BabyBearP3> *io, BatchFRICols<BabyBearP3> *cols)
    {
        batch_fri::event_to_row<BabyBear>(
            *reinterpret_cast<const BatchFRIEvent<BabyBear> *>(io),
            *reinterpret_cast<BatchFRICols<BabyBear> *>(cols));
    }
    extern void batch_fri_instr_to_row_babybear(const BatchFRIInstrFFI<BabyBearP3> *instr, BatchFRIPreprocessedCols<BabyBearP3> *cols)
    {
        batch_fri::instr_to_row<BabyBear>(
            *reinterpret_cast<const BatchFRIInstrFFI<BabyBear> *>(instr),
            *reinterpret_cast<BatchFRIPreprocessedCols<BabyBear> *>(cols));
    }

    extern void exp_reverse_bits_event_to_row_babybear(
        const ExpReverseBitsEventFFI<BabyBearP3> *io,
        size_t i,
        ExpReverseBitsLenCols<BabyBearP3> *cols)
    {
        exp_reverse_bits::event_to_row<BabyBear>(
            *reinterpret_cast<const ExpReverseBitsEventFFI<BabyBear> *>(io),
            i,
            *reinterpret_cast<ExpReverseBitsLenCols<BabyBear> *>(cols));
    }
    extern void exp_reverse_bits_instr_to_row_babybear(
        const ExpReverseBitsInstrFFI<BabyBearP3> *instr,
        size_t i,
        size_t len,
        ExpReverseBitsLenPreprocessedCols<BabyBearP3> *cols)
    {
        exp_reverse_bits::instr_to_row<BabyBear>(
            *reinterpret_cast<const ExpReverseBitsInstrFFI<BabyBear> *>(instr),
            i,
            len,
            *reinterpret_cast<ExpReverseBitsLenPreprocessedCols<BabyBear> *>(cols));
    }

    extern void fri_fold_event_to_row_babybear(const FriFoldEvent<BabyBearP3> *io, FriFoldCols<BabyBearP3> *cols)
    {
        fri_fold::event_to_row<BabyBear>(
            *reinterpret_cast<const FriFoldEvent<BabyBear> *>(io),
            *reinterpret_cast<FriFoldCols<BabyBear> *>(cols));
    }
    extern void fri_fold_instr_to_row_babybear(const FriFoldInstrFFI<BabyBearP3> *instr, size_t i, FriFoldPreprocessedCols<BabyBearP3> *cols)
    {
        fri_fold::instr_to_row<BabyBear>(
            *reinterpret_cast<const FriFoldInstrFFI<BabyBear> *>(instr),
            i,
            *reinterpret_cast<FriFoldPreprocessedCols<BabyBear> *>(cols));
    }

    extern void public_values_event_to_row_babybear(const CommitPublicValuesEvent<BabyBearP3> *io, size_t digest_idx, PublicValuesCols<BabyBearP3> *cols)
    {
        public_values::event_to_row<BabyBear>(
            *reinterpret_cast<const CommitPublicValuesEvent<BabyBear> *>(io),
            digest_idx,
            *reinterpret_cast<PublicValuesCols<BabyBear> *>(cols));
    }
    extern void public_values_instr_to_row_babybear(const CommitPublicValuesInstr<BabyBearP3> *instr, size_t digest_idx, PublicValuesPreprocessedCols<BabyBearP3> *cols)
    {
        public_values::instr_to_row<BabyBear>(
            *reinterpret_cast<const CommitPublicValuesInstr<BabyBear> *>(instr),
            digest_idx,
            *reinterpret_cast<PublicValuesPreprocessedCols<BabyBear> *>(cols));
    }

    extern void select_event_to_row_babybear(const SelectEvent<BabyBearP3> *io, SelectCols<BabyBearP3> *cols)
    {
        select::event_to_row<BabyBear>(
            *reinterpret_cast<const SelectEvent<BabyBear> *>(io),
            *reinterpret_cast<SelectCols<BabyBear> *>(cols));
    }
    extern void select_instr_to_row_babybear(const SelectInstr<BabyBearP3> *instr, SelectPreprocessedCols<BabyBearP3> *cols)
    {
        select::instr_to_row<BabyBear>(
            *reinterpret_cast<const SelectInstr<BabyBear> *>(instr),
            *reinterpret_cast<SelectPreprocessedCols<BabyBear> *>(cols));
    }

    extern void poseidon2_skinny_event_to_row_babybear(const Poseidon2Event<BabyBearP3> *io, Poseidon2<BabyBearP3> *cols[NUM_EXTERNAL_ROUNDS + 3])
    {
        poseidon2_skinny::event_to_row<BabyBear>(
            *reinterpret_cast<const Poseidon2Event<BabyBear> *>(io),
            *reinterpret_cast<Poseidon2<BabyBear> *(*)[NUM_EXTERNAL_ROUNDS + 3]>(&cols));
    }
} // namespace sp1_recursion_core_sys
