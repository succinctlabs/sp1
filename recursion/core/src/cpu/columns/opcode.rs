use std::collections::HashMap;
use std::collections::HashSet;
use std::hash::Hash;

use p3_air::AirBuilder;
use p3_field::AbstractField;
use p3_field::Field;
use sp1_core::air::SP1AirBuilder;
use sp1_derive::AlignedBorrow;

use crate::{cpu::Instruction, runtime::Opcode};

const OPCODE_COUNT: usize = core::mem::size_of::<OpcodeSelectorCols<u8>>();

/// Selectors for the opcode.
///
/// This contains selectors for the different opcodes corresponding to variants of the [`Opcode`]
/// enum.
#[derive(AlignedBorrow, Clone, Copy, Default, Debug)]
#[repr(C)]
pub struct OpcodeSelectorCols<T> {
    // Arithmetic field instructions.
    pub is_add: T,
    pub is_sub: T,
    pub is_mul: T,
    pub is_div: T,

    // Arithmetic field extension operations.
    pub is_eadd: T,
    pub is_esub: T,
    pub is_emul: T,
    pub is_ediv: T,

    // Mixed arithmetic operations.
    pub is_efadd: T,
    pub is_efsub: T,
    pub is_fesub: T,
    pub is_efmul: T,
    pub is_efdiv: T,
    pub is_fediv: T,

    // Memory instructions.
    pub is_lw: T,
    pub is_sw: T,
    pub is_le: T,
    pub is_se: T,

    // Branch instructions.
    pub is_beq: T,
    pub is_bne: T,
    pub is_ebeq: T,
    pub is_ebne: T,

    // Jump instructions.
    pub is_jal: T,
    pub is_jalr: T,

    // System instructions.
    pub is_trap: T,
    pub is_noop: T,
}

impl<F: Field> OpcodeSelectorCols<F> {
    /// Populates the opcode columns with the given instruction.
    ///
    /// The opcode flag should be set to 1 for the relevant opcode and 0 for the rest. We already
    /// assume that the state of the columns is set to zero at the start of the function, so we only
    /// need to set the relevant opcode column to 1.
    pub fn populate(&mut self, instruction: &Instruction<F>) {
        match instruction.opcode {
            Opcode::ADD => self.is_add = F::one(),
            Opcode::SUB => self.is_sub = F::one(),
            Opcode::MUL => self.is_mul = F::one(),
            Opcode::DIV => self.is_div = F::one(),
            Opcode::EADD => self.is_eadd = F::one(),
            Opcode::ESUB => self.is_esub = F::one(),
            Opcode::EMUL => self.is_emul = F::one(),
            Opcode::EDIV => self.is_ediv = F::one(),
            Opcode::EFADD => self.is_efadd = F::one(),
            Opcode::EFSUB => self.is_efsub = F::one(),
            Opcode::FESUB => self.is_fesub = F::one(),
            Opcode::EFMUL => self.is_efmul = F::one(),
            Opcode::EFDIV => self.is_efdiv = F::one(),
            Opcode::FEDIV => self.is_fediv = F::one(),
            Opcode::LW => self.is_lw = F::one(),
            Opcode::SW => self.is_sw = F::one(),
            Opcode::LE => self.is_le = F::one(),
            Opcode::SE => self.is_se = F::one(),
            Opcode::BEQ => self.is_beq = F::one(),
            Opcode::BNE => self.is_bne = F::one(),
            Opcode::EBEQ => self.is_ebeq = F::one(),
            Opcode::EBNE => self.is_ebne = F::one(),
            Opcode::JAL => self.is_jal = F::one(),
            Opcode::JALR => self.is_jalr = F::one(),
            Opcode::TRAP => self.is_trap = F::one(),
            Opcode::PrintF => self.is_noop = F::one(),
            Opcode::PrintE => self.is_noop = F::one(),
            _ => unimplemented!("opcode {:?} not supported", instruction.opcode),
        }
    }
}

impl<V: Copy> OpcodeSelectorCols<V> {
    fn opcode_map(&self) -> HashMap<Opcode, V> {
        let mut map = HashMap::new();
        map.insert(Opcode::ADD, self.is_add);
        map.insert(Opcode::SUB, self.is_sub);
        map.insert(Opcode::MUL, self.is_mul);
        map.insert(Opcode::DIV, self.is_div);
        map.insert(Opcode::EADD, self.is_eadd);
        map.insert(Opcode::ESUB, self.is_esub);
        map.insert(Opcode::EMUL, self.is_emul);
        map.insert(Opcode::EDIV, self.is_ediv);
        map.insert(Opcode::EFADD, self.is_efadd);
        map.insert(Opcode::EFSUB, self.is_efsub);
        map.insert(Opcode::FESUB, self.is_fesub);
        map.insert(Opcode::EFMUL, self.is_efmul);
        map.insert(Opcode::EFDIV, self.is_efdiv);
        map.insert(Opcode::FEDIV, self.is_fediv);
        map.insert(Opcode::LW, self.is_lw);
        map.insert(Opcode::SW, self.is_sw);
        map.insert(Opcode::LE, self.is_le);
        map.insert(Opcode::SE, self.is_se);
        map.insert(Opcode::BEQ, self.is_beq);
        map.insert(Opcode::BNE, self.is_bne);
        map.insert(Opcode::EBEQ, self.is_ebeq);
        map.insert(Opcode::EBNE, self.is_ebne);
        map.insert(Opcode::JAL, self.is_jal);
        map.insert(Opcode::JALR, self.is_jalr);
        map.insert(Opcode::TRAP, self.is_trap);
        // map.insert(Opcode::PrintF, &self.is_noop);
        // map.insert(Opcode::PrintE, &self.is_noop);
        map
    }

    pub fn eval<AB: SP1AirBuilder<Var = V>>(&self, builder: &mut AB, row_opcode: AB::Expr)
    where
        V: Into<AB::Expr>,
    {
        // Ensure that the flags are all 0 or 1.
        let map = self.opcode_map();
        // for flag in map.values().cloned() {
        //     builder.assert_bool(flag);
        //     // println!("{:?}", flag);
        // }
        builder.assert_bool(self.is_add);
        builder.assert_bool(self.is_sub);
        builder.assert_bool(self.is_mul);
        builder.assert_bool(self.is_div);
        builder.assert_bool(self.is_eadd);
        builder.assert_bool(self.is_esub);
        builder.assert_bool(self.is_emul);
        builder.assert_bool(self.is_ediv);
        builder.assert_bool(self.is_efadd);
        builder.assert_bool(self.is_efsub);
        builder.assert_bool(self.is_fesub);
        builder.assert_bool(self.is_efmul);
        builder.assert_bool(self.is_efdiv);
        builder.assert_bool(self.is_fediv);
        builder.assert_bool(self.is_lw);
        builder.assert_bool(self.is_sw);
        builder.assert_bool(self.is_le);
        builder.assert_bool(self.is_se);
        builder.assert_bool(self.is_beq);
        builder.assert_bool(self.is_bne);
        builder.assert_bool(self.is_ebeq);
        builder.assert_bool(self.is_ebne);
        builder.assert_bool(self.is_jal);
        builder.assert_bool(self.is_jalr);
        builder.assert_bool(self.is_trap);
        builder.assert_bool(self.is_noop);

        // Ensure that exactly one flag is set to 1.
        // let sum = map
        //     .values()
        //     .fold(AB::Expr::zero(), |acc, flag| acc + **flag)
        //     + self.is_noop;
        // builder.assert_eq(sum, AB::F::one());

        // Ensure that if the flag is 1, then the opcode is set to the corresponding value.
        // map.iter().for_each(|(opcode, flag)| {
        //     builder.when(**flag).assert_eq(
        //         row_opcode.clone(),
        //         AB::F::from_canonical_u32(*opcode as u32),
        //     );
        // });
    }
}

impl<T> IntoIterator for OpcodeSelectorCols<T> {
    type Item = T;

    type IntoIter = std::array::IntoIter<T, OPCODE_COUNT>;

    fn into_iter(self) -> Self::IntoIter {
        [
            self.is_add,
            self.is_sub,
            self.is_mul,
            self.is_div,
            self.is_eadd,
            self.is_esub,
            self.is_emul,
            self.is_ediv,
            self.is_efadd,
            self.is_efsub,
            self.is_fesub,
            self.is_efmul,
            self.is_efdiv,
            self.is_fediv,
            self.is_lw,
            self.is_sw,
            self.is_le,
            self.is_se,
            self.is_beq,
            self.is_bne,
            self.is_ebeq,
            self.is_ebne,
            self.is_jal,
            self.is_jalr,
            self.is_trap,
            self.is_noop,
        ]
        .into_iter()
    }
}
