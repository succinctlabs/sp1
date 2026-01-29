use std::collections::HashMap;

use crate::instruction::{Instruction16, Instruction32, Opcode};

struct RegisterAllocator {
    f_used: Vec<bool>,
    ef_used: Vec<bool>,
    f_vreg2phys_map: HashMap<u32, u32>,
    ef_vreg2phys_map: HashMap<u32, u32>,
    f_max: usize,
    ef_max: usize,
}

impl RegisterAllocator {
    pub fn new() -> Self {
        let mut f_used = vec![false; 2048];
        let mut ef_used = vec![false; 1024];

        // Make %v0 always map to %p0.
        f_used[0] = true;
        ef_used[0] = true;
        let f_vreg2phys_map = HashMap::new();
        let ef_vreg2phys_map = HashMap::new();

        Self { f_used, ef_used, f_vreg2phys_map, ef_vreg2phys_map, f_max: 0, ef_max: 0 }
    }

    pub fn f_vreg2phys(&mut self, vreg: u32) -> u32 {
        if self.f_vreg2phys_map.contains_key(&vreg) {
            return self.f_vreg2phys_map[&vreg];
        }
        for i in 0..self.f_used.len() {
            if !self.f_used[i] {
                self.f_used[i] = true;
                let phys = i as u32;
                self.f_vreg2phys_map.insert(vreg, phys);
                if i > self.f_max {
                    self.f_max = i;
                }
                return phys;
            }
        }
        unreachable!()
    }

    pub fn ef_vreg2phys(&mut self, vreg: u32) -> u32 {
        if self.ef_vreg2phys_map.contains_key(&vreg) {
            return self.ef_vreg2phys_map[&vreg];
        }
        for i in 0..self.ef_used.len() {
            if !self.ef_used[i] {
                self.ef_used[i] = true;
                let phys = i as u32;
                self.ef_vreg2phys_map.insert(vreg, phys);
                if i > self.ef_max {
                    self.ef_max = i;
                }
                return phys;
            }
        }
        unreachable!()
    }

    pub fn f_free(&mut self, vreg: u32) {
        if self.f_vreg2phys_map.contains_key(&vreg) {
            let phys = self.f_vreg2phys_map.remove(&vreg).unwrap();
            self.f_used[phys as usize] = false;
        }
    }

    pub fn ef_free(&mut self, vreg: u32) {
        if self.ef_vreg2phys_map.contains_key(&vreg) {
            let phys = self.ef_vreg2phys_map.remove(&vreg).unwrap();
            self.ef_used[phys as usize] = false;
        }
    }
}

pub fn optimize(instructions: Vec<Instruction32>) -> (Vec<Instruction16>, usize, usize) {
    let mut f_first_time_vreg_used: HashMap<u32, u32> = HashMap::new();
    let mut f_last_time_vreg_used: HashMap<u32, u32> = HashMap::new();
    let mut ef_first_time_vreg_used: HashMap<u32, u32> = HashMap::new();
    let mut ef_last_time_vreg_used: HashMap<u32, u32> = HashMap::new();

    for (i, instr) in instructions.iter().enumerate() {
        let i = i as u32;
        let opcode = Opcode::from(instr.opcode);

        if opcode.is_f_assign() {
            f_first_time_vreg_used.entry(instr.a).or_insert(i);
            f_last_time_vreg_used.insert(instr.a, i);
        }

        if opcode.is_f_arg1() {
            f_first_time_vreg_used.entry(instr.b).or_insert(i);
            f_last_time_vreg_used.insert(instr.b, i);
        }

        if opcode.is_f_arg2() {
            f_first_time_vreg_used.entry(instr.c).or_insert(i);
            f_last_time_vreg_used.insert(instr.c, i);
        }

        if opcode.is_e_assign() {
            ef_first_time_vreg_used.entry(instr.a).or_insert(i);
            ef_last_time_vreg_used.insert(instr.a, i);
        }

        if opcode.is_e_arg1() {
            ef_first_time_vreg_used.entry(instr.b).or_insert(i);
            ef_last_time_vreg_used.insert(instr.b, i);
        }

        if opcode.is_e_arg2() {
            ef_first_time_vreg_used.entry(instr.c).or_insert(i);
            ef_last_time_vreg_used.insert(instr.c, i);
        }
    }

    let mut optimized_instructions = Vec::new();
    let mut allocator = RegisterAllocator::new();
    for (i, instr) in instructions.iter().enumerate() {
        let i = i as u32;
        let opcode = Opcode::from(instr.opcode);

        let mut new_instr = *instr;
        if opcode.is_f_assign() {
            let phys_a = allocator.f_vreg2phys(instr.a);
            new_instr.a = phys_a;
        }

        if opcode.is_f_arg1() {
            let phys_b = allocator.f_vreg2phys(instr.b);
            new_instr.b = phys_b;
        }

        if opcode.is_f_arg2() {
            let phys_c = allocator.f_vreg2phys(instr.c);
            new_instr.c = phys_c;
        }

        if opcode.is_e_assign() {
            let phys_a = allocator.ef_vreg2phys(instr.a);
            new_instr.a = phys_a;
        }

        if opcode.is_e_arg1() {
            let phys_b = allocator.ef_vreg2phys(instr.b);
            new_instr.b = phys_b;
        }

        if opcode.is_e_arg2() {
            let phys_c = allocator.ef_vreg2phys(instr.c);
            new_instr.c = phys_c;
        }

        optimized_instructions.push(new_instr);

        if opcode.is_f_assign() && f_last_time_vreg_used.get(&instr.a).unwrap() == &i {
            allocator.f_free(instr.a);
        }

        if opcode.is_f_arg1() && f_last_time_vreg_used.get(&instr.b).unwrap() == &i {
            allocator.f_free(instr.b);
        }

        if opcode.is_f_arg2() && f_last_time_vreg_used.get(&instr.c).unwrap() == &i {
            allocator.f_free(instr.c);
        }

        if opcode.is_e_assign() && ef_last_time_vreg_used.get(&instr.a).unwrap() == &i {
            allocator.ef_free(instr.a);
        }

        if opcode.is_e_arg1() && ef_last_time_vreg_used.get(&instr.b).unwrap() == &i {
            allocator.ef_free(instr.b);
        }

        if opcode.is_e_arg2() && ef_last_time_vreg_used.get(&instr.c).unwrap() == &i {
            allocator.ef_free(instr.c);
        }
    }

    (
        optimized_instructions
            .into_iter()
            .map(|instr| Instruction16 {
                opcode: instr.opcode,
                b_variant: instr.b_variant,
                c_variant: instr.c_variant,
                a: instr.a as u16,
                b: instr.b as u16,
                c: instr.c as u16,
            })
            .collect(),
        allocator.f_max,
        allocator.ef_max,
    )
}
