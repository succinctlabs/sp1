use crate::{
    alu::ALU,
    cpu::Cpu,
    program::{
        basic::{Basic32, BasicInstruction},
        ISA,
    },
    runtime::store::FunctionStore,
    segment::Segment,
};

use anyhow::Result;

use super::Instance;

pub struct CoreInstance<IS: ISA> {
    pub program: Vec<IS::Instruction>,
    pub max_segment_len: usize,
    pub fp: IS::Word,
    pub pc: IS::Word,
}

pub struct CoreSegment<IS: ISA> {
    cpu_trace: Vec<Cpu<IS>>,
    alu_trace: Vec<ALU<IS>>,
}

impl<IS: ISA> CoreSegment<IS> {
    pub fn new() -> Self {
        Self {
            cpu_trace: vec![],
            alu_trace: vec![],
        }
    }
}

impl<IS: ISA> Segment for CoreSegment<IS> {
    fn init() -> Self {
        Self::new()
    }
}

impl<IS: ISA> CoreInstance<IS> {
    pub fn new(program: Vec<IS::Instruction>, max_segment_len: usize) -> Self {
        Self {
            program,
            max_segment_len,
            pc: IS::Word::default(),
            fp: IS::Word::default(),
        }
    }

    fn execute(
        instruction: &IS::Instruction,
        store: &mut FunctionStore<IS>,
        segment: &mut CoreSegment<IS>,
    ) {
    }
}

impl Instance<FunctionStore<u32>, Basic32> for CoreInstance<Basic32> {
    type Segment = CoreSegment<Basic32>;
    type Segments = Vec<Self::Segment>;

    fn max_segment_len(&self) -> usize {
        self.max_segment_len
    }

    fn execute(
        &self,
        Instruction: &BasicInstruction<u32>,
        store: &mut FunctionStore<u32>,
        segment: &mut Self::Segment,
    ) -> Result<()> {
        Ok(())
    }

    fn run(&self, store: &mut FunctionStore<u32>) -> Result<Self::Segments> {
        let mut segments = vec![];

        loop {
            let mut segment = Self::Segment::init();
            let mut instruction_counter = 0;

            while instruction_counter < self.max_segment_len {}
            segments.push(segment);
        }
        Ok(vec![])
    }
}
