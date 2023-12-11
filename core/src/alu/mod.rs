pub struct AluEvent {
    pub clk: u32,
    pub opcode: u32,
    pub addr_d: usize,
    pub addr_1: usize,
    pub addr_2: usize,
    pub v_d: i32,
    pub v_1: i32,
    pub v_2: i32,
}
