mod addmul;

pub use addmul::*;

#[cfg(test)]
mod tests {
    use crate::{
        io::SP1Stdin,
        runtime::Program,
        utils::{
            self,
            run_test_io,
        },
    };

    use test_artifacts::ADD_MUL_ELF;

    #[test]
    fn test_add_mul() {
        utils::setup_logger();
        println!("This test is running!");
        let program = Program::from(ADD_MUL_ELF);
        run_test_io::<CpuProver<_, _>>(program, SP1Stdin::new()).unwrap();
    }

}