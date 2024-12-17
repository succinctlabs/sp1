use sp1_core_machine::io::SP1Stdin;

/// Dump the program and stdin to files for debugging if `SP1_DUMP` is set.
pub(crate) fn dump_proof_input(elf: &[u8], stdin: &SP1Stdin) {
    if std::env::var("SP1_DUMP").map(|v| v == "1" || v.to_lowercase() == "true").unwrap_or(false) {
        std::fs::write("program.bin", elf).unwrap();
        let stdin = bincode::serialize(&stdin).unwrap();
        std::fs::write("stdin.bin", stdin.clone()).unwrap();
    }
}
