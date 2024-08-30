use csv::WriterBuilder;
use rsp_client_executor::{io::ClientExecutorInput, ChainVariant};
use serde::{Deserialize, Serialize};
use sp1_sdk::ExecutionReport;
use std::{fs::OpenOptions, path::PathBuf};

#[derive(Serialize, Deserialize)]
struct ExecutionReportData {
    chain_id: u64,
    block_number: u64,
    gas_used: u64,
    tx_count: usize,
    number_cycles: u64,
    number_syscalls: u64,
    bn_add_cycles: u64,
    bn_mul_cycles: u64,
    bn_pair_cycles: u64,
    kzg_point_eval_cycles: u64,
}

/// Given an execution report, print it out and write it to a CSV specified by report_path.
pub fn process_execution_report(
    variant: ChainVariant,
    client_input: ClientExecutorInput,
    execution_report: ExecutionReport,
    report_path: PathBuf,
) -> eyre::Result<()> {
    println!("\nExecution report:\n{}", execution_report);

    let chain_id = variant.chain_id();
    let executed_block = client_input.current_block;
    let block_number = executed_block.header.number;
    let gas_used = executed_block.header.gas_used;
    let tx_count = executed_block.body.len();
    let number_cycles = execution_report.total_instruction_count();
    let number_syscalls = execution_report.total_syscall_count();

    let bn_add_cycles = *execution_report.cycle_tracker.get("precompile-bn-add").unwrap_or(&0);
    let bn_mul_cycles = *execution_report.cycle_tracker.get("precompile-bn-mul").unwrap_or(&0);
    let bn_pair_cycles = *execution_report.cycle_tracker.get("precompile-bn-pair").unwrap_or(&0);
    let kzg_point_eval_cycles =
        *execution_report.cycle_tracker.get("precompile-kzg-point-evaluation").unwrap_or(&0);

    // TODO: we can track individual syscalls in our CSV once we have sp1-core as a dependency
    // let keccak_count = execution_report.syscall_counts.get(SyscallCode::KECCAK_PERMUTE);
    // let secp256k1_decompress_count =
    //     execution_report.syscall_counts.get(SyscallCode::SECP256K1_DECOMPRESS);

    let report_data = ExecutionReportData {
        chain_id,
        block_number,
        gas_used,
        tx_count,
        number_cycles,
        number_syscalls,
        bn_add_cycles,
        bn_mul_cycles,
        bn_pair_cycles,
        kzg_point_eval_cycles,
    };

    // Open the file for appending or create it if it doesn't exist
    let file = OpenOptions::new().append(true).create(true).open(report_path)?;

    // Check if the file is empty
    let file_is_empty = file.metadata()?.len() == 0;

    let mut writer = WriterBuilder::new().has_headers(file_is_empty).from_writer(file);
    writer.serialize(report_data)?;
    writer.flush()?;

    Ok(())
}
