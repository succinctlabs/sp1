//! End-to-end smoke tests for `sp1_lib::invalid_hint!` and exit code 3.
//!
//! These verify the wiring works: a guest that fires `invalid_hint!` halts
//! with `report.exit_code == 3` (`StatusCode::INVALID_HINT`), distinct from
//! a regular panic (exit code 1).
//!
//! Per-patch failure tests that override hint hooks live elsewhere; those
//! depend on routing executor hook dispatch through the
//! user-supplied `HookRegistry`, which the current minimal executor does
//! not yet do. Once that lands, each patched crate can add its own
//! `invalid_<patch>_hint_halts_with_3` test using `with_hook`.

#[tokio::test]
async fn invalid_hint_macro_with_message_halts_with_3() {
    use sp1_sdk::{include_elf, Elf, Prover, SP1Stdin};

    sp1_test::setup().await;
    const ELF: Elf = include_elf!("invalid_hint_macro");

    let client = sp1_test::sp1_cpu_prover().await;
    let mut stdin = SP1Stdin::new();
    stdin.write(&1u8); // trigger the macro

    let (_pv, report) =
        client.execute(ELF, stdin).await.expect("execution should complete");

    assert_eq!(
        report.exit_code, 3,
        "expected exit code 3 from invalid_hint!, got {}",
        report.exit_code
    );
}

#[tokio::test]
async fn invalid_hint_macro_no_message_halts_with_3() {
    use sp1_sdk::{include_elf, Elf, Prover, SP1Stdin};

    sp1_test::setup().await;
    const ELF: Elf = include_elf!("invalid_hint_no_message");

    let client = sp1_test::sp1_cpu_prover().await;
    let mut stdin = SP1Stdin::new();
    stdin.write(&1u8);

    let (_pv, report) =
        client.execute(ELF, stdin).await.expect("execution should complete");

    assert_eq!(
        report.exit_code, 3,
        "expected exit code 3 from invalid_hint!() no-arg form, got {}",
        report.exit_code
    );
}

#[tokio::test]
async fn invalid_hint_macro_passthrough_exits_0() {
    use sp1_sdk::{include_elf, Elf, Prover, SP1Stdin};

    sp1_test::setup().await;
    const ELF: Elf = include_elf!("invalid_hint_macro");

    let client = sp1_test::sp1_cpu_prover().await;
    let mut stdin = SP1Stdin::new();
    stdin.write(&0u8); // trigger == 0 → fall through, exit 0

    let (_pv, report) =
        client.execute(ELF, stdin).await.expect("execution should complete");

    assert_eq!(report.exit_code, 0, "expected normal exit 0, got {}", report.exit_code);
}

/// `read_vec()` on an empty input stream is a hint failure (the prover/hook
/// did not supply expected data), so it must halt with exit code 3 instead
/// of panicking with exit code 1.
#[tokio::test]
async fn read_vec_empty_input_halts_with_3() {
    use sp1_sdk::{include_elf, Elf, Prover, SP1Stdin};

    sp1_test::setup().await;
    const ELF: Elf = include_elf!("invalid_hint_empty_input");

    let client = sp1_test::sp1_cpu_prover().await;
    let stdin = SP1Stdin::new(); // empty — read_vec will halt(3)

    let (_pv, report) =
        client.execute(ELF, stdin).await.expect("execution should complete");

    assert_eq!(
        report.exit_code, 3,
        "expected halt(3) for empty input stream, got {}",
        report.exit_code
    );
}
