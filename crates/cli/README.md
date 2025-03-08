# CLI

The `cargo prove` CLI is useful for various tasks related to the SP1 project, such as building the toolchain, compiling programs, tracing programs, and more. Typically users will not need to interact with the CLI directly, but rather use the `sp1up` script to install the CLI.

## Available Commands

The CLI provides several essential commands for working with SP1:

### Core Commands

- `cargo prove new <name>` - Create a new SP1 project
- `cargo prove build` - Build the current SP1 project
- `cargo prove test` - Run tests for the current project
- `cargo prove trace` - Generate execution trace for debugging
- `cargo prove prove` - Generate a proof for the program
- `cargo prove verify` - Verify a previously generated proof

### Advanced Commands

- `cargo prove setup` - Set up the SP1 development environment
- `cargo prove clean` - Clean build artifacts
- `cargo prove check` - Check the project for common issues
- `cargo prove bench` - Run performance benchmarks

## Development

To run the CLI locally, you can use the following command:

```bash
cargo run --bin cargo-prove -- --help
```

To test a particular subcommand, you can pass in `prove` and the subcommand you want to test along with the arguments you want to pass to it. For example, to test the `trace` subcommand, you can run the following command:

```bash
cargo run --bin cargo-prove -- prove trace --elf <path-to-elf> --trace <output-path>
```

### Common Usage Examples

1. Creating and building a new project:
```bash
cargo prove new my-project
cd my-project
cargo prove build
```

2. Running tests with trace output:
```bash
cargo prove test --trace
```

3. Generating and verifying proofs:
```bash
cargo prove prove --output proof.json
cargo prove verify --proof proof.json
```

### Installing the CLI locally from source

You can install the CLI locally from source by running the following command:

```bash
cargo install --locked --force --path .
```

### Running the CLI after installing

After installing the CLI, you can run it by simply running the following command:

```bash
cargo prove
```

## Troubleshooting

Common issues and their solutions:

1. **Build Failures**
   - Ensure you have the latest Rust toolchain installed
   - Check that all dependencies are available
   - Try running `cargo prove clean` and rebuild

2. **Trace Generation Issues**
   - Verify the ELF file path is correct
   - Ensure sufficient disk space for trace output
   - Check program memory requirements

3. **Proof Generation Problems**
   - Verify input parameters are correct
   - Ensure sufficient system resources
   - Check for compatible proving backend

## Environment Variables

The CLI respects several environment variables:

- `SP1_PATH` - Custom path for SP1 installation
- `SP1_PROVE_BACKEND` - Select proving backend (local/remote)
- `SP1_DEBUG` - Enable debug output (0/1)
- `SP1_TRACE_LEVEL` - Set trace detail level
