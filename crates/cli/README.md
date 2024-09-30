# CLI

The `cargo prove` CLI is useful for various tasks related to the SP1 project, such as building the toolchain, compiling programs, tracing programs, and more. Typically users will not need to interact with the CLI directly, but rather use the `sp1up` script to install the CLI.

## Development

To run the CLI locally, you can use the following command:

```bash
cargo run --bin cargo-prove -- --help
```

To test a particular subcommand, you can pass in `prove` and the subcommand you want to test along with the arguments you want to pass to it. For example, to test the `trace` subcommand, you can run the following command:

```bash
cargo run --bin cargo-prove -- prove trace --elf <...> --trace <...>
```

### Installing the CLI locally from source

You can install the CLI locally from source by running the following command:

```bash
cargo install --locked --path .
```

### Running the CLI after installing

After installing the CLI, you can run it by simply running the following command:

```bash
cargo prove
```
