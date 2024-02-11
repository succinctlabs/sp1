# Installation

Curta currently runs on Linux and macOS. You can either use prebuilt binaries through Curtaup or
build the toolchain and CLI from source.

Make sure you have [Rust](https://www.rust-lang.org/tools/install) installed.

## Prebuilt Binaries (Recommended)

Curtaup is the Curta zkVM toolchain installer. Open your terminal and run the following command and follow the instructions:

```bash
curl -L https://curta.succinct.xyz | bash
```

This will install Curtaup, then simply follow the instructions on-screen, which will make the `curtaup` command available in your CLI.

After following the instructions, you can run `curtaup` to install the toolchain:

```bash
curtaup
```

This will install support for the `riscv32im-succinct-zkvm-elf` compilation target within your Rust compiler
and a `cargo prove` CLI tool that will let you compile provable programs and then prove their correctness. 

You can verify the installation by running `cargo prove --version`:

```bash
cargo prove --version
```

If this works, go to the [next section](./quickstart.md) to compile and prove a simple zkVM program.

## Building from Source

Make sure you have installed the [dependencies](https://github.com/rust-lang/rust/blob/master/INSTALL.md#dependencies) needed to build the rust toolchain from source.

Clone the `curta` repository and navigate to the root directory. 

```bash
git clone git@github.com:succinctlabs/curta.git
cd vm
cd cli
cargo install --locked --path .
cargo prove build-toolchain
```

Building the toolchain can take a while, ranging from 30 mins to an hour depending on your machine.

To verify the installation of the tooolchain, run and make sure you see `succinct`:

```bash
rustup toolchain list
```

You can delete your existing installation of the toolchain with:

```bash
rustup toolchain remove succinct
```