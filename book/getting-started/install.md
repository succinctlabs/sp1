# Installation

SP1 currently runs on Linux and macOS. You can either use prebuilt binaries through sp1up or
build the toolchain and CLI from source.

## Requirements

- [Git](https://git-scm.com/book/en/v2/Getting-Started-Installing-Git)
- [Rust (Nightly)](https://www.rust-lang.org/tools/install)
- [Docker](https://docs.docker.com/get-docker/)

## Option 1: Prebuilt Binaries (Recommended)

Currently our prebuilt binaries are built on Ubuntu 20.04 (22.04 on ARM) and macOS. If your OS uses an older GLIBC version, it's possible these may not work and you will need to [build the toolchain from source](#option-2-building-from-source).

sp1up is the SP1 toolchain installer. Open your terminal and run the following command and follow the instructions:

```bash
curl -L https://sp1.succinct.xyz | bash
```

Then simply follow the instructions on-screen, which will make the `sp1up` command available in your CLI.

After following the instructions, you can run `sp1up` to install the toolchain:

```bash
sp1up
```

This will install two things:

1. The `succinct` Rust toolchain which has support for the `riscv32im-succinct-zkvm-elf` compilation target.
2. `cargo prove` CLI tool that will let you compile provable programs and then prove their correctness.

You can verify the installation by running `cargo prove --version`:

```bash
cargo prove --version
```

If this works, go to the [next section](./quickstart.md) to compile and prove a simple zkVM program.

### Troubleshooting

If you experience [rate-limiting](https://docs.github.com/en/rest/using-the-rest-api/getting-started-with-the-rest-api?apiVersion=2022-11-28#rate-limiting) when using the `sp1up` command, you can resolve this by using the `--token` flag and providing your GitHub token.

If you have installed `cargo-prove` from source, it may conflict with `sp1up`'s `cargo-prove` installation or vice versa. You can remove the `cargo-prove` that was installed from source with the following command:

```bash
rm ~/.cargo/bin/cargo-prove
```

Or, you can remove the `cargo-prove` that was installed through `sp1up`:

```bash
rm ~/.sp1/bin/cargo-prove
```

## Option 2: Building from Source

Make sure you have installed the [dependencies](https://github.com/rust-lang/rust/blob/master/INSTALL.md#dependencies) needed to build the rust toolchain from source.

Clone the `sp1` repository and navigate to the root directory.

```bash
git clone git@github.com:succinctlabs/sp1.git
cd sp1
cd cli
cargo install --locked --path .
cd ~
cargo prove build-toolchain
```

Building the toolchain can take a while, ranging from 30 mins to an hour depending on your machine. If you're on a machine that we have prebuilt binaries for (ARM Mac or x86 or ARM Linux), you can use the following to download a prebuilt version.

```bash
cargo prove install-toolchain
```

To verify the installation of the toolchain, run and make sure you see `succinct`:

```bash
rustup toolchain list
```

You can delete your existing installation of the toolchain with:

```bash
rustup toolchain remove succinct
```
