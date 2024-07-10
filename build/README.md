# sp1-build
Lightweight crate used to build SP1 programs. Internal crate that is exposed to users via `sp1-cli` and `sp1-helper`.

Exposes `build_program`, which builds an SP1 program in the local environment or in a docker container with the specified parameters from `BuildArgs`.

## Usage

```rust
use sp1_build::build_program;

build_program(&BuildArgs::default(), Some(program_dir));
```