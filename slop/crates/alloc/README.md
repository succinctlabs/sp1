# slop-alloc

Memory allocation backend abstraction for SLOP.

Provides the `Backend` trait that abstracts over different memory allocation strategies. This enables SLOP's data structures to work with both CPU and GPU memory backends, supporting future hardware acceleration.

## Features

- `Backend` trait for generic memory allocation
- Support for different alignment requirements
- Foundation for CPU/GPU portable data structures

---

Part of [SLOP](https://github.com/succinctlabs/sp1/tree/dev/slop), the Succinct Library of Polynomials.
