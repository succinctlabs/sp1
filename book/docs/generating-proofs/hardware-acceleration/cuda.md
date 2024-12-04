# CUDA

<div class="warning">
WARNING: CUDA proving is still an experimental feature and may be buggy.
</div>


SP1 supports CUDA acceleration, which can provide dramatically better latency and cost performance
compared to using the CPU prover, even with AVX acceleration.

## Software Requirements

Please make sure you have the following installed before using the CUDA prover:

- [CUDA 12](https://developer.nvidia.com/cuda-12-0-0-download-archive?target_os=Linux&target_arch=x86_64&Distribution=Ubuntu&target_version=22.04&target_type=deb_local)
- [CUDA Container Toolkit](https://docs.nvidia.com/datacenter/cloud-native/container-toolkit/latest/install-guide.html)

## Hardware Requirements

- **CPU**: We recommend having at least 8 CPU cores with 32GB of RAM available to fully utilize the GPU.
- **GPU**: 24GB or more for core/compressed proofs, 40GB or more for shrink/wrap proofs

## Usage

To use the CUDA prover, you can compile the `sp1-sdk` crate with the `cuda` feature enabled. You
can use the normal methods on the `ProverClient` to generate proofs.