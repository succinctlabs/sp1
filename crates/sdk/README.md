## Groth16 and PLONK CUDA acceleration

The `groth16-cuda` and `plonk-cuda` features prove the final Groth16 and PLONK wrapping on an NVIDIA GPU.

Building requires the CUDA toolkit: `nvcc` must be on the `PATH`, or `CUDA_HOME` must point to the toolkit.
At runtime, `libcudart` must be on the library path, for example:
```sh
export LD_LIBRARY_PATH="$CUDA_HOME/lib64"
```
