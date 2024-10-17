# SP1 Recursion


## Debugging recursion programs
The recursion programs are executed in the recursion runtime. In case of a panic in the recursion 
runtime, rust will panic with a `TRAP` error. In order to get detailed information about the panic, 
with a backtrace, compile the test with the environment variables:
```bash
RUST_BACKTRACE=1 RUSTFLAGS="-g" SP1_DEBUG=true 
```
