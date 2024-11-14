# Profiling ZKVM programs

Profiling the ZKVM can only be done with debug builds, and special care must be taken to ensure correctness, only one program may be profiled at a time.

To profile a program, you have to setup a script to execute the program, many examples can be found in the repo, such as this ('fibonacci')[../../examples/fibonacci/script/src/main.rs] script.
Once you have your script it should contain the following code:
```rs 
    // Execute the program using the `ProverClient.execute` method, without generating a proof.
    let (_, report) = client.execute(ELF, stdin.clone()).run().unwrap();
```

As mentioned, profiling is only enabled in debug mode, and you can set the sample rate to reduce the size of the profiling as they can get quite large using the `TRACE_SAMPLE_RATE` env var.
To enable profiling, set the `TRACE_FILE` env var to the path where you want the profile to be saved.

The full command to profile should look something like this
```sh
    TRACE_FILE=output.json TRACE_SAMPLE_RATE=100 cargo run ...
```

To view these profiles, we reccomend Samply.
```sh
    cargo install --locked samply
    samply load output.json
```
