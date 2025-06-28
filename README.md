# Fuzz Socket Module

This repository contains a socket fuzzing harness and related utilities.

## Building

Run the provided `build.sh` script to compile everything. Ensure the script is executable before running it:

```bash
chmod +x build.sh
./build.sh
```

The script compiles the wrapper library, generates protobuf sources, and builds the fuzzer binary.

## Running the Fuzzer

After building, preload the wrapper and run the fuzzer against the corpus directory:

```bash
LD_PRELOAD=./wrap_net.so ./fuzz_socket -max_len=512 corpus/
```

See the `build.sh` script for additional instructions on coverage analysis and seed corpus contents.
