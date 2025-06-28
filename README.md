# Fuzzing Python's socket module

This project provides a libFuzzer-based harness for Python's socket module using `libprotobuf-mutator` to generate protocol buffers describing socket operations.

## Requirements

Install the following packages on a Debian/Ubuntu system:

```bash
sudo apt-get update
sudo apt-get install -y git clang cmake build-essential ninja-build \
    protobuf-compiler libprotobuf-dev python3-dev
```

`libprotobuf-mutator` is not packaged in Debian/Ubuntu. You must build it from source.

## Building libprotobuf-mutator

```bash
# Clone and build libprotobuf-mutator
git clone https://github.com/google/libprotobuf-mutator.git
cd libprotobuf-mutator
git submodule update --init
cmake -S . -B build -GNinja
cmake --build build -j$(nproc)
sudo cmake --install build
cd ..
```

This installs headers and libraries under `/usr/local`.

## Building the fuzzer

Clone this repository and run the build script:

```bash
git clone https://example.com/fuzz_socketmodule.git
cd fuzz_socketmodule
./build.sh
```

The script generates protobuf bindings and compiles the `fuzz_socket` binary with sanitizers enabled. It also creates a default seed corpus under `corpus/`.

## Running

Use the provided wrapper to intercept networking calls:

```bash
LD_PRELOAD=./wrap_net.so ./fuzz_socket -max_len=512 corpus/
```

See the `build.sh` script for additional instructions on coverage analysis and seed corpus contents.
