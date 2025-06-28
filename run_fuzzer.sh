#!/bin/bash
# Simple script to run the fuzzer with the networking wrapper
set -euo pipefail
LD_PRELOAD=./wrap_net.so ./fuzz_socket -max_len=512 corpus/
