#!/bin/bash
set -e

export CC=clang
export CXX=clang++
export CFLAGS="-fsanitize=fuzzer,address,undefined -fno-sanitize=function -fno-sanitize=leak -fsanitize-coverage=trace-cmp,trace-div,trace-gep -g -O1 -fno-omit-frame-pointer -fno-optimize-sibling-calls -Ibuildroot/usr/include/python3.9 -I/usr/local/include/libprotobuf-mutator -L/usr/local/lib -Wl,--export-dynamic -Wl,--whole-archive buildroot/usr/lib64/python3.9/config-3.9-x86_64-linux-gnu/libpython3.9.a -Wl,--no-whole-archive -lcrypt -ldl -lm -lpthread -lutil -lrt -lstdc++ "
export CXXFLAGS="$CFLAGS -std=c++17"

# Build wrap_net.so
echo "Building wrap_net.so..."
$CC -fPIC -shared -o wrap_net.so wrap_net.c -ldl

# Generate protobuf files
echo "Generating protobuf files..."
protoc --cpp_out=. socket_api.proto

# Get Python config using bundled interpreter
PYTHON_CONFIG="buildroot/usr/bin/python3.9 buildroot/usr/lib64/python3.9/config-3.9-x86_64-linux-gnu/python-config.py"
PYTHON_CFLAGS=$(ASAN_OPTIONS=detect_leaks=0 $PYTHON_CONFIG --cflags)
PYTHON_LDFLAGS=$(ASAN_OPTIONS=detect_leaks=0 $PYTHON_CONFIG --ldflags --embed)

# Build fuzzer
echo "Building fuzzer..."
$CXX $CXXFLAGS \
    fuzz_socket_prog.cc socket_api.pb.cc \
    -lprotobuf-mutator-libfuzzer \
    -lprotobuf-mutator \
    -lprotobuf \
    -fsanitize=fuzzer \
    -o fuzz_socket

# Create seed corpus
echo "Creating seed corpus..."
mkdir -p corpus

# Seed 1: Basic socket operations
cat > corpus/seed1.txt << 'EOF'
init {
  socks { id: 0 family: 2 type: 1 }
  socks { id: 1 family: 2 type: 1 preload_send: "GET / HTTP/1.0\r\n\r\n" }
}
cmds { sock_connect { id: 0 addr: "\x00\x50" } }
cmds { sock_send { id: 0 data: "Hello" flags: 0 } }
cmds { sock_recv { id: 0 maxlen: 1024 flags: 0 } }
cmds { sock_close { id: 0 } }
EOF

# Seed 2: Accept/bind/listen operations
cat > corpus/seed2.txt << 'EOF'
init {
  socks { id: 2 family: 2 type: 1 }
}
cmds { sock_bind { id: 2 addr: "\x30\x39" } }
cmds { sock_listen { id: 2 backlog: 5 } }
cmds { sock_accept { id: 2 new_id: 3 } }
cmds { sock_setsockopt { id: 3 level: 1 opt: 7 val: "\x00\x10\x00\x00" } }
cmds { sock_getsockopt { id: 3 level: 1 opt: 7 } }
EOF

# Seed 3: DNS and socketpair operations  
cat > corpus/seed3.txt << 'EOF'
cmds { inet_pton { family: 2 text: "192.168.1.1" } }
cmds { inet_ntop { family: 2 packed: "\xc0\xa8\x01\x01" } }
cmds { getaddrinfo { host: "example.com" service: "80" family: 0 type: 1 } }
cmds { htons { val: 8080 } }
cmds { sock_socketpair { id1: 4 id2: 5 family: 1 type: 1 proto: 0 } }
cmds { sock_sendmsg { id: 4 data: "test" flags: 0 } }
cmds { sock_recvmsg { id: 5 maxlen: 100 ancbufsize: 0 flags: 0 } }
EOF

# Seed 4: Edge cases and error conditions
cat > corpus/seed4.txt << 'EOF'
init {
  socks { id: 6 family: 10 type: 2 }
}
cmds { sock_settimeout { id: 6 timeout: 0.5 } }
cmds { sock_setblocking { id: 6 blocking: false } }
cmds { sock_recv_into { id: 6 nbytes: 256 flags: 2048 } }
cmds { sock_shutdown { id: 6 how: 2 } }
cmds { if_nameindex { } }
cmds { if_nametoindex { name: "lo" } }
cmds { if_indextoname { index: 1 } }
EOF

echo "Build complete!"
echo ""
echo "To run the fuzzer:"
echo "  LD_PRELOAD=./wrap_net.so ./fuzz_socket -max_len=512 corpus/"
echo ""
echo "For coverage-guided fuzzing with visualization:"
echo "  LD_PRELOAD=./wrap_net.so ./fuzz_socket -max_len=512 -max_total_time=3600 corpus/"
echo "  llvm-profdata merge -sparse default.profraw -o default.profdata"
echo "  llvm-cov show ./fuzz_socket -instr-profile=default.profdata"
