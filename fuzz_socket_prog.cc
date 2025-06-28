#include <Python.h>
#include <array>
#include <algorithm>
#include <cstring>
#include <unistd.h>
#include <sys/socket.h>
#include <dlfcn.h>
#include <libprotobuf-mutator/src/libfuzzer/libfuzzer_macro.h>
#include "socket_api.pb.h"
#include <netinet/in.h>
#include <arpa/inet.h>
#undef htons
#undef htonl
#undef ntohs
#undef ntohl

extern "C" {
void __sanitizer_cov_trace_pc_guard_cmp8(uint64_t arg1, uint64_t arg2);
Py_ssize_t _PyGC_CollectNoFail(void);
const uint8_t *__wrap_input = nullptr;
}

// Provide weak definition in case sanitizer runtime doesn't supply it
extern "C" __attribute__((weak)) void __sanitizer_cov_trace_pc_guard_cmp8(
    uint64_t, uint64_t) {}

static std::array<PyObject*, 64> socket_pool;
static PyObject* socket_module = nullptr;
static uint32_t iteration_count = 0;
static void (*wrap_reset_fn)(void) = nullptr;

static void reset_resource_pool() {
    for (auto& sock : socket_pool) {
        if (sock && sock != Py_None) {
            PyObject_CallMethod(sock, "close", nullptr);
            Py_DECREF(sock);
        }
        sock = nullptr;
    }
    if (!wrap_reset_fn) {
        wrap_reset_fn = (void (*)())dlsym(RTLD_DEFAULT, "wrap_reset");
    }
    if (wrap_reset_fn) {
        wrap_reset_fn();
    }
}

static void apply_InitSection(const Header& init) {
    for (const auto& sock_init : init.socks()) {
        if (sock_init.id() >= 64) continue;
        
        int fd[2];
        if (socketpair(AF_UNIX, sock_init.type(), 0, fd) == 0) {
            if (!sock_init.preload_send().empty()) {
                write(fd[1], sock_init.preload_send().data(),
                      sock_init.preload_send().size());
            }

            PyObject* sock = PyObject_CallMethod(socket_module, "socket", "iiii",
                sock_init.family(), sock_init.type(), 0, fd[0]);
            if (sock) {
                socket_pool[sock_init.id()] = sock;
            } else {
                close(fd[0]);
                close(fd[1]);
            }
        }
    }
}

static void do_command(const Command& cmd) {
    PyObject* result = nullptr;
    
    switch (cmd.cmd_case()) {
        case Command::kSockSocket: {
            const auto& c = cmd.sock_socket();
            if (c.target_id() >= 64) break;
            result = PyObject_CallMethod(socket_module, "socket", "iii",
                c.family(), c.type(), c.proto());
            if (result) {
                if (socket_pool[c.target_id()]) Py_DECREF(socket_pool[c.target_id()]);
                socket_pool[c.target_id()] = result;
                result = nullptr;
            }
            break;
        }
        
        case Command::kSockSocketpair: {
            const auto& c = cmd.sock_socketpair();
            if (c.id1() >= 64 || c.id2() >= 64) break;
            result = PyObject_CallMethod(socket_module, "socketpair", "iii",
                c.family(), c.type(), c.proto());
            if (result && PyTuple_Check(result) && PyTuple_Size(result) == 2) {
                PyObject* sock1 = PyTuple_GetItem(result, 0);
                PyObject* sock2 = PyTuple_GetItem(result, 1);
                Py_INCREF(sock1);
                Py_INCREF(sock2);
                if (socket_pool[c.id1()]) Py_DECREF(socket_pool[c.id1()]);
                if (socket_pool[c.id2()]) Py_DECREF(socket_pool[c.id2()]);
                socket_pool[c.id1()] = sock1;
                socket_pool[c.id2()] = sock2;
            }
            break;
        }
        
        case Command::kSockDup: {
            const auto& c = cmd.sock_dup();
            if (c.src_id() >= 64 || c.dst_id() >= 64 || !socket_pool[c.src_id()]) break;
            result = PyObject_CallMethod(socket_pool[c.src_id()], "dup", nullptr);
            if (result) {
                if (socket_pool[c.dst_id()]) Py_DECREF(socket_pool[c.dst_id()]);
                socket_pool[c.dst_id()] = result;
                result = nullptr;
            }
            break;
        }
        
        case Command::kSockClose: {
            const auto& c = cmd.sock_close();
            if (c.id() >= 64 || !socket_pool[c.id()]) break;
            PyObject_CallMethod(socket_pool[c.id()], "close", nullptr);
            break;
        }
        
        case Command::kInetPton: {
            const auto& c = cmd.inet_pton();
            result = PyObject_CallMethod(socket_module, "inet_pton", "is",
                c.family(), c.text().c_str());
            break;
        }
        
        case Command::kInetNtop: {
            const auto& c = cmd.inet_ntop();
            result = PyObject_CallMethod(socket_module, "inet_ntop", "iy#",
                c.family(), c.packed().data(), c.packed().size());
            break;
        }
        
        case Command::kInetAton: {
            const auto& c = cmd.inet_aton();
            result = PyObject_CallMethod(socket_module, "inet_aton", "s", c.text().c_str());
            break;
        }
        
        case Command::kInetNtoa: {
            const auto& c = cmd.inet_ntoa();
            if (c.packed().size() >= 4) {
                // inet_ntoa expects struct in_addr packed as bytes
                PyObject* packed_addr = PyBytes_FromStringAndSize(c.packed().data(), 4);
                if (packed_addr) {
                    result = PyObject_CallMethod(socket_module, "inet_ntoa", "O", packed_addr);
                    Py_DECREF(packed_addr);
                }
            }
            break;
        }
        
        case Command::kHtons: {
            const auto& c = cmd.htons();
            result = PyObject_CallMethod(socket_module, "htons", "I", c.val());
            break;
        }
        
        case Command::kHtonl: {
            const auto& c = cmd.htonl();
            result = PyObject_CallMethod(socket_module, "htonl", "I", c.val());
            break;
        }
        
        case Command::kNtohs: {
            const auto& c = cmd.ntohs();
            result = PyObject_CallMethod(socket_module, "ntohs", "I", c.val());
            break;
        }
        
        case Command::kNtohl: {
            const auto& c = cmd.ntohl();
            result = PyObject_CallMethod(socket_module, "ntohl", "I", c.val());
            break;
        }
        
        case Command::kGetaddrinfo: {
            const auto& c = cmd.getaddrinfo();
            result = PyObject_CallMethod(socket_module, "getaddrinfo", "ssiiii",
                c.host().c_str(), c.service().c_str(), c.family(), c.type(), c.proto(), c.flags());
            break;
        }
        
        case Command::kGetnameinfo: {
            const auto& c = cmd.getnameinfo();
            if (c.sockaddr().size() >= 4) {
                // For IPv4, getnameinfo expects tuple (address, port)
                const uint8_t* data = (const uint8_t*)c.sockaddr().data();
                char ip_str[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, data, ip_str, sizeof(ip_str));
                uint16_t port = 80;
                if (c.sockaddr().size() >= 6) {
                    port = ntohs(*(uint16_t*)(data + 4));
                }
                PyObject* addr_tuple = Py_BuildValue("(si)", ip_str, port);
                if (addr_tuple) {
                    result = PyObject_CallMethod(socket_module, "getnameinfo", "Oi", 
                        addr_tuple, c.flags());
                    Py_DECREF(addr_tuple);
                }
            }
            break;
        }
        
        case Command::kIfNameindex: {
            result = PyObject_CallMethod(socket_module, "if_nameindex", nullptr);
            break;
        }
        
        case Command::kIfNametoindex: {
            const auto& c = cmd.if_nametoindex();
            result = PyObject_CallMethod(socket_module, "if_nametoindex", "s", c.name().c_str());
            break;
        }
        
        case Command::kIfIndextoname: {
            const auto& c = cmd.if_indextoname();
            result = PyObject_CallMethod(socket_module, "if_indextoname", "I", c.index());
            break;
        }
        
        case Command::kGethostbyname: {
            const auto& c = cmd.gethostbyname();
            result = PyObject_CallMethod(socket_module, "gethostbyname", "s", c.name().c_str());
            break;
        }
        
        case Command::kGethostbynameEx: {
            const auto& c = cmd.gethostbyname_ex();
            result = PyObject_CallMethod(socket_module, "gethostbyname_ex", "s", c.name().c_str());
            break;
        }
        
        case Command::kGethostbyaddr: {
            const auto& c = cmd.gethostbyaddr();
            // gethostbyaddr expects an IP address (string or packed bytes)
            if (!c.addr().empty()) {
                // Try as IP string first
                result = PyObject_CallMethod(socket_module, "gethostbyaddr", "s", c.addr().c_str());
            }
            break;
        }
        
        case Command::kGetservbyname: {
            const auto& c = cmd.getservbyname();
            result = PyObject_CallMethod(socket_module, "getservbyname", "ss",
                c.name().c_str(), c.proto().c_str());
            break;
        }
        
        case Command::kGetservbyport: {
            const auto& c = cmd.getservbyport();
            // getservbyport expects port in host byte order
            const char* proto = c.proto().empty() ? nullptr : c.proto().c_str();
            result = PyObject_CallMethod(socket_module, "getservbyport", "is",
                c.port(), proto);
            break;
        }
        
        case Command::kSockAccept: {
            const auto& c = cmd.sock_accept();
            if (c.id() >= 64 || c.new_id() >= 64 || !socket_pool[c.id()]) break;
            result = PyObject_CallMethod(socket_pool[c.id()], "accept", nullptr);
            if (result && PyTuple_Check(result) && PyTuple_Size(result) >= 1) {
                PyObject* new_sock = PyTuple_GetItem(result, 0);
                Py_INCREF(new_sock);
                if (socket_pool[c.new_id()]) Py_DECREF(socket_pool[c.new_id()]);
                socket_pool[c.new_id()] = new_sock;
            }
            break;
        }
        
        case Command::kSockBind: {
            const auto& c = cmd.sock_bind();
            if (c.id() >= 64 || !socket_pool[c.id()]) break;
            if (c.addr().size() >= 2) {
                struct sockaddr_in addr;
                addr.sin_family = AF_INET;
                addr.sin_port = htons(*(uint16_t*)c.addr().data());
                addr.sin_addr.s_addr = INADDR_ANY;
                PyObject* addr_tuple = Py_BuildValue("(si)", "127.0.0.1", ntohs(addr.sin_port));
                if (addr_tuple) {
                    result = PyObject_CallMethod(socket_pool[c.id()], "bind", "O", addr_tuple);
                    Py_DECREF(addr_tuple);
                }
            }
            break;
        }
        
        case Command::kSockListen: {
            const auto& c = cmd.sock_listen();
            if (c.id() >= 64 || !socket_pool[c.id()]) break;
            result = PyObject_CallMethod(socket_pool[c.id()], "listen", "i", c.backlog());
            break;
        }
        
        case Command::kSockConnect: {
            const auto& c = cmd.sock_connect();
            if (c.id() >= 64 || !socket_pool[c.id()]) break;
            if (c.addr().size() >= 2) {
                struct sockaddr_in addr;
                addr.sin_family = AF_INET;
                addr.sin_port = htons(*(uint16_t*)c.addr().data());
                addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
                PyObject* addr_tuple = Py_BuildValue("(si)", "127.0.0.1", ntohs(addr.sin_port));
                if (addr_tuple) {
                    result = PyObject_CallMethod(socket_pool[c.id()], "connect", "O", addr_tuple);
                    Py_DECREF(addr_tuple);
                }
            }
            break;
        }
        
        case Command::kSockConnectEx: {
            const auto& c = cmd.sock_connect_ex();
            if (c.id() >= 64 || !socket_pool[c.id()]) break;
            if (c.addr().size() >= 2) {
                struct sockaddr_in addr;
                addr.sin_family = AF_INET;
                addr.sin_port = htons(*(uint16_t*)c.addr().data());
                addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
                PyObject* addr_tuple = Py_BuildValue("(si)", "127.0.0.1", ntohs(addr.sin_port));
                if (addr_tuple) {
                    result = PyObject_CallMethod(socket_pool[c.id()], "connect_ex", "O", addr_tuple);
                    Py_DECREF(addr_tuple);
                }
            }
            break;
        }
        
        case Command::kSockShutdown: {
            const auto& c = cmd.sock_shutdown();
            if (c.id() >= 64 || !socket_pool[c.id()]) break;
            result = PyObject_CallMethod(socket_pool[c.id()], "shutdown", "i", c.how());
            break;
        }
        
        case Command::kSockSetsockopt: {
            const auto& c = cmd.sock_setsockopt();
            if (c.id() >= 64 || !socket_pool[c.id()]) break;
            result = PyObject_CallMethod(socket_pool[c.id()], "setsockopt", "iiy#",
                c.level(), c.opt(), c.val().data(), c.val().size());
            break;
        }
        
        case Command::kSockGetsockopt: {
            const auto& c = cmd.sock_getsockopt();
            if (c.id() >= 64 || !socket_pool[c.id()]) break;
            result = PyObject_CallMethod(socket_pool[c.id()], "getsockopt", "ii",
                c.level(), c.opt());
            break;
        }
        
        case Command::kSockSend: {
            const auto& c = cmd.sock_send();
            if (c.id() >= 64 || !socket_pool[c.id()]) break;
            result = PyObject_CallMethod(socket_pool[c.id()], "send", "y#i",
                c.data().data(), c.data().size(), c.flags());
            break;
        }
        
        case Command::kSockSendto: {
            const auto& c = cmd.sock_sendto();
            if (c.id() >= 64 || !socket_pool[c.id()]) break;
            if (c.addr().size() >= 2) {
                struct sockaddr_in addr;
                addr.sin_family = AF_INET;
                addr.sin_port = htons(*(uint16_t*)c.addr().data());
                addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
                PyObject* addr_tuple = Py_BuildValue("(si)", "127.0.0.1", ntohs(addr.sin_port));
                if (addr_tuple) {
                    result = PyObject_CallMethod(socket_pool[c.id()], "sendto", "y#iO",
                        c.data().data(), c.data().size(), c.flags(), addr_tuple);
                    Py_DECREF(addr_tuple);
                }
            }
            break;
        }
        
        case Command::kSockSendall: {
            const auto& c = cmd.sock_sendall();
            if (c.id() >= 64 || !socket_pool[c.id()]) break;
            if (c.flags() == 0) {
                result = PyObject_CallMethod(socket_pool[c.id()], "sendall", "y#",
                    c.data().data(), c.data().size());
            } else {
                result = PyObject_CallMethod(socket_pool[c.id()], "sendall", "y#i",
                    c.data().data(), c.data().size(), c.flags());
            }
            break;
        }
        
        case Command::kSockSendmsg: {
            const auto& c = cmd.sock_sendmsg();
            if (c.id() >= 64 || !socket_pool[c.id()]) break;
            PyObject* buffers = PyList_New(1);
            PyObject* data = PyBytes_FromStringAndSize(c.data().data(), c.data().size());
            PyList_SetItem(buffers, 0, data);
            result = PyObject_CallMethod(socket_pool[c.id()], "sendmsg", "Oi",
                buffers, c.flags());
            Py_DECREF(buffers);
            break;
        }
        
        case Command::kSockRecv: {
            const auto& c = cmd.sock_recv();
            if (c.id() >= 64 || !socket_pool[c.id()]) break;
            // Limit receive size to prevent excessive memory allocation
            uint32_t recv_size = c.maxlen() > 65536 ? 65536 : c.maxlen();
            result = PyObject_CallMethod(socket_pool[c.id()], "recv", "Ii",
                recv_size, c.flags());
            break;
        }
        
        case Command::kSockRecvfrom: {
            const auto& c = cmd.sock_recvfrom();
            if (c.id() >= 64 || !socket_pool[c.id()]) break;
            // Limit receive size to prevent excessive memory allocation
            uint32_t recv_size = c.maxlen() > 65536 ? 65536 : c.maxlen();
            result = PyObject_CallMethod(socket_pool[c.id()], "recvfrom", "Ii",
                recv_size, c.flags());
            break;
        }
        
        case Command::kSockRecvmsg: {
            const auto& c = cmd.sock_recvmsg();
            if (c.id() >= 64 || !socket_pool[c.id()]) break;
            // Limit receive size to prevent excessive memory allocation
            uint32_t recv_size = c.maxlen() > 65536 ? 65536 : c.maxlen();
            result = PyObject_CallMethod(socket_pool[c.id()], "recvmsg", "IIi",
                recv_size, c.ancbufsize(), c.flags());
            break;
        }
        
        case Command::kSockRecvInto: {
            const auto& c = cmd.sock_recv_into();
            if (c.id() >= 64 || !socket_pool[c.id()]) break;
            // Limit buffer size to prevent excessive memory allocation
            uint32_t buf_size = c.nbytes() > 65536 ? 65536 : c.nbytes();
            PyObject* buf = PyByteArray_FromStringAndSize(nullptr, buf_size);
            if (buf) {
                result = PyObject_CallMethod(socket_pool[c.id()], "recv_into", "Oi",
                    buf, c.flags());
                Py_DECREF(buf);
            }
            break;
        }
        
        case Command::kSockRecvfromInto: {
            const auto& c = cmd.sock_recvfrom_into();
            if (c.id() >= 64 || !socket_pool[c.id()]) break;
            // Limit buffer size to prevent excessive memory allocation
            uint32_t buf_size = c.nbytes() > 65536 ? 65536 : c.nbytes();
            PyObject* buf = PyByteArray_FromStringAndSize(nullptr, buf_size);
            if (buf) {
                result = PyObject_CallMethod(socket_pool[c.id()], "recvfrom_into", "Oi",
                    buf, c.flags());
                Py_DECREF(buf);
            }
            break;
        }
        
        case Command::kSockRecvmsgInto: {
            const auto& c = cmd.sock_recvmsg_into();
            if (c.id() >= 64 || !socket_pool[c.id()]) break;
            // Limit buffer size to prevent excessive memory allocation
            uint32_t buf_size = c.nbytes() > 65536 ? 65536 : c.nbytes();
            PyObject* buf = PyByteArray_FromStringAndSize(nullptr, buf_size);
            if (buf) {
                PyObject* buffers = PyList_New(1);
                PyList_SetItem(buffers, 0, buf);
                result = PyObject_CallMethod(socket_pool[c.id()], "recvmsg_into", "OIi",
                    buffers, c.ancbufsize(), c.flags());
                Py_DECREF(buffers);
            }
            break;
        }
        
        case Command::kSockSettimeout: {
            const auto& c = cmd.sock_settimeout();
            if (c.id() >= 64 || !socket_pool[c.id()]) break;
            result = PyObject_CallMethod(socket_pool[c.id()], "settimeout", "d", c.timeout());
            break;
        }
        
        case Command::kSockSetblocking: {
            const auto& c = cmd.sock_setblocking();
            if (c.id() >= 64 || !socket_pool[c.id()]) break;
            result = PyObject_CallMethod(socket_pool[c.id()], "setblocking", "i",
                c.blocking() ? 1 : 0);
            break;
        }
        
        default:
            break;
    }
    
    Py_XDECREF(result);
    
    if (PyErr_Occurred()) {
        __sanitizer_cov_trace_pc_guard_cmp8(0, 1);
        PyErr_Clear();
    }
}

extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv) {
    Py_SetProgramName(L"fuzz_socket");
    Py_SetPythonHome(L"buildroot/usr");
    Py_NoSiteFlag = 1;
    Py_IsolatedFlag = 1;
    Py_Initialize();
    
    socket_module = PyImport_ImportModule("socket");
    if (!socket_module) {
        PyErr_Print();
        exit(1);
    }
    
    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    __wrap_input = data;
    
    Program program;
    if (!program.ParseFromArray(data, size)) {
        return 0;
    }
    
    if (program.cmds_size() > 64) {
        return 0;
    }
    
    reset_resource_pool();
    apply_InitSection(program.init());
    
    for (const auto& cmd : program.cmds()) {
        do_command(cmd);
    }
    
    PyErr_Clear();
    
    if (++iteration_count >= 1024) {
        _PyGC_CollectNoFail();
        iteration_count = 0;
    }
    
    return 0;
}

static void cleanup_invalid_commands(Program* program) {
    std::array<bool, 64> valid_ids = {false};
    
    for (const auto& init : program->init().socks()) {
        if (init.id() < 64) {
            valid_ids[init.id()] = true;
        }
    }
    
    auto* cmds = program->mutable_cmds();
    cmds->erase(
        std::remove_if(cmds->begin(), cmds->end(),
            [&valid_ids](const Command& cmd) {
                uint32_t id = 0;
                bool needs_socket = false;
                
                switch (cmd.cmd_case()) {
                    case Command::kSockSocket:
                        id = cmd.sock_socket().target_id();
                        if (id < 64) valid_ids[id] = true;
                        return false;
                    case Command::kSockSocketpair:
                        if (cmd.sock_socketpair().id1() < 64) valid_ids[cmd.sock_socketpair().id1()] = true;
                        if (cmd.sock_socketpair().id2() < 64) valid_ids[cmd.sock_socketpair().id2()] = true;
                        return false;
                    case Command::kSockDup:
                        id = cmd.sock_dup().src_id();
                        needs_socket = true;
                        if (id < 64 && valid_ids[id] && cmd.sock_dup().dst_id() < 64) {
                            valid_ids[cmd.sock_dup().dst_id()] = true;
                        }
                        break;
                    case Command::kSockClose:
                        id = cmd.sock_close().id();
                        needs_socket = true;
                        break;
                    case Command::kSockAccept:
                        id = cmd.sock_accept().id();
                        needs_socket = true;
                        if (id < 64 && valid_ids[id] && cmd.sock_accept().new_id() < 64) {
                            valid_ids[cmd.sock_accept().new_id()] = true;
                        }
                        break;
                    case Command::kSockBind:
                        id = cmd.sock_bind().id();
                        needs_socket = true;
                        break;
                    case Command::kSockListen:
                        id = cmd.sock_listen().id();
                        needs_socket = true;
                        break;
                    case Command::kSockConnect:
                        id = cmd.sock_connect().id();
                        needs_socket = true;
                        break;
                    case Command::kSockConnectEx:
                        id = cmd.sock_connect_ex().id();
                        needs_socket = true;
                        break;
                    case Command::kSockShutdown:
                        id = cmd.sock_shutdown().id();
                        needs_socket = true;
                        break;
                    case Command::kSockSetsockopt:
                        id = cmd.sock_setsockopt().id();
                        needs_socket = true;
                        break;
                    case Command::kSockGetsockopt:
                        id = cmd.sock_getsockopt().id();
                        needs_socket = true;
                        break;
                    case Command::kSockSend:
                        id = cmd.sock_send().id();
                        needs_socket = true;
                        break;
                    case Command::kSockSendto:
                        id = cmd.sock_sendto().id();
                        needs_socket = true;
                        break;
                    case Command::kSockSendall:
                        id = cmd.sock_sendall().id();
                        needs_socket = true;
                        break;
                    case Command::kSockSendmsg:
                        id = cmd.sock_sendmsg().id();
                        needs_socket = true;
                        break;
                    case Command::kSockRecv:
                        id = cmd.sock_recv().id();
                        needs_socket = true;
                        break;
                    case Command::kSockRecvfrom:
                        id = cmd.sock_recvfrom().id();
                        needs_socket = true;
                        break;
                    case Command::kSockRecvmsg:
                        id = cmd.sock_recvmsg().id();
                        needs_socket = true;
                        break;
                    case Command::kSockRecvInto:
                        id = cmd.sock_recv_into().id();
                        needs_socket = true;
                        break;
                    case Command::kSockRecvfromInto:
                        id = cmd.sock_recvfrom_into().id();
                        needs_socket = true;
                        break;
                    case Command::kSockRecvmsgInto:
                        id = cmd.sock_recvmsg_into().id();
                        needs_socket = true;
                        break;
                    case Command::kSockSettimeout:
                        id = cmd.sock_settimeout().id();
                        needs_socket = true;
                        break;
                    case Command::kSockSetblocking:
                        id = cmd.sock_setblocking().id();
                        needs_socket = true;
                        break;
                    default:
                        return false;
                }
                
                return needs_socket && (id >= 64 || !valid_ids[id]);
            }),
        cmds->end());
}

// Custom mutator and crossover wrappers used by libprotobuf-mutator
extern "C" size_t LLVMFuzzerCustomMutator(uint8_t *data, size_t size,
                                           size_t max_size, unsigned int seed) {
    Program program;
    size = protobuf_mutator::libfuzzer::CustomProtoMutator(false, data, size,
                                                           max_size, seed,
                                                           &program);
    cleanup_invalid_commands(&program);
    size_t new_size = program.ByteSizeLong();
    if (new_size > max_size) new_size = max_size;
    if (program.SerializeToArray(data, new_size)) {
        return new_size;
    }
    return 0;
}

extern "C" size_t LLVMFuzzerCustomCrossOver(const uint8_t *data1, size_t size1,
                                             const uint8_t *data2, size_t size2,
                                             uint8_t *out, size_t max_out_size,
                                             unsigned int seed) {
    Program program1;
    Program program2;
    size_t out_size = protobuf_mutator::libfuzzer::CustomProtoCrossOver(false,
                                                                       data1,
                                                                       size1,
                                                                       data2,
                                                                       size2,
                                                                       out,
                                                                       max_out_size,
                                                                       seed,
                                                                       &program1,
                                                                       &program2);
    Program out_program;
    if (out_program.ParseFromArray(out, out_size)) {
        cleanup_invalid_commands(&out_program);
        size_t new_size = out_program.ByteSizeLong();
        if (new_size > max_out_size) new_size = max_out_size;
        if (out_program.SerializeToArray(out, new_size)) {
            return new_size;
        }
    }
    return out_size;
}
