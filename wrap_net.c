#define _GNU_SOURCE
#include <dlfcn.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <poll.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdbool.h>

typedef int (*socketpair_fn)(int, int, int, int[2]);
typedef int (*connect_fn)(int, const struct sockaddr*, socklen_t);
typedef int (*accept_fn)(int, struct sockaddr*, socklen_t*);
typedef int (*poll_fn)(struct pollfd*, nfds_t, int);
typedef ssize_t (*send_fn)(int, const void*, size_t, int);
typedef ssize_t (*recv_fn)(int, void*, size_t, int);
typedef ssize_t (*sendmsg_fn)(int, const struct msghdr*, int);
typedef ssize_t (*recvmsg_fn)(int, struct msghdr*, int);
typedef ssize_t (*sendto_fn)(int, const void*, size_t, int, const struct sockaddr*, socklen_t);
typedef ssize_t (*recvfrom_fn)(int, void*, size_t, int, struct sockaddr*, socklen_t*);
typedef int (*bind_fn)(int, const struct sockaddr*, socklen_t);
typedef int (*getaddrinfo_fn)(const char*, const char*, const struct addrinfo*, struct addrinfo**);
typedef int (*getnameinfo_fn)(const struct sockaddr*, socklen_t, char*, socklen_t, char*, socklen_t, int);
typedef int (*close_fn)(int);

static socketpair_fn real_socketpair;
static connect_fn real_connect;
static accept_fn real_accept;
static poll_fn real_poll;
static send_fn real_send;
static recv_fn real_recv;
static sendmsg_fn real_sendmsg;
static recvmsg_fn real_recvmsg;
static sendto_fn real_sendto;
static recvfrom_fn real_recvfrom;
static bind_fn real_bind;
static getaddrinfo_fn real_getaddrinfo;
static getnameinfo_fn real_getnameinfo;
static close_fn real_close;

static int call_counts[16] = {0};
static int pair_fd[1024] = {[0 ... 1023] = -1};

// This will be set by the fuzzer
extern const uint8_t *__wrap_input;

__attribute__((constructor))
static void init_wrap() {
    real_socketpair = dlsym(RTLD_NEXT, "socketpair");
    real_connect = dlsym(RTLD_NEXT, "connect");
    real_accept = dlsym(RTLD_NEXT, "accept");
    real_poll = dlsym(RTLD_NEXT, "poll");
    real_send = dlsym(RTLD_NEXT, "send");
    real_recv = dlsym(RTLD_NEXT, "recv");
    real_sendmsg = dlsym(RTLD_NEXT, "sendmsg");
    real_recvmsg = dlsym(RTLD_NEXT, "recvmsg");
    real_sendto = dlsym(RTLD_NEXT, "sendto");
    real_recvfrom = dlsym(RTLD_NEXT, "recvfrom");
    real_bind = dlsym(RTLD_NEXT, "bind");
    real_getaddrinfo = dlsym(RTLD_NEXT, "getaddrinfo");
    real_getnameinfo = dlsym(RTLD_NEXT, "getnameinfo");
    real_close = dlsym(RTLD_NEXT, "close");
}

int socketpair(int domain, int type, int protocol, int sv[2]) {
    if (!real_socketpair) real_socketpair = dlsym(RTLD_NEXT, "socketpair");
    
    // Always use real socketpair for AF_UNIX but track the pair
    if (domain == AF_UNIX) {
        int ret = real_socketpair(domain, type, protocol, sv);
        if (ret == 0) {
            if (sv[0] < 1024) pair_fd[sv[0]] = sv[1];
            if (sv[1] < 1024) pair_fd[sv[1]] = sv[0];
        }
        return ret;
    }
    
    // For other domains, succeed first time or based on input bit
    if (call_counts[0]++ == 0 || (__wrap_input && (__wrap_input[0] & 1))) {
        int unix_sv[2];
        if (real_socketpair(AF_UNIX, type, 0, unix_sv) == 0) {
            sv[0] = unix_sv[0];
            sv[1] = unix_sv[1];
            if (sv[0] < 1024) pair_fd[sv[0]] = sv[1];
            if (sv[1] < 1024) pair_fd[sv[1]] = sv[0];
            return 0;
        }
    }
    errno = ECONNREFUSED;
    return -1;
}

int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
    if (!real_connect) real_connect = dlsym(RTLD_NEXT, "connect");
    
    if (call_counts[1]++ == 0 || (__wrap_input && (__wrap_input[0] & 2))) {
        return 0;  // Success
    }
    errno = ECONNREFUSED;
    return -1;
}

int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
    if (!real_bind) real_bind = dlsym(RTLD_NEXT, "bind");

    if (call_counts[12]++ == 0 || (__wrap_input && (__wrap_input[0] & 128))) {
        return 0;
    }
    errno = EADDRINUSE;
    return -1;
}

int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen) {
    if (!real_accept) real_accept = dlsym(RTLD_NEXT, "accept");
    
    if (call_counts[2]++ == 0 || (__wrap_input && (__wrap_input[0] & 4))) {
        int fds[2];
        if (real_socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0) {
            if (addr && addrlen && *addrlen >= sizeof(struct sockaddr_in)) {
                struct sockaddr_in *sin = (struct sockaddr_in*)addr;
                sin->sin_family = AF_INET;
                sin->sin_port = htons(1234);
                sin->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
                *addrlen = sizeof(struct sockaddr_in);
            }
            close(fds[1]);
            return fds[0];
        }
    }
    errno = EAGAIN;
    return -1;
}

int poll(struct pollfd *fds, nfds_t nfds, int timeout) {
    if (!real_poll) real_poll = dlsym(RTLD_NEXT, "poll");
    
    if (call_counts[3]++ == 0) {
        for (nfds_t i = 0; i < nfds; i++) {
            fds[i].revents = fds[i].events & (POLLIN | POLLOUT);
        }
        return nfds;
    }
    errno = EINTR;
    return -1;
}

ssize_t send(int sockfd, const void *buf, size_t len, int flags) {
    if (!real_send) real_send = dlsym(RTLD_NEXT, "send");
    
    if (call_counts[4]++ == 0 || (__wrap_input && (__wrap_input[0] & 8))) {
        if (sockfd < 1024 && pair_fd[sockfd] >= 0) {
            return write(pair_fd[sockfd], buf, len);
        }
        return len;  // Pretend we sent it all
    }
    errno = EAGAIN;
    return -1;
}

ssize_t recv(int sockfd, void *buf, size_t len, int flags) {
    if (!real_recv) real_recv = dlsym(RTLD_NEXT, "recv");
    
    if (call_counts[5]++ == 0 || (__wrap_input && (__wrap_input[0] & 16))) {
        if (sockfd < 1024 && pair_fd[sockfd] >= 0) {
            ssize_t ret = read(sockfd, buf, len);
            if (ret > 0) return ret;
        }
        // Return some dummy data
        if (len > 0) {
            memset(buf, 'A', len > 4 ? 4 : len);
            return len > 4 ? 4 : len;
        }
        return 0;
    }
    errno = EAGAIN;
    return -1;
}

ssize_t sendto(int sockfd, const void *buf, size_t len, int flags,
               const struct sockaddr *dest_addr, socklen_t addrlen) {
    if (!real_sendto) real_sendto = dlsym(RTLD_NEXT, "sendto");

    if (call_counts[10]++ == 0 || (__wrap_input && (__wrap_input[0] & 32))) {
        if (sockfd < 1024 && pair_fd[sockfd] >= 0) {
            return write(pair_fd[sockfd], buf, len);
        }
        return len;
    }
    errno = EAGAIN;
    return -1;
}

ssize_t recvfrom(int sockfd, void *buf, size_t len, int flags,
                 struct sockaddr *src_addr, socklen_t *addrlen) {
    if (!real_recvfrom) real_recvfrom = dlsym(RTLD_NEXT, "recvfrom");

    if (call_counts[11]++ == 0 || (__wrap_input && (__wrap_input[0] & 64))) {
        if (sockfd < 1024 && pair_fd[sockfd] >= 0) {
            ssize_t ret = read(sockfd, buf, len);
            if (ret > 0) {
                if (src_addr && addrlen && *addrlen >= sizeof(struct sockaddr_in)) {
                    struct sockaddr_in *sin = (struct sockaddr_in *)src_addr;
                    sin->sin_family = AF_INET;
                    sin->sin_port = htons(1234);
                    sin->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
                    *addrlen = sizeof(struct sockaddr_in);
                }
                return ret;
            }
        }
        if (len > 0) {
            memset(buf, 'C', len > 4 ? 4 : len);
            if (src_addr && addrlen && *addrlen >= sizeof(struct sockaddr_in)) {
                struct sockaddr_in *sin = (struct sockaddr_in *)src_addr;
                sin->sin_family = AF_INET;
                sin->sin_port = htons(1234);
                sin->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
                *addrlen = sizeof(struct sockaddr_in);
            }
            return len > 4 ? 4 : len;
        }
        return 0;
    }
    errno = EAGAIN;
    return -1;
}

ssize_t sendmsg(int sockfd, const struct msghdr *msg, int flags) {
    if (!real_sendmsg) real_sendmsg = dlsym(RTLD_NEXT, "sendmsg");
    
    if (call_counts[6]++ == 0) {
        size_t total = 0;
        for (size_t i = 0; i < msg->msg_iovlen; i++) {
            total += msg->msg_iov[i].iov_len;
        }
        return total;
    }
    errno = EPIPE;
    return -1;
}

ssize_t recvmsg(int sockfd, struct msghdr *msg, int flags) {
    if (!real_recvmsg) real_recvmsg = dlsym(RTLD_NEXT, "recvmsg");
    
    if (call_counts[7]++ == 0) {
        size_t total = 0;
        for (size_t i = 0; i < msg->msg_iovlen && total < 16; i++) {
            size_t len = msg->msg_iov[i].iov_len;
            if (len > 16 - total) len = 16 - total;
            memset(msg->msg_iov[i].iov_base, 'B', len);
            total += len;
        }
        msg->msg_controllen = 0;
        return total;
    }
    errno = EAGAIN;
    return -1;
}

int getaddrinfo(const char *node, const char *service,
                const struct addrinfo *hints,
                struct addrinfo **res) {
    if (!real_getaddrinfo) real_getaddrinfo = dlsym(RTLD_NEXT, "getaddrinfo");
    
    if (call_counts[8]++ == 0) {
        struct addrinfo *ai = calloc(1, sizeof(struct addrinfo));
        struct sockaddr_in *sin = calloc(1, sizeof(struct sockaddr_in));
        
        sin->sin_family = AF_INET;
        sin->sin_port = htons(80);
        sin->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        
        ai->ai_family = AF_INET;
        ai->ai_socktype = SOCK_STREAM;
        ai->ai_protocol = IPPROTO_TCP;
        ai->ai_addrlen = sizeof(struct sockaddr_in);
        ai->ai_addr = (struct sockaddr*)sin;
        ai->ai_canonname = node ? strdup(node) : strdup("localhost");
        
        *res = ai;
        return 0;
    }
    return EAI_AGAIN;
}

int getnameinfo(const struct sockaddr *addr, socklen_t addrlen,
                char *host, socklen_t hostlen,
                char *serv, socklen_t servlen, int flags) {
    if (!real_getnameinfo) real_getnameinfo = dlsym(RTLD_NEXT, "getnameinfo");
    
    if (call_counts[9]++ == 0) {
        if (host && hostlen > 0) {
            strncpy(host, "localhost", hostlen - 1);
            host[hostlen - 1] = '\0';
        }
        if (serv && servlen > 0) {
            strncpy(serv, "80", servlen - 1);
            serv[servlen - 1] = '\0';
        }
        return 0;
    }
    return EAI_AGAIN;
}

int close(int fd) {
    if (!real_close) real_close = dlsym(RTLD_NEXT, "close");

    if (fd < 1024) {
        int partner = pair_fd[fd];
        if (partner >= 0 && partner < 1024) {
            pair_fd[partner] = -1;
        }
        pair_fd[fd] = -1;
    }

    return real_close(fd);
}

// Called by the fuzzer to clean up any remaining descriptors
void wrap_reset(void) {
    if (!real_close) real_close = dlsym(RTLD_NEXT, "close");
    for (int i = 0; i < 1024; i++) {
        if (pair_fd[i] >= 0) {
            real_close(i);
            pair_fd[i] = -1;
        }
    }
}
