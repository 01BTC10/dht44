#define _GNU_SOURCE          /* O_CLOEXEC, accept4, SOCK_NONBLOCK */

#include "ipc.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

#include "state.h"

#define PATH_MAX 4096
#define HEADER_LEN 4

int
ipc_socket_path(char *out, size_t cap)
{
    char home[PATH_MAX];
    if (state_home(home, sizeof(home)) < 0) return -1;
    int n = snprintf(out, cap, "%s/sock", home);
    return (n < 0 || (size_t)n >= cap) ? -1 : 0;
}

static int
fill_unix(struct sockaddr_un *addr, const char *path)
{
    if (strlen(path) >= sizeof(addr->sun_path)) {
        fprintf(stderr, "[dht44:ipc] path too long: %s\n", path);
        return -1;
    }
    memset(addr, 0, sizeof(*addr));
    addr->sun_family = AF_UNIX;
    strcpy(addr->sun_path, path);
    return 0;
}

void
ipc_cleanup(void)
{
    char path[PATH_MAX];
    if (ipc_socket_path(path, sizeof(path)) == 0) {
        unlink(path);
    }
}

int
ipc_listen(void)
{
    if (state_ensure_dir() < 0) return -1;
    char path[PATH_MAX];
    if (ipc_socket_path(path, sizeof(path)) < 0) return -1;

    /* Unlink any stale socket file from a prior run. */
    unlink(path);

    int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (fd < 0) {
        fprintf(stderr, "[dht44:ipc] socket: %s\n", strerror(errno));
        return -1;
    }
    struct sockaddr_un addr;
    if (fill_unix(&addr, path) < 0) { close(fd); return -1; }

    /* umask must be temporarily restrictive so the socket inherits 0700 */
    mode_t prev = umask(0077);
    int rc = bind(fd, (struct sockaddr *)&addr, sizeof(addr));
    umask(prev);
    if (rc < 0) {
        fprintf(stderr, "[dht44:ipc] bind %s: %s\n", path, strerror(errno));
        close(fd);
        return -1;
    }
    chmod(path, 0700);
    if (listen(fd, 8) < 0) {
        fprintf(stderr, "[dht44:ipc] listen: %s\n", strerror(errno));
        close(fd);
        unlink(path);
        return -1;
    }
    return fd;
}

int
ipc_accept(int listen_fd)
{
    int c = accept4(listen_fd, NULL, NULL, SOCK_NONBLOCK | SOCK_CLOEXEC);
    if (c < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
        fprintf(stderr, "[dht44:ipc] accept: %s\n", strerror(errno));
    }
    return c;
}

/* ============================================================
 * Per-connection state
 * ============================================================ */

struct ipc_conn {
    int       fd;
    uint8_t   header[HEADER_LEN];
    size_t    header_off;
    uint8_t  *body;
    size_t    body_cap;
    size_t    body_len;       /* bytes expected (decoded from header) */
    size_t    body_off;       /* bytes received so far */
    int       has_message;    /* 1 if a complete message is ready */
};

ipc_conn *
ipc_conn_new(int fd)
{
    ipc_conn *c = calloc(1, sizeof(*c));
    if (!c) return NULL;
    c->fd = fd;
    return c;
}

void
ipc_conn_free(ipc_conn *c)
{
    if (!c) return;
    if (c->fd >= 0) close(c->fd);
    free(c->body);
    free(c);
}

int
ipc_conn_fd(const ipc_conn *c)
{
    return c ? c->fd : -1;
}

static int
read_some(int fd, void *dst, size_t want, size_t *got)
{
    *got = 0;
    while (*got < want) {
        ssize_t n = read(fd, (char *)dst + *got, want - *got);
        if (n == 0) return -1;          /* EOF */
        if (n < 0) {
            if (errno == EINTR) continue;
            if (errno == EAGAIN || errno == EWOULDBLOCK) return 0;
            fprintf(stderr, "[dht44:ipc] read: %s\n", strerror(errno));
            return -1;
        }
        *got += (size_t)n;
    }
    return 0;
}

int
ipc_conn_try_read(ipc_conn *c, const uint8_t **out, size_t *out_len)
{
    if (c->has_message) return 1;       /* caller needs to consume() first */

    if (c->header_off < HEADER_LEN) {
        size_t got = 0;
        int rc = read_some(c->fd, c->header + c->header_off,
                           HEADER_LEN - c->header_off, &got);
        c->header_off += got;
        if (rc < 0) return -1;
        if (c->header_off < HEADER_LEN) return 0;

        /* parse big-endian length */
        size_t len =
              ((size_t)c->header[0] << 24)
            | ((size_t)c->header[1] << 16)
            | ((size_t)c->header[2] <<  8)
            | ((size_t)c->header[3]);
        if (len == 0 || len > IPC_MAX_MESSAGE) {
            fprintf(stderr, "[dht44:ipc] bad message length: %zu\n", len);
            return -1;
        }
        c->body_len = len;
        c->body_off = 0;
        if (c->body_cap < len) {
            uint8_t *nb = realloc(c->body, len);
            if (!nb) return -1;
            c->body = nb;
            c->body_cap = len;
        }
    }

    if (c->body_off < c->body_len) {
        size_t got = 0;
        int rc = read_some(c->fd, c->body + c->body_off,
                           c->body_len - c->body_off, &got);
        c->body_off += got;
        if (rc < 0) return -1;
        if (c->body_off < c->body_len) return 0;
    }

    c->has_message = 1;
    *out = c->body;
    *out_len = c->body_len;
    return 1;
}

void
ipc_conn_consume(ipc_conn *c)
{
    c->has_message = 0;
    c->header_off = 0;
    c->body_len = 0;
    c->body_off = 0;
}

int
ipc_conn_send(ipc_conn *c, const void *buf, size_t len)
{
    if (len == 0 || len > IPC_MAX_MESSAGE) return -1;
    uint8_t hdr[HEADER_LEN] = {
        (uint8_t)(len >> 24), (uint8_t)(len >> 16),
        (uint8_t)(len >> 8),  (uint8_t)(len)
    };
    /* Switch to blocking for the send to keep the helper simple. */
    int flags = fcntl(c->fd, F_GETFL, 0);
    if (flags >= 0) fcntl(c->fd, F_SETFL, flags & ~O_NONBLOCK);

    int rc = 0;
    size_t off = 0;
    while (off < HEADER_LEN) {
        ssize_t w = send(c->fd, hdr + off, HEADER_LEN - off, MSG_NOSIGNAL);
        if (w < 0) {
            if (errno == EINTR) continue;
            fprintf(stderr, "[dht44:ipc] send hdr: %s\n", strerror(errno));
            rc = -1;
            goto out;
        }
        off += (size_t)w;
    }
    off = 0;
    while (off < len) {
        ssize_t w = send(c->fd, (const char *)buf + off, len - off, MSG_NOSIGNAL);
        if (w < 0) {
            if (errno == EINTR) continue;
            fprintf(stderr, "[dht44:ipc] send body: %s\n", strerror(errno));
            rc = -1;
            goto out;
        }
        off += (size_t)w;
    }

out:
    if (flags >= 0) fcntl(c->fd, F_SETFL, flags);
    return rc;
}

/* ============================================================
 * Client side
 * ============================================================ */

int
ipc_connect(void)
{
    char path[PATH_MAX];
    if (ipc_socket_path(path, sizeof(path)) < 0) return -1;

    int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) return -1;
    struct sockaddr_un addr;
    if (fill_unix(&addr, path) < 0) { close(fd); return -1; }
    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        if (errno == ENOENT || errno == ECONNREFUSED) {
            /* No daemon — caller will print the user-facing message. */
        } else {
            fprintf(stderr, "[dht44:ipc] connect %s: %s\n", path, strerror(errno));
        }
        close(fd);
        return -1;
    }
    return fd;
}

static int
write_all(int fd, const void *buf, size_t len)
{
    size_t off = 0;
    while (off < len) {
        ssize_t w = send(fd, (const char *)buf + off, len - off, MSG_NOSIGNAL);
        if (w < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        off += (size_t)w;
    }
    return 0;
}

static int
read_all(int fd, void *buf, size_t len)
{
    size_t off = 0;
    while (off < len) {
        ssize_t r = read(fd, (char *)buf + off, len - off);
        if (r == 0) return -1;
        if (r < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        off += (size_t)r;
    }
    return 0;
}

int
ipc_request(int fd,
            const void *req, size_t req_len,
            uint8_t *resp, size_t resp_cap, size_t *resp_len_out)
{
    if (req_len == 0 || req_len > IPC_MAX_MESSAGE) return -1;
    uint8_t hdr[HEADER_LEN] = {
        (uint8_t)(req_len >> 24), (uint8_t)(req_len >> 16),
        (uint8_t)(req_len >> 8),  (uint8_t)(req_len)
    };
    if (write_all(fd, hdr, HEADER_LEN) < 0) return -1;
    if (write_all(fd, req, req_len) < 0) return -1;

    if (read_all(fd, hdr, HEADER_LEN) < 0) return -1;
    size_t resp_len =
          ((size_t)hdr[0] << 24)
        | ((size_t)hdr[1] << 16)
        | ((size_t)hdr[2] <<  8)
        | ((size_t)hdr[3]);
    if (resp_len == 0 || resp_len > IPC_MAX_MESSAGE) return -1;
    if (resp_len > resp_cap) {
        fprintf(stderr, "[dht44:ipc] response %zu > cap %zu\n", resp_len, resp_cap);
        return -1;
    }
    if (read_all(fd, resp, resp_len) < 0) return -1;
    *resp_len_out = resp_len;
    return 0;
}
