#ifndef DHT44_IPC_H
#define DHT44_IPC_H

#include <stddef.h>
#include <stdint.h>

/*
 * Local IPC between dht44 CLI and daemon over an AF_UNIX SOCK_STREAM at
 * $DHT44_HOME/sock (mode 0700). Wire format per message:
 *
 *   uint32_t length  (BE)
 *   uint8_t  payload[length]   ; bencoded dict
 *
 * Max message size IPC_MAX_MESSAGE — anything larger is rejected.
 */

#define IPC_MAX_MESSAGE (256 * 1024)

/* ===== Server (daemon) ===== */

/* Bind, listen on $DHT44_HOME/sock with backlog 8. The socket file is
 * unlinked + recreated; mode 0700. Returns the listen fd, or -1 on error. */
int ipc_listen(void);

/* Convenience: $DHT44_HOME/sock path written into out (no trailing slash). */
int ipc_socket_path(char *out, size_t cap);

/* Unlink the socket file (no error if missing). Caller closes the fd. */
void ipc_cleanup(void);

/* Accept a new client (non-blocking listen fd). Returns the client fd
 * (also non-blocking), or -1 if no pending connections. */
int ipc_accept(int listen_fd);

/* Per-client read buffer state. Opaque from outside. */
typedef struct ipc_conn ipc_conn;

ipc_conn *ipc_conn_new(int fd);
void      ipc_conn_free(ipc_conn *c);
int       ipc_conn_fd(const ipc_conn *c);

/*
 * Pull bytes from the kernel into the per-conn read buffer. If a complete
 * framed message is now available, sets out and out_len to a pointer inside
 * the buffer (valid until ipc_conn_consume) and returns 1. Returns 0 if
 * more bytes are needed, -1 on EOF or fatal error.
 */
int ipc_conn_try_read(ipc_conn *c, const uint8_t **out, size_t *out_len);

/* Mark the current message consumed so the next try_read can yield a new one. */
void ipc_conn_consume(ipc_conn *c);

/* Send a framed message (blocks; only used for small responses ≪ MTU). */
int ipc_conn_send(ipc_conn *c, const void *buf, size_t len);

/* ===== Client (CLI) ===== */

/* Connect to $DHT44_HOME/sock. Returns connected fd, or -1 if no daemon. */
int ipc_connect(void);

/*
 * Synchronous: send `req` framed, read one framed response into `resp`
 * (resp_cap is the max bytes accepted). Returns 0 on success, -1 on
 * error (including resp too large for resp_cap).
 */
int ipc_request(int fd,
                const void *req, size_t req_len,
                uint8_t *resp, size_t resp_cap, size_t *resp_len_out);

#endif
