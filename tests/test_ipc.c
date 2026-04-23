#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

#include "ipc.h"

static int failures = 0;

#define FAIL(fmt, ...) do { \
    fprintf(stderr, "FAIL %s:%d: " fmt "\n", __FILE__, __LINE__, ##__VA_ARGS__); \
    failures++; \
} while (0)

#define EXPECT(cond) do { if (!(cond)) FAIL("%s", #cond); } while (0)

/* End-to-end framing test using a socketpair. The "server" half is wrapped
 * in an ipc_conn; the "client" half drives ipc_request directly. */
static void
test_request_response_roundtrip(void)
{
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) < 0) {
        fprintf(stderr, "socketpair: %s\n", strerror(errno));
        failures++;
        return;
    }
    /* server side: non-blocking */
    int flags = fcntl(sv[0], F_GETFL, 0);
    fcntl(sv[0], F_SETFL, flags | O_NONBLOCK);

    ipc_conn *server = ipc_conn_new(sv[0]);
    EXPECT(server != NULL);

    /* Fork to drive both sides. Child = client, parent = server. */
    pid_t pid = fork();
    if (pid < 0) { failures++; return; }
    if (pid == 0) {
        ipc_conn_free(server);          /* close server side in child */
        const char *req = "d3:opi42ee"; /* arbitrary bencode */
        uint8_t resp[64];
        size_t resp_len = 0;
        int rc = ipc_request(sv[1], req, strlen(req), resp, sizeof(resp), &resp_len);
        if (rc < 0 || resp_len != 12 || memcmp(resp, "d3:opi43e1:r", 12) != 0) {
            _exit(1);
        }
        _exit(0);
    }

    /* parent: read the client's request, respond */
    const uint8_t *msg = NULL;
    size_t msg_len = 0;
    /* spin a bit (5s ceiling) */
    for (int i = 0; i < 5000; i++) {
        int rc = ipc_conn_try_read(server, &msg, &msg_len);
        if (rc == 1) break;
        if (rc < 0) { failures++; goto end; }
        usleep(1000);
    }
    EXPECT(msg_len == 10);
    EXPECT(memcmp(msg, "d3:opi42ee", 10) == 0);
    ipc_conn_consume(server);

    EXPECT(ipc_conn_send(server, "d3:opi43e1:r", 12) == 0);

end:
    ipc_conn_free(server);
    int status = 0;
    waitpid(pid, &status, 0);
    EXPECT(WIFEXITED(status) && WEXITSTATUS(status) == 0);
}

static void
test_oversize_rejected(void)
{
    /* manually craft a header claiming 16 MB then verify try_read rejects */
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) < 0) {
        failures++; return;
    }
    int flags = fcntl(sv[0], F_GETFL, 0);
    fcntl(sv[0], F_SETFL, flags | O_NONBLOCK);

    ipc_conn *server = ipc_conn_new(sv[0]);
    EXPECT(server != NULL);

    /* 0x01000000 = 16 MB, > IPC_MAX_MESSAGE */
    uint8_t hdr[4] = { 0x01, 0x00, 0x00, 0x00 };
    write(sv[1], hdr, sizeof(hdr));

    const uint8_t *msg = NULL;
    size_t msg_len = 0;
    /* let it process */
    int rc = ipc_conn_try_read(server, &msg, &msg_len);
    /* might need to read again to consume header */
    if (rc == 0) {
        /* drain header into the conn buffer */
        usleep(1000);
        rc = ipc_conn_try_read(server, &msg, &msg_len);
    }
    EXPECT(rc == -1);

    close(sv[1]);
    ipc_conn_free(server);
}

int
main(void)
{
    test_request_response_roundtrip();
    test_oversize_rejected();

    if (failures) {
        fprintf(stderr, "FAIL: %d failure(s)\n", failures);
        return 1;
    }
    fputs("ok: ipc\n", stderr);
    return 0;
}
