#include <stdio.h>
#include <string.h>

#include "commands.h"

static void
usage(FILE *out)
{
    fputs(
        "usage: dht44 <command> [args]\n"
        "\n"
        "commands:\n"
        "  keygen -o KEYFILE\n"
        "  pubkey -k KEYFILE\n"
        "  target -k KEYFILE [--salt S]\n"
        "  put -k KEYFILE [--salt S] --seq N [--cas M] [--bencode|--string] VALUE\n"
        "  put-immutable [--bencode|--string] VALUE\n"
        "  get --target HEX\n"
        "  get -k KEYFILE [--salt S]\n"
        "  get --pubkey HEX [--salt S]\n"
        "  daemon [--port N] [--republish MIN] [--no-upnp] [--upnp-lifetime SEC]\n",
        out);
}

int
main(int argc, char **argv)
{
    if (argc < 2) {
        usage(stderr);
        return 1;
    }
    const char *cmd = argv[1];
    int sub_argc = argc - 1;
    char **sub_argv = argv + 1;

    if (strcmp(cmd, "-h") == 0 || strcmp(cmd, "--help") == 0) {
        usage(stdout);
        return 0;
    }
    if (strcmp(cmd, "keygen") == 0)        return cmd_keygen(sub_argc, sub_argv);
    if (strcmp(cmd, "pubkey") == 0)        return cmd_pubkey(sub_argc, sub_argv);
    if (strcmp(cmd, "target") == 0)        return cmd_target(sub_argc, sub_argv);
    if (strcmp(cmd, "put") == 0)           return cmd_put(sub_argc, sub_argv);
    if (strcmp(cmd, "put-immutable") == 0) return cmd_put_immutable(sub_argc, sub_argv);
    if (strcmp(cmd, "get") == 0)           return cmd_get(sub_argc, sub_argv);
    if (strcmp(cmd, "daemon") == 0)        return cmd_daemon(sub_argc, sub_argv);

    fprintf(stderr, "dht44: unknown command: %s\n", cmd);
    usage(stderr);
    return 1;
}
