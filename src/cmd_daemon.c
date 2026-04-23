#include <stdio.h>

#include "commands.h"

int
cmd_daemon(int argc, char **argv)
{
    (void)argc; (void)argv;
    fprintf(stderr, "[dht44:cmd_daemon] daemon: not implemented yet\n");
    return 1;
}
