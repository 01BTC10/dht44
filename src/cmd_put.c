#include <stdio.h>

#include "commands.h"

int
cmd_put(int argc, char **argv)
{
    (void)argc; (void)argv;
    fprintf(stderr, "[dht44:cmd_put] put: not implemented yet\n");
    return 1;
}

int
cmd_put_immutable(int argc, char **argv)
{
    (void)argc; (void)argv;
    fprintf(stderr, "[dht44:cmd_put] put-immutable: not implemented yet\n");
    return 1;
}
