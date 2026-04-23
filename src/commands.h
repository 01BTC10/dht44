#ifndef DHT44_COMMANDS_H
#define DHT44_COMMANDS_H

int cmd_keygen(int argc, char **argv);
int cmd_pubkey(int argc, char **argv);
int cmd_target(int argc, char **argv);
int cmd_put(int argc, char **argv);
int cmd_put_immutable(int argc, char **argv);
int cmd_get(int argc, char **argv);
int cmd_daemon(int argc, char **argv);

#endif
