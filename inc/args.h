#pragma once

#include <stddef.h>
#include "log.h"
#include "client.h"

typedef enum {
    JANK_OP_SERVER,
    JANK_OP_CLIENT,
} jank_op_t;

typedef struct {
    jank_op_t op;
    log_level_t log_level;

    const char* domain;

    union {
        struct {
            size_t max_domain_len;
            const char* resolvers[CLIENT_MAX_RESOLVERS + 1];
            const char* inbound_listen_addr;
            const char* ds_listen_addr;
            const char* ds_src_addr;
        } client;
        struct {
            const char* dns_listen_addr;
            const char* ds_addr;
            const char* ds_src_addr;
            const char* dest_addr;
        } server;
    };
} jank_args_t;

int jank_args_parse(jank_args_t* args, int argc, char** argv);
