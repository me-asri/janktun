#include <stddef.h>
#include <stdlib.h>

#include "args.h"
#include "log.h"
#include "server.h"
#include "client.h"

static int run_client(jank_args_t* args);
static int run_server(jank_args_t* args);

int main(int argc, char** argv)
{
    jank_args_t args;
    int ret;

    ret = jank_args_parse(&args, argc, argv);
    if (ret <= 0) {
        return ret;
    }

    log_init(args.log_level);
    switch (args.op) {
    case JANK_OP_CLIENT:
        return run_client(&args);
    case JANK_OP_SERVER:
        return run_server(&args);
    default:
        abort();
    }
}

int run_client(jank_args_t* args)
{
    jank_client_ctx_t client;
    int ret;

    if (jank_client_init(&client, args->domain, args->client.max_domain_len,
            args->client.resolvers, args->client.inbound_listen_addr,
            args->client.ds_listen_addr, args->client.ds_src_addr)
        != 0) {
        log_e("Failed to initialize client");
        return -1;
    }
    ret = jank_client_run(&client);
    if (ret < 0) {
        log_e("Failed to start client");
    }

    jank_client_destroy(&client);
    return ret;
}

int run_server(jank_args_t* args)
{
    jank_server_ctx_t server;
    int ret;

    if (jank_server_init(&server, args->domain,
            args->server.dns_listen_addr, args->server.ds_addr,
            args->server.ds_src_addr, args->server.dest_addr)
        != 0) {
        log_e("Failed to initialize server");
        return -1;
    }
    ret = jank_server_run(&server);
    if (ret < 0) {
        log_e("Failed to start server");
    }

    jank_server_destroy(&server);
    return ret;
}