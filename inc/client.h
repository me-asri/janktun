#pragma once

#include <stddef.h>
#include <sys/socket.h>

#include "dns.h"

#define CLIENT_MAX_RESOLVERS 16

typedef struct {
    char domain[DNS_MAX_DOMAIN_LEN];
    size_t domain_len;
    size_t max_domain_len;

    int epollfd;

    int dns_sockfd;
    int inbound_sockfd;
    int ds_sockfd;

    struct sockaddr_storage resolver_addrs[CLIENT_MAX_RESOLVERS];
    socklen_t resolver_addrlens[CLIENT_MAX_RESOLVERS];
    size_t resolver_count;
    size_t resolver_index;

    struct sockaddr_storage last_ds_addr;
    socklen_t last_ds_addrlen;

    struct sockaddr_storage last_inbound_addr;
    socklen_t last_inbound_addrlen;
} jank_client_ctx_t;

/* Initialize janktun client instance */
int jank_client_init(jank_client_ctx_t* ctx,
    const char* domain, size_t max_domain_len, const char** resolvers,
    const char* inbound_listen_addr, const char* ds_listen_addr,
    const char* ds_src_addr);

/* Run janktun client*/
int jank_client_run(jank_client_ctx_t* ctx);

/* Destroy and free janktun client instance */
int jank_client_destroy(jank_client_ctx_t* ctx);
