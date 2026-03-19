#pragma once

#include "bits.h"
#include "dns.h"
#include "protocol.h"

#define SERVER_MAX_ASM_SESSIONS 512
#define SERVER_MAX_SESSION_HIST 1024

typedef struct {
    uint32_t session_id;
    uint64_t timestamp;
    frag_assembler_t assembler;
} asm_session_t;

typedef struct {
    uint32_t session_id;
    uint64_t timestamp;
} session_hist_entry_t;

typedef struct {
    session_hist_entry_t entries[SERVER_MAX_SESSION_HIST];

    size_t head;
    size_t tail;
    size_t count;
} session_hist_t;

typedef struct {
    char domain[DNS_MAX_DOMAIN_LEN + 1];
    size_t domain_len;

    int dns_sockfd;
    int dest_sockfd;
    int ds_sockfd;

    int epollfd;

    bitset512_t active_asm_sessions;
    asm_session_t asm_sessions[SERVER_MAX_ASM_SESSIONS];

    session_hist_t session_hist;
} jank_server_ctx_t;

/* Initialize janktun server context */
int jank_server_init(jank_server_ctx_t* ctx, const char* domain,
    const char* dns_listen_addr, const char* ds_addr,
    const char* ds_src_addr, const char* dest_addr);

/* Start janktun server */
int jank_server_run(jank_server_ctx_t* ctx);

/* Destroy and free up janktun server context */
int jank_server_destroy(jank_server_ctx_t* ctx);
