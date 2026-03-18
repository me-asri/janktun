#pragma once

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#include <sys/types.h>
#include <sys/uio.h>

#include "bits.h"
#include "dns.h"

/* [Base] (dot) [7 (32-bit metadata)] + (dot) */
#define PROTO_DOMAIN_LEN_OVERHEAD 9

/* Assuming max domain length while excluding overhead,
   you can only store 152 bytes as Base32 without padding */
#define PROTO_FRAG_LEN_MAX 152

/* Maximum number of fragments */
#define PROTO_FRAG_MAX 64

/* Maximum size of datagram fittable in a DNS query */
#define PROTO_MAX_DATAGRAM (PROTO_FRAG_LEN_MAX * PROTO_FRAG_MAX)

typedef struct {
    union {
        struct {
            uint32_t session_id : 25;
            uint32_t frag_idx : 6;
            uint32_t last_frag : 1;
        };
        uint32_t u32;
    };
} metadata_t;

typedef enum {
    PROTOERR_SUCCESS = 0,
    PROTOERR_OVERFLOW = -1,
    PROTOERR_INVALID = -2,
    PROTOERR_INTER = -3,
    PROTOERR_DUP = -4,
    PROTOERR_INCOMPLETE = -5,
} protoerr_t;

typedef struct {
    bitset64_t received_frags;
    uint8_t max_frag_count;
    uint8_t max_frag_size;
    uint8_t last_frag_size;
    char buf[PROTO_MAX_DATAGRAM];
} frag_assembler_t;

/* Callback for `protocol_encode_domain` */
typedef bool (*proto_domain_cb_t)(metadata_t* metadata, char* domain, void* userdata);

/* Decode domain name into bytes */
ssize_t protocol_decode_domain(char* domain, size_t domain_len,
    const char* base_domain, size_t base_domain_len,
    metadata_t* metadata, char* buf, size_t buflen);

/* Encode bytes into domain name */
protoerr_t protocol_encode_domain(
    const char* base_domain, size_t base_domain_len, size_t max_domain_len,
    const char* buf, size_t buflen,
    proto_domain_cb_t callback, void* userdata);

/* Initialize fragment assembler */
void frag_assembler_init(frag_assembler_t* assembler);

/* Add fragment to assembler */
protoerr_t frag_assembler_add(frag_assembler_t* assembler,
    uint8_t frag_idx, bool last_frag, char* buf, size_t buflen);

/* Try assembling all fragments */
protoerr_t frag_assembler_assemble(frag_assembler_t* assembler, char** buf, size_t* buflen);
