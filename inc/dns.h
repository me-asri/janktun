#pragma once

#include <stddef.h>
#include <stdint.h>

#include <sys/types.h>
#include <asm/byteorder.h>

#define DNS_MAX_LABEL_LEN 63
#define DNS_MAX_DOMAIN_LEN 253
#define DNS_MIN_BUFSIZE 512

/* Flags used in `dns_hdr_t` */
typedef struct {
    union {
        struct {
#if defined(__LITTLE_ENDIAN_BITFIELD)
            /* response code */
            uint16_t rcode : 4;
            /* reserved, set to 0 */
            uint16_t z : 3;
            /* recursion available */
            uint16_t ra : 1;
            /* recursion desired */
            uint16_t rd : 1;
            /* truncated */
            uint16_t tc : 1;
            /* authoritative answer */
            uint16_t aa : 1;
            /* query type */
            uint16_t opcode : 4;
            /* query/response */
            uint16_t qr : 1;
#elif defined(__BIG_ENDIAN_BITFIELD)
            /* query/response */
            uint16_t qr : 1;
            /* query type */
            uint16_t opcode : 4;
            /* authoritative answer */
            uint16_t aa : 1;
            /* truncated */
            uint16_t tc : 1;
            /* recursion desired */
            uint16_t rd : 1;
            /* recursion available */
            uint16_t ra : 1;
            /* reserved, set to 0 */
            uint16_t z : 3;
            /* response code */
            uint16_t rcode : 4;
#else
#error "Please fix <asm/byteorder.h>"
#endif
        };
        /* flags as uint16_t */
        uint16_t u16;
    };
} dns_flags_t;

/* DNS header */
typedef struct {
    /* identifier */
    uint16_t id;
    /* dns flags */
    dns_flags_t flags;
    /* number of question entries*/
    uint16_t qdcount;
    /* number of answer resource records */
    uint16_t ancount;
    /* number of name server resource records */
    uint16_t nscount;
    /* number of additional records */
    uint16_t arcount;
} __attribute__((packed)) dns_hdr_t;

typedef enum : uint16_t {
    QTYPE_A = 1,
    QTYPE_AAAA = 28
} qtype_t;

typedef enum : uint16_t {
    QCLASS_IN = 1,
} qclass_t;

typedef enum {
    RCODE_NOERROR = 0,
    RCODE_FORMERR = 1,
    RCODE_SERVFAIL = 2,
    RCODE_NXDOMAIN = 3,
    RCODE_NOTIMP = 4,
    RCODE_REFUSED = 5,
} rcode_t;

typedef enum {
    DNSERR_SUCCESS = 0,
    DNSERR_OVERFLOW = -1,
    DNSERR_LABEL_TOOLONG = -2,
    DNSERR_NAME_TOOLONG = -3,
    DNSERR_INVALID_QUERY = -4,
} dnserr_t;

/* Compose a DNS query */
ssize_t dns_compose_query(const char* domain_name, uint16_t type,
    uint16_t id, char* buf, size_t buflen);

/* Parse uncompressed DNS query */
dnserr_t dns_parse_query(const char* buf, size_t buflen, char* domain_name_buf,
    size_t domain_name_buflen, size_t* domain_len, uint16_t* type, uint16_t* id);

/* Compose empty DNS reply */
ssize_t dns_compose_reply_empty(char* query, size_t query_len, rcode_t rcode,
    char* buf, size_t buflen);

/* Get string description for dnserr_t error */
const char* dnserr_str(dnserr_t error);
