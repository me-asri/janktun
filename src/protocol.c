#include "protocol.h"

#include <stdlib.h>
#include <string.h>
#include <stddef.h>
#include <stdbool.h>
#include <threads.h>

#include <arpa/inet.h>

#include "dns.h"
#include "random.h"
#include "bits.h"
#include "log.h"

#define MIN(a, b) ((a) < (b) ? (a) : (b))

static const char BASE32_ALPHABET[] = "abcdefghijklmnopqrstuvwxyz234567";

static const char* PROTOERR_STR[] = {
    [-PROTOERR_SUCCESS] = "Success",
    [-PROTOERR_OVERFLOW] = "Data exceeds limit",
    [-PROTOERR_INVALID] = "Malformed data",
    [-PROTOERR_INTER] = "Process interrupted",
    [-PROTOERR_DUP] = "Duplicate entry",
    [-PROTOERR_INCOMPLETE] = "Partial data"
};

static thread_local uint32_t base_session_id = 0;

static ssize_t base32_decode(const char* input, char* buf, size_t buflen);
static ssize_t base32_delim_encode(const char* buf, size_t buflen, char* out,
    size_t outlen, char delim, size_t n_delim);

ssize_t protocol_decode_domain(char* domain, size_t domain_len,
    const char* base_domain, size_t base_domain_len,
    metadata_t* metadata, char* buf, size_t buflen)
{
    char* delim;

    ssize_t ret;

    /* Remove base from domain */
    domain[domain_len - base_domain_len - 1] = '\0';

    /* First segment contains the metadata */
    delim = strchr(domain, '.');
    if (!delim) {
        return PROTOERR_INVALID;
    }
    *delim = '\0';
    ret = base32_decode(domain, (char*)metadata, sizeof(*metadata));
    if (ret < 0) {
        return ret;
    } else if (ret != sizeof(*metadata)) {
        return PROTOERR_INVALID;
    }
    metadata->u32 = ntohl(metadata->u32);

    /* The rest are payload */
    return base32_decode(delim + 1, buf, buflen);
}

protoerr_t protocol_encode_domain(
    const char* base_domain, size_t base_domain_len, size_t max_domain_len,
    const char* buf, size_t buflen,
    proto_domain_cb_t callback, void* userdata)
{
    if (base_session_id == 0) {
        base_session_id = random_u32();
    }

    metadata_t md = {
        .session_id = (base_session_id++) & 0x01FFFFFF,
    };

    size_t remaining;
    size_t label_len;
    size_t payload_chars;

    size_t chunk_size;
    size_t frag_count;

    const char* payload_ptr;
    size_t payload_len;

    char domain[DNS_MAX_DOMAIN_LEN + 1];
    size_t index;
    ssize_t ret;

    size_t i;

    if (max_domain_len > DNS_MAX_DOMAIN_LEN) {
        return PROTOERR_OVERFLOW;
    }

    if (base_domain_len + PROTO_DOMAIN_LEN_OVERHEAD >= max_domain_len) {
        return PROTOERR_OVERFLOW;
    }

    remaining = max_domain_len - base_domain_len - PROTO_DOMAIN_LEN_OVERHEAD;
    payload_chars = 0;
    while (remaining > 0) {
        label_len = MIN(DNS_MAX_LABEL_LEN, remaining);
        payload_chars += label_len;
        remaining -= label_len;

        if (remaining > 1) {
            remaining--;
        } else {
            break;
        }
    }
    if (payload_chars == 0) {
        return PROTOERR_OVERFLOW;
    }

    chunk_size = (payload_chars * 5) / 8;
    if (chunk_size == 0) {
        return PROTOERR_OVERFLOW;
    }
    frag_count = (buflen > 0) ? (buflen + chunk_size - 1) / chunk_size : 1;
    if (frag_count > PROTO_FRAG_MAX) {
        return PROTOERR_OVERFLOW;
    }

    for (i = 0; i < frag_count; i++) {
        md.frag_idx = i;
        md.last_frag = (i == frag_count - 1);

        payload_ptr = buf + i * chunk_size;
        remaining = buflen - i * chunk_size;
        payload_len = (remaining < chunk_size) ? remaining : chunk_size;

        /* first segment is base32-encoded metadata */
        ret = base32_delim_encode((char*)&(metadata_t) { .u32 = htonl(md.u32) },
            sizeof(md), domain, sizeof(domain), '\0', 0);
        if (ret < 0) {
            return ret;
        }

        index = ret;
        domain[index++] = '.';
        /* rest are base32-encoded data */
        ret = base32_delim_encode(payload_ptr, payload_len, domain + index, sizeof(domain) - index,
            '.', DNS_MAX_LABEL_LEN);
        if (ret < 0) {
            return ret;
        }
        index += ret;
        domain[index++] = '.';
        /* finally the base domain */
        memcpy(domain + index, base_domain, base_domain_len);
        domain[index + base_domain_len] = '\0';

        if (!callback(&md, domain, userdata)) {
            return PROTOERR_INTER;
        }
    }

    return PROTOERR_SUCCESS;
}

ssize_t base32_decode(const char* input, char* buf, size_t buflen)
{
    uint8_t val;

    size_t index = 0;
    uint32_t buffer = 0;
    int bits_left = 0;

    size_t i;

    for (i = 0; input[i]; i++) {
        if (input[i] >= 'A' && input[i] <= 'Z') {
            val = input[i] - 'A';
        } else if (input[i] >= 'a' && input[i] <= 'z') {
            val = input[i] - 'a';
        } else if (input[i] >= '2' && input[i] <= '7') {
            val = input[i] - '2' + 26;
        } else {
            /* skip invalid characters */
            continue;
        }

        buffer = (buffer << 5) | val;
        bits_left += 5;
        if (bits_left >= 8) {
            if (index == buflen) {
                return PROTOERR_OVERFLOW;
            }
            buf[index++] = (char)((buffer >> (bits_left - 8)) & 0xFF);
            bits_left -= 8;
        }
    }
    return index;
}

ssize_t base32_delim_encode(const char* buf, size_t buflen, char* out,
    size_t outlen, char delim, size_t n_delim)
{
    uint32_t buffer = 0;
    size_t index = 0;
    int bits_left = 0;

    size_t i;

    for (i = 0; i < buflen; i++) {
        buffer = (buffer << 8) | (uint8_t)buf[i];
        bits_left += 8;

        while (bits_left >= 5) {
            if (index == outlen) {
                return PROTOERR_OVERFLOW;
            }
            /* insert delimiter if necessary */
            if (n_delim > 0 && (index + 1) % n_delim == 0) {
                if (index + 1 == outlen) {
                    return PROTOERR_OVERFLOW;
                }
                out[index++] = delim;
            }

            out[index++] = BASE32_ALPHABET[(buffer >> (bits_left - 5)) & 0x1F];
            bits_left -= 5;
        }
    }
    /* last partial chunk */
    if (bits_left > 0) {
        if (index == outlen) {
            return PROTOERR_OVERFLOW;
        }
        if (n_delim > 0 && (index + 1) % n_delim == 0) {
            if (index + 1 == outlen) {
                return PROTOERR_OVERFLOW;
            }
            out[index++] = delim;
        }

        out[index++] = BASE32_ALPHABET[(buffer << (5 - bits_left)) & 0x1F];
    }

    /* null-terminate */
    if (index == outlen) {
        return PROTOERR_OVERFLOW;
    }
    out[index] = '\0';

    return index;
}

void frag_assembler_init(frag_assembler_t* assembler)
{
    BITSET64_ZERO_INIT(assembler->received_frags);
    assembler->max_frag_size = 0;
    assembler->max_frag_count = 0;
    assembler->last_frag_size = 0;
}

protoerr_t frag_assembler_add(frag_assembler_t* assembler,
    uint8_t frag_idx, bool last_frag, char* buf, size_t buflen)
{
    char* dest;

    if (frag_idx > PROTO_FRAG_MAX || buflen > PROTO_FRAG_LEN_MAX) {
        return PROTOERR_OVERFLOW;
    }
    if (buflen == 0) {
        return PROTOERR_INVALID;
    }
    if (BITSET64_TEST_BIT(assembler->received_frags, frag_idx)) {
        return PROTOERR_DUP;
    }

    if (last_frag == true) {
        if (assembler->last_frag_size != 0) {
            /* duplicate last frag at different position */
            return PROTOERR_INVALID;
        }

        if (assembler->max_frag_size == 0 && frag_idx != 0) {
            /* we don't know the max frag size yet and its not the only fragment,
               so park it at the end for now */
            dest = assembler->buf + (sizeof(assembler->buf) - buflen);
        } else {
            dest = assembler->buf + frag_idx * assembler->max_frag_size;
        }

        memcpy(dest, buf, buflen);
        assembler->max_frag_count = frag_idx + 1;
        assembler->last_frag_size = buflen;
    } else {
        if (assembler->max_frag_size != 0) {
            /* not the first intermediate frag, check size */
            if (buflen != assembler->max_frag_size) {
                /* the intermediate frag has mismatching size */
                return PROTOERR_INVALID;
            }
        } else {
            /* first intermediate frag defines max size */
            assembler->max_frag_size = buflen;

            /* rearrange previously parked last frag if available */
            if (assembler->max_frag_count != 0) {
                memmove(assembler->buf + (assembler->max_frag_count - 1) * assembler->max_frag_size,
                    assembler->buf + (sizeof(assembler->buf) - assembler->last_frag_size),
                    assembler->last_frag_size);
            }
        }

        dest = assembler->buf + frag_idx * assembler->max_frag_size;
        memcpy(dest, buf, buflen);
    }
    BITSET64_SET_BIT(assembler->received_frags, frag_idx);

    return PROTOERR_SUCCESS;
}

protoerr_t frag_assembler_assemble(frag_assembler_t* assembler, char** buf, size_t* buflen)
{
    if (assembler->max_frag_count == 0
        || assembler->last_frag_size == 0
        || !BITSET64_TEST_SEQ(assembler->received_frags, 0, assembler->max_frag_count)) {
        return PROTOERR_INCOMPLETE;
    }

    *buf = assembler->buf;
    *buflen = ((assembler->max_frag_count - 1) * assembler->max_frag_size)
        + assembler->last_frag_size;
    return PROTOERR_SUCCESS;
}

const char* protoerr_str(protoerr_t error)
{
    int index = -error;
    if (index < 0 || index > sizeof(PROTOERR_STR) / sizeof(PROTOERR_STR[0])) {
        return NULL;
    }
    return PROTOERR_STR[index];
}
