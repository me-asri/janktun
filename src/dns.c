#include "dns.h"

#include <stddef.h>
#include <string.h>

#include <sys/types.h>
#include <arpa/inet.h>

static ssize_t encode_domain(const char* domain, char* buf, size_t buflen);
static ssize_t decode_domain(const char* encoded_name, char* domain_buf,
    size_t domain_buflen, size_t* domain_len);
static ssize_t get_qd_size(const char* buf, size_t buflen);

ssize_t dns_compose_query(const char* domain, uint16_t type,
    uint16_t id, char* buf, size_t buflen)
{
    dns_hdr_t* hdr;

    char* qname;
    uint16_t* qtype;
    uint16_t* qclass;

    ssize_t qname_len;

    if (buflen < sizeof(*hdr)) {
        return DNSERR_OVERFLOW;
    }
    hdr = (dns_hdr_t*)buf;
    memset(hdr, 0, sizeof(*hdr));
    hdr->id = htons(id);
    hdr->flags.u16 = htons(((dns_flags_t) { .rd = 1 }.u16));
    hdr->qdcount = htons(1);

    qname = buf + sizeof(dns_hdr_t);
    qname_len = encode_domain(domain, qname, buflen - sizeof(*hdr));
    if (qname_len < 0) {
        return qname_len;
    }

    if (buflen < sizeof(*hdr) + qname_len + 2 /* qtype */ + 2 /* qclass*/) {
        return DNSERR_OVERFLOW;
    }
    qtype = (uint16_t*)(qname + qname_len);
    *qtype = htons(type);

    qclass = qtype + 1;
    *qclass = htons(QCLASS_IN);

    return (char*)(qclass + 1) - buf;
}

dnserr_t dns_parse_query(const char* buf, size_t buflen,
    char* domain_buf, size_t domain_buflen, size_t* domain_len,
    uint16_t* type, uint16_t* id)
{
    dns_hdr_t* hdr;
    dns_flags_t flags;

    const char* qname;
    ssize_t qname_len;

    uint16_t* qtype;
    uint16_t* qclass;

    if (buflen < sizeof(*hdr)) {
        return DNSERR_OVERFLOW;
    }
    hdr = (dns_hdr_t*)buf;
    if (id) {
        *id = ntohs(hdr->id);
    }
    if (ntohs(hdr->qdcount) != 1) {
        return DNSERR_INVALID_QUERY;
    }
    flags.u16 = ntohs(hdr->flags.u16);
    if (flags.qr || flags.opcode) {
        return DNSERR_INVALID_QUERY;
    }

    qname = buf + sizeof(*hdr);
    qname_len = decode_domain(qname, domain_buf, domain_buflen, domain_len);
    if (qname_len < 0) {
        return qname_len;
    }

    if (buflen < sizeof(*hdr) + qname_len + 2 /* qtype */ + 2 /* qclass*/) {
        return DNSERR_OVERFLOW;
    }
    qtype = (uint16_t*)(qname + qname_len);
    if (type) {
        *type = ntohs(*qtype);
    }

    qclass = qtype + 1;
    if (ntohs(*qclass) != QCLASS_IN) {
        return DNSERR_INVALID_QUERY;
    }

    return DNSERR_SUCCESS;
}

ssize_t dns_compose_reply_empty(char* query, size_t query_len, rcode_t rcode,
    char* buf, size_t buflen)
{
    dns_hdr_t* query_hdr;
    char* query_qd;
    ssize_t query_qd_size;

    dns_hdr_t* reply_hdr;
    char* reply_qd;

    if (query_len < sizeof(*query_hdr)) {
        return DNSERR_OVERFLOW;
    }
    query_hdr = (dns_hdr_t*)query;
    if (ntohs(query_hdr->qdcount) != 1) {
        return DNSERR_INVALID_QUERY;
    }
    query_qd = query + sizeof(*query_hdr);
    query_qd_size = get_qd_size(query_qd, query_len - sizeof(*query_hdr));
    if (query_qd_size < 0) {
        return query_qd_size;
    }

    if (buflen < sizeof(*reply_hdr) + query_qd_size) {
        return DNSERR_OVERFLOW;
    }
    reply_hdr = (dns_hdr_t*)buf;
    memset(reply_hdr, 0, sizeof(*reply_hdr));
    reply_hdr->id = query_hdr->id;
    reply_hdr->qdcount = query_hdr->qdcount;
    reply_hdr->flags.u16 = htons(((dns_flags_t) { .qr = 1, .aa = 1, .rcode = rcode }.u16));

    reply_qd = buf + sizeof(*reply_hdr);
    memcpy(reply_qd, query_qd, query_qd_size);

    return (reply_qd + query_qd_size) - buf;
}

/* TODO: check domain name length */
ssize_t encode_domain(const char* domain, char* buf, size_t buflen)
{
    size_t total_len = 0;
    char* label_len_ptr;

    uint8_t len;

    while (*domain) {
        /* Ensure we have room for at least the length byte and one char */
        if (total_len + 1 >= buflen) {
            return DNSERR_OVERFLOW;
        }

        label_len_ptr = buf++;
        total_len++;

        len = 0;
        while (*domain && *domain != '.') {
            if (len >= DNS_MAX_LABEL_LEN) {
                return DNSERR_LABEL_TOOLONG;
            }
            if (total_len >= buflen) {
                return DNSERR_OVERFLOW;
            }

            *buf++ = *domain++;
            len++;
            total_len++;
        }

        *label_len_ptr = len;

        if (*domain == '.') {
            domain++;
            /* Handle edge case of trailing dot or double dots */
            if (*domain == '\0') {
                break;
            }
        }
    }

    /* Add root terminator (0 length label) */
    if (total_len >= buflen) {
        return DNSERR_OVERFLOW;
    }
    *buf = 0;
    total_len++;

    return total_len;
}

ssize_t decode_domain(const char* encoded_name, char* domain_buf,
    size_t domain_buflen, size_t* domain_len)
{
    const char* enc_ptr = encoded_name;
    size_t total_written = 0;
    uint8_t label_len;

    uint8_t i;

    while (*enc_ptr != 0) {
        label_len = *enc_ptr++;

        if (label_len > DNS_MAX_LABEL_LEN) {
            return DNSERR_LABEL_TOOLONG;
        }

        /* If this isn't the first label, we need to prepend a dot */
        if (total_written > 0) {
            if (total_written + 1 >= domain_buflen) {
                return DNSERR_OVERFLOW;
            }
            *domain_buf++ = '.';
            total_written++;
        }

        /* Ensure the label itself fits in the output buffer */
        if (total_written + label_len >= domain_buflen) {
            return DNSERR_OVERFLOW;
        }

        /* Copy the label characters */
        for (i = 0; i < label_len; i++) {
            *domain_buf++ = (char)*enc_ptr++;
            total_written++;
        }
    }
    if (domain_len) {
        *domain_len = total_written;
    }

    /* Add the null terminator */
    if (total_written + 1 > domain_buflen) {
        return DNSERR_OVERFLOW;
    }
    *domain_buf = '\0';
    total_written++;

    return enc_ptr - encoded_name + 1;
}

/* TODO: check domain name length */
ssize_t get_qd_size(const char* buf, size_t buflen)
{
    const char* ptr;
    const char* end;
    uint8_t label_len;

    if (buflen < 1 /* root */ + 2 /* qtype */ + 2 /* qclass */) {
        return 0;
    }

    ptr = buf;
    end = buf + buflen;

    while (ptr < end) {
        label_len = *ptr;

        if (label_len == 0) {
            if (ptr + 1 /* \0 */ + 2 /* qtype */ + 2 /* qclass*/ <= end) {
                return (ptr + 5) - buf;
            }
            /* truncated */
            return DNSERR_INVALID_QUERY;
        }

        if (label_len > DNS_MAX_LABEL_LEN) {
            return DNSERR_LABEL_TOOLONG;
        }

        if (ptr + label_len + 1 >= end) {
            return 0;
        }
        ptr += (label_len + 1);
    }
    return DNSERR_INVALID_QUERY;
}
