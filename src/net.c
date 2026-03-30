#include "net.h"

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>

#define AI_HINT_FLAGS (AI_NUMERICSERV | AI_PASSIVE | AI_V4MAPPED | AI_ADDRCONFIG)

char* net_saddr_to_str_r(const struct sockaddr* addr, char str[NET_SADDR_MAX_STRLEN])
{
    char ip_buf[INET6_ADDRSTRLEN];
    uint16_t port;

    switch (addr->sa_family) {
    case AF_INET:
        if (!inet_ntop(AF_INET, &(((struct sockaddr_in*)addr)->sin_addr), ip_buf, INET6_ADDRSTRLEN)) {
            return NULL;
        }
        port = ntohs(((struct sockaddr_in*)addr)->sin_port);

        if (port > 0) {
            snprintf(str, NET_SADDR_MAX_STRLEN, "%s:%hu", ip_buf, port);
        } else {
            snprintf(str, NET_SADDR_MAX_STRLEN, "%s", ip_buf);
        }

        break;
    case AF_INET6:
        if (!inet_ntop(AF_INET6, &(((struct sockaddr_in6*)addr)->sin6_addr), ip_buf, INET6_ADDRSTRLEN)) {
            return NULL;
        }
        port = ntohs(((struct sockaddr_in6*)addr)->sin6_port);

        if (port > 0) {
            snprintf(str, NET_SADDR_MAX_STRLEN, "[%s]:%hu", ip_buf, port);
        } else {
            snprintf(str, NET_SADDR_MAX_STRLEN, "[%s]", ip_buf);
        }

        break;
    default:
        return NULL;
    }

    return str;
}

const char* net_saddr_to_str(const struct sockaddr* addr)
{
    static thread_local char addr_str[NET_SADDR_MAX_STRLEN];
    return net_saddr_to_str_r(addr, addr_str);
}

const char* net_sockname_to_str(int sockfd)
{
    static thread_local char addr_str[NET_SADDR_MAX_STRLEN];

    struct sockaddr_storage saddr;
    socklen_t saddrlen = sizeof(saddr);

    if (getsockname(sockfd, (struct sockaddr*)&saddr, &saddrlen) != 0) {
        return NULL;
    }
    return net_saddr_to_str_r((struct sockaddr*)&saddr, addr_str);
}

const char* net_peername_to_str(int sockfd)
{
    static thread_local char addr_str[NET_SADDR_MAX_STRLEN];

    struct sockaddr_storage saddr;
    socklen_t saddrlen = sizeof(saddr);

    if (getpeername(sockfd, (struct sockaddr*)&saddr, &saddrlen) != 0) {
        return NULL;
    }
    return net_saddr_to_str_r((struct sockaddr*)&saddr, addr_str);
}

int net_resolve_saddr(const char* host, int family,
    struct sockaddr* addr, socklen_t* addrlen, const char* default_port)
{
    char* host_dup = strdup(host);
    char *host_start, *host_end;
    const char* port_str = default_port;

    struct addrinfo hints = {
        .ai_family = family,
        .ai_socktype = 0,
        .ai_protocol = 0,
        .ai_flags = AI_HINT_FLAGS,
    };
    struct addrinfo* res = NULL;
    struct addrinfo* rp;

    int ret = 0;

    if (host_dup[0] == '[') {
        host_start = host_dup + 1;
        host_end = strchr(host_dup, ']');
        if (!host_end) {
            /* Missing host end */
            goto error_parse;
        }
        host_end[0] = '\0';

        if (host_end[1] == ':') {
            if (host_end[2] == '\0') {
                /* Missing port after : */
                goto error_parse;
            }
            port_str = &host_end[2];
        }
    } else {
        host_start = host_dup;
        host_end = strchr(host_dup, ':');
        if (host_end) {
            if (host_end[1] == '\0') {
                /* Missing port after : */
                goto error_parse;
            }
            host_end[0] = '\0';
            port_str = &host_end[1];
        }
    }
    if (*host_start == '\0') {
        host_start = NULL;
    }
    if (port_str == NULL) {
        goto error_parse;
    }

    ret = getaddrinfo(host_start, port_str, &hints, &res);
    free(host_dup);
    if (ret != 0) {
        return -1;
    }

    ret = -3;
    for (rp = res; rp != NULL; rp = rp->ai_next) {
        if (res->ai_addrlen <= *addrlen) {
            memcpy(addr, res->ai_addr, res->ai_addrlen);
            *addrlen = res->ai_addrlen;

            ret = 0;
            break;
        }
    }

    freeaddrinfo(res);
    return ret;

error_parse:
    free(host_dup);
    return -2;
}

bool net_saddr_match(const struct sockaddr* a, socklen_t a_len,
    const struct sockaddr* b, socklen_t b_len)
{
    if (a_len != b_len) {
        return false;
    }
    return (memcmp(a, b, a_len) == 0);
}
