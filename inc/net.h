#pragma once

#include <netinet/in.h>

#ifndef INET6_ADDRSTRLEN
#define INET6_ADDRSTRLEN 46
#endif

/* INET6_ADDRSTRLEN + len(port) + '[' + ']' + ':' */
#define NET_SADDR_MAX_STRLEN 54

/* Convert IPv4/IPv6 socket address to text format in the user-supplied buffer */
char* net_saddr_to_str_r(const struct sockaddr* addr, char str[NET_SADDR_MAX_STRLEN]);

/* Convert IPv4/IPv6 socket address to text format */
const char* net_saddr_to_str(const struct sockaddr* addr);

/* Convert socket sockname to text format */
const char* net_sockname_to_str(int sockfd);

/* Convert socket peername to text format */
const char* net_peername_to_str(int sockfd);

/* Resolve IPv4/IPv6 socket address from given text */
int net_resolve_saddr(const char* host, int family,
    struct sockaddr* addr, socklen_t* addrlen, const char* default_port);

/* Check whether two socket addresses match */
bool net_saddr_match(const struct sockaddr* a, socklen_t a_len,
    const struct sockaddr* b, socklen_t b_len);
