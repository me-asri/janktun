#include "client.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>

#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/epoll.h>

#include "net.h"
#include "dns.h"
#include "log.h"
#include "sigfd.h"
#include "protocol.h"
#include "random.h"

#define DNS_SOCK_SNDBUF (1024 * 1024)
#define EPOLL_MAX_EVENTS 4
#define UDP_BUFSIZE 65535

static int handle_ds_events(jank_client_ctx_t* ctx, int fd, int events);
static int handle_inbound_events(jank_client_ctx_t* ctx, int fd, int events);
static int send_data_as_dns(jank_client_ctx_t* ctx, char* buf, size_t buflen);
static bool on_fragment(metadata_t* metadata, char* domain, void* userdata);

int jank_client_init(jank_client_ctx_t* ctx,
    const char* domain, size_t max_domain_len, const char** resolvers,
    const char* inbound_listen_addr, const char* ds_listen_addr,
    const char* ds_src_addr)
{
    struct sockaddr_storage saddr;
    socklen_t saddrlen;
    int optval;
    socklen_t optlen;
    struct epoll_event ev;

    if (max_domain_len > DNS_MAX_DOMAIN_LEN) {
        log_e("Max domain length may not exceed %d", DNS_MAX_DOMAIN_LEN);
        return -1;
    }
    ctx->max_domain_len = max_domain_len;

    ctx->domain_len = strlen(domain);
    if (ctx->domain_len > ctx->max_domain_len) {
        log_e("Domain length may not exceed %d", ctx->max_domain_len);
        return -1;
    }
    if (ctx->max_domain_len - ctx->domain_len <= PROTO_DOMAIN_LEN_OVERHEAD) {
        log_e("Domain length too short");
        return -1;
    }

    strcpy(ctx->domain, domain);

    ctx->last_ds_addrlen = 0;
    ctx->last_inbound_addrlen = 0;

    ctx->resolver_count = 0;
    ctx->resolver_index = 0;
    while (*resolvers) {
        ctx->resolver_addrlens[ctx->resolver_count] = sizeof(ctx->resolver_addrs[0]);
        if (net_resolve_saddr(*resolvers, AF_INET6 /* DNS socket is IPv6-only */,
                (struct sockaddr*)&ctx->resolver_addrs[ctx->resolver_count],
                &ctx->resolver_addrlens[ctx->resolver_count], "53")
            != 0) {
            log_w("Failed to resolve DNS resolver '%s'", *resolvers);
        } else {
            ctx->resolver_count++;
        }
        resolvers++;
    }
    if (ctx->resolver_count == 0) {
        log_e("No resolvers supplied");
        return -1;
    }

    ctx->epollfd = epoll_create1(0);
    if (ctx->epollfd < 0) {
        elog_e("Failed to create epoll instance");
        return -1;
    }

    ctx->dns_sockfd = socket(AF_INET6, SOCK_DGRAM | SOCK_NONBLOCK, 0);
    if (ctx->dns_sockfd < 0) {
        elog_e("Failed to create DNS socket");
        goto err_close_epollfd;
    }
    optval = 0;
    if (setsockopt(ctx->dns_sockfd, SOL_IPV6, IPV6_V6ONLY,
            &optval, sizeof(optval))
        != 0) {
        elog_e("Failed to disable V6 only on DNS socket");
        goto err_close_dns;
    }
    optval = DNS_SOCK_SNDBUF;
    if (setsockopt(ctx->dns_sockfd, SOL_SOCKET, SO_SNDBUF,
            &optval, sizeof(optval))
        != 0) {
        elog_w("Failed to increase send buffer for DNS socket");
    }
    optlen = sizeof(optval);
    if (getsockopt(ctx->dns_sockfd, SOL_SOCKET, SO_SNDBUF, &optval, &optlen) == 0) {
        log_d("DNS socket send buffer size: %d", optval);
    }
    memset(&saddr, 0, sizeof(saddr));
    saddr.ss_family = AF_INET6;
    if (bind(ctx->dns_sockfd, (struct sockaddr*)&saddr, sizeof(saddr)) != 0) {
        elog_e("Failed to bind DNS socket");
        goto err_close_dns;
    }

    saddrlen = sizeof(saddr);
    if (net_resolve_saddr(ds_listen_addr, AF_UNSPEC,
            (struct sockaddr*)&saddr, &saddrlen, NULL)
        != 0) {
        log_e("Failed to resolve downstream listen address '%s'", ds_listen_addr);
        goto err_close_dns;
    }
    ctx->ds_sockfd = socket(saddr.ss_family, SOCK_DGRAM | SOCK_NONBLOCK, 0);
    if (ctx->ds_sockfd < 0) {
        elog_e("Failed to create downstream socket");
        goto err_close_dns;
    }
    if (saddr.ss_family == AF_INET6) {
        optval = 0;
        if (setsockopt(ctx->ds_sockfd, SOL_IPV6, IPV6_V6ONLY,
                &optval, sizeof(optval))
            != 0) {
            elog_w("Failed to disable V6-only on downstream socket");
        }
    }
    if (bind(ctx->ds_sockfd, (struct sockaddr*)&saddr, saddrlen) != 0) {
        elog_e("Failed to bind downstream socket");
        goto err_close_ds;
    }
    if (ds_src_addr) {
        saddrlen = sizeof(saddr);
        if (net_resolve_saddr(ds_src_addr, AF_UNSPEC,
                (struct sockaddr*)&saddr, &saddrlen, NULL)
            != 0) {
            log_e("Failed to resolve downstream source address '%s'", ds_src_addr);
            goto err_close_ds;
        }
        if (connect(ctx->ds_sockfd, (struct sockaddr*)&saddr, saddrlen) != 0) {
            elog_e("Failed to connect downstream socket");
            goto err_close_ds;
        };
    }
    ev.data.fd = ctx->ds_sockfd;
    ev.events = EPOLLIN;
    if (epoll_ctl(ctx->epollfd, EPOLL_CTL_ADD, ctx->ds_sockfd, &ev) != 0) {
        elog_e("Failed to add downstream socket to epoll instance");
        goto err_close_ds;
    }

    saddrlen = sizeof(saddr);
    if (net_resolve_saddr(inbound_listen_addr, AF_UNSPEC,
            (struct sockaddr*)&saddr, &saddrlen, NULL)
        != 0) {
        log_e("Failed to resolve inbound listen address '%s'", ds_src_addr);
        goto err_close_ds;
    }
    ctx->inbound_sockfd = socket(saddr.ss_family, SOCK_DGRAM | SOCK_NONBLOCK, 0);
    if (ctx->inbound_sockfd < 0) {
        elog_e("Failed to create inbound socket");
        goto err_close_ds;
    }
    if (saddr.ss_family == AF_INET6) {
        optval = 0;
        if (setsockopt(ctx->inbound_sockfd, SOL_IPV6, IPV6_V6ONLY,
                &optval, sizeof(optval))
            != 0) {
            elog_w("Failed to disable V6-only on inbound socket");
        }
    }
    if (bind(ctx->inbound_sockfd, (struct sockaddr*)&saddr, saddrlen) != 0) {
        elog_e("Failed to bind inbound socket");
        goto err_close_inbound;
    }
    ev.data.fd = ctx->inbound_sockfd;
    ev.events = EPOLLIN;
    if (epoll_ctl(ctx->epollfd, EPOLL_CTL_ADD, ctx->inbound_sockfd, &ev) != 0) {
        elog_e("Failed to add inbound socket to epoll instance");
        goto err_close_inbound;
    }

    return 0;

err_close_inbound:
    close(ctx->inbound_sockfd);
err_close_ds:
    close(ctx->ds_sockfd);
err_close_dns:
    close(ctx->dns_sockfd);
err_close_epollfd:
    close(ctx->epollfd);

    return -1;
}

int jank_client_run(jank_client_ctx_t* ctx)
{
    uint32_t signo;
    int sigfd;

    struct epoll_event events[EPOLL_MAX_EVENTS];
    int ret;

    size_t i;

    log_i("Domain: %s - Max length: %zu", ctx->domain, ctx->max_domain_len);
    log_i("Downstream socket listening on %s",
        net_sockname_to_str(ctx->ds_sockfd));
    log_i("Inbound socket listening on %s",
        net_sockname_to_str(ctx->inbound_sockfd));
    log_i("Available resolvers:");
    for (i = 0; i < ctx->resolver_count; i++) {
        log_i("- %s", net_saddr_to_str((struct sockaddr*)&ctx->resolver_addrs[i]));
    }

    sigfd = sigfd_create(2, SIGINT, SIGTERM);
    if (sigfd < 0) {
        return -1;
    }
    events[0].data.fd = sigfd;
    events[0].events = EPOLLIN;
    if (epoll_ctl(ctx->epollfd, EPOLL_CTL_ADD, sigfd, &events[0]) != 0) {
        elog_e("Failed to add signalfd to epoll instance");
        goto err_close_sigfd;
    }

    for (;;) {
        ret = epoll_wait(ctx->epollfd, events, EPOLL_MAX_EVENTS, -1);
        if (ret < 0) {
            if (errno == EINTR) {
                continue;
            }
            elog_e("epoll_wait failed");
            goto err_close_sigfd;
        }

        for (i = 0; i < ret; i++) {
            if (events[i].data.fd == ctx->ds_sockfd) {
                if (handle_ds_events(ctx, events[i].data.fd, events[i].events) < 0) {
                    log_e("Failed to handle downstream events");
                    goto err_close_sigfd;
                }
            } else if (events[i].data.fd == ctx->inbound_sockfd) {
                if (handle_inbound_events(ctx, events[i].data.fd, events[i].events) < 0) {
                    log_e("Failed to handle inbound events");
                    goto err_close_sigfd;
                }
            } else if (events[i].data.fd == sigfd) {
                if (sigfd_read(events[i].data.fd, &signo) <= 0) {
                    elog_e("Failed to read signals");
                    goto err_close_sigfd;
                }
                log_i("Received SIG%s, stopping...", sigfd_sig_name(signo));
                goto stop;
            }
        }
    }

stop:
    sigfd_close(sigfd);
    return 0;

err_close_sigfd:
    sigfd_close(sigfd);
    return -1;
}

int jank_client_destroy(jank_client_ctx_t* ctx)
{
    int ret = 0;

    if (close(ctx->inbound_sockfd) != 0) {
        elog_w("Failed to close inbound socket");
        ret = 1;
    }
    if (close(ctx->ds_sockfd) != 0) {
        elog_w("Failed to close downstream socket");
        ret = 1;
    }
    if (close(ctx->dns_sockfd) != 0) {
        elog_w("Failed to close DNS socket");
        ret = 1;
    }
    if (close(ctx->epollfd) != 0) {
        elog_w("Failed to close epoll instance");
        ret = 1;
    }

    return ret;
}

int handle_ds_events(jank_client_ctx_t* ctx, int fd, int events)
{
    int error = 0;
    socklen_t errorlen = sizeof(error);

    char buf[UDP_BUFSIZE];
    struct sockaddr_storage saddr;
    socklen_t saddrlen;
    ssize_t recvd;
    ssize_t sent;

    if (events & EPOLLERR) {
        if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &errorlen) != 0) {
            elog_w("Failed to read error on downstream socket");
        } else {
            errno = error;
            elog_w("Destination socket error");
        }
    }
    if (events & EPOLLIN) {
    retry_recv:
        saddrlen = sizeof(saddr);
        recvd = recvfrom(fd, buf, sizeof(buf), 0, (struct sockaddr*)&saddr, &saddrlen);
        if (recvd < 0) {
            if (errno == EINTR) {
                goto retry_recv;
            }
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                return 0;
            }
            elog_e("Failed to receive datagram on downstream socket");
            return -1;
        }
        log_t("Received datagram of size %zd from upstream", recvd);

        if (!net_saddr_match((struct sockaddr*)&saddr, saddrlen,
                (struct sockaddr*)&ctx->last_ds_addr, ctx->last_ds_addrlen)) {
            log_i("Upstream connected from %s", net_saddr_to_str((struct sockaddr*)&saddr));
            memcpy(&ctx->last_ds_addr, &saddr, saddrlen);
            ctx->last_ds_addrlen = saddrlen;
        }

        if (ctx->last_inbound_addrlen == 0) {
            log_w("Inbound not connected, dropping datagram from upstream");
            return 1;
        }
    retry_send:
        sent = sendto(ctx->inbound_sockfd, buf, recvd, 0,
            (struct sockaddr*)&ctx->last_inbound_addr, ctx->last_inbound_addrlen);
        if (sent < 0) {
            if (errno == EINTR) {
                goto retry_send;
            }
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                log_d("Inbound socket send buffer full, dropping datagram");
                return 0;
            }
            elog_e("Failed to send datagram to inbound");
            return 1;
        }
        log_t("Sent datagram of size %zd to inbound", sent);
    }
    return 0;
}

int handle_inbound_events(jank_client_ctx_t* ctx, int fd, int events)
{
    int error = 0;
    socklen_t errorlen = sizeof(error);

    char buf[PROTO_MAX_DATAGRAM];
    struct sockaddr_storage saddr;
    socklen_t saddrlen;
    ssize_t recvd;

    if (events & EPOLLERR) {
        if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &errorlen) != 0) {
            elog_w("Failed to read error on destination socket");
        } else {
            errno = error;
            elog_w("Destination socket error");
        }
    }
    if (events & EPOLLIN) {
    retry_recv:
        saddrlen = sizeof(saddr);
        recvd = recvfrom(fd, buf, sizeof(buf), 0, (struct sockaddr*)&saddr, &saddrlen);
        if (recvd < 0) {
            if (errno == EINTR) {
                goto retry_recv;
            }
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                return 0;
            }
            elog_e("Failed to receive datagram on inbound socket");
            return -1;
        }
        log_t("Received datagram of size %zd from inbound client", recvd);

        if (!net_saddr_match((struct sockaddr*)&saddr, saddrlen,
                (struct sockaddr*)&ctx->last_inbound_addr, ctx->last_inbound_addrlen)) {
            log_i("Inbound connected from %s", net_saddr_to_str((struct sockaddr*)&saddr));
            memcpy(&ctx->last_inbound_addr, &saddr, saddrlen);
            ctx->last_inbound_addrlen = saddrlen;
        }

        if (send_data_as_dns(ctx, buf, recvd) != 0) {
            return -1;
        }
    }

    return 0;
}

int send_data_as_dns(jank_client_ctx_t* ctx, char* buf, size_t buflen)
{
    protoerr_t ret;

    ret = protocol_encode_domain(ctx->domain, ctx->domain_len, ctx->max_domain_len,
        buf, buflen, on_fragment, ctx);
    if (ret != PROTOERR_SUCCESS) {
        if (ret != PROTOERR_INTER) {
            log_e("Failed to encode data as DNS query");
        }
        return -1;
    }
    return 0;
}

bool on_fragment(metadata_t* metadata, char* domain, void* userdata)
{
    jank_client_ctx_t* ctx = userdata;

    ssize_t recvd;
    ssize_t sent;
    char buf[DNS_MIN_BUFSIZE];
    size_t ridx;

    log_t("S%u - F#%u => '%s'", metadata->session_id, metadata->frag_idx, domain);
    recvd = dns_compose_query(domain, random_bool() ? QTYPE_A : QTYPE_AAAA,
        random_u16(), buf, sizeof(buf));
    if (recvd < 0) {
        log_e("Failed to compose DNS query: %zd", recvd);
        return false;
    }

    ridx = (ctx->resolver_index++) % ctx->resolver_count;
retry_send:
    sent = sendto(ctx->dns_sockfd, buf, recvd, 0,
        (struct sockaddr*)&ctx->resolver_addrs[ridx], ctx->resolver_addrlens[ridx]);
    if (sent < 0) {
        if (errno == EINTR) {
            goto retry_send;
        }
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            log_e("DNS socket send buffer, query dropped");
            return false;
        }
        elog_e("Failed to send DNS query");
        return false;
    }
    log_t("Sent DNS query of size %zd to %s", sent,
        net_saddr_to_str((struct sockaddr*)&ctx->resolver_addrs[ridx]));

    return true;
}
