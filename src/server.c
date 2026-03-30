#include "server.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/epoll.h>

#include "net.h"
#include "log.h"
#include "sigfd.h"
#include "dns.h"
#include "protocol.h"
#include "bits.h"
#include "timestamp.h"
#include "timer.h"

#define EPOLL_MAX_EVENTS 4

#define EXPIRY_TIMER_INTERVAL 1000
#define ASM_SESSION_EXPIRY 10000
#define SESSION_HIST_EXPIRY 15000

static int handle_dns_events(jank_server_ctx_t* ctx, int fd, int events);
static int handle_dest_events(jank_server_ctx_t* ctx, int fd, int events);
static bool handle_dns_query(jank_server_ctx_t* ctx, char* domain, size_t domain_len);
static void handle_expiry(jank_server_ctx_t* ctx);

static ssize_t asm_session_find(jank_server_ctx_t* ctx, uint32_t session_id, asm_session_t** session);
static ssize_t asm_session_alloc(jank_server_ctx_t* ctx, uint32_t session_id, asm_session_t** session);
static void asm_session_evict(jank_server_ctx_t* ctx, size_t index);
static ssize_t asm_session_realloc_oldest(jank_server_ctx_t* ctx, uint32_t session_id, asm_session_t** session);

static void session_hist_push(jank_server_ctx_t* ctx, uint32_t session_id, uint64_t timestamp);
static void session_hist_pop(jank_server_ctx_t* ctx);
static session_hist_entry_t* session_hist_peek(jank_server_ctx_t* ctx);
static session_hist_entry_t* session_hist_find(jank_server_ctx_t* ctx, uint32_t session_id);

int jank_server_init(jank_server_ctx_t* ctx, const char* domain,
    const char* dns_listen_addr, const char* ds_addr,
    const char* ds_src_addr, const char* dest_addr)
{
    struct sockaddr_storage saddr;
    socklen_t saddrlen;
    int optval;
    struct epoll_event ev;

    size_t i;

    ctx->domain_len = strlen(domain);
    if (ctx->domain_len > DNS_MAX_DOMAIN_LEN) {
        log_e("Domain length may not exceed %d", DNS_MAX_DOMAIN_LEN);
        return -1;
    }
    if (DNS_MAX_DOMAIN_LEN - ctx->domain_len <= PROTO_DOMAIN_LEN_OVERHEAD) {
        log_e("Domain length too short");
        return -1;
    }
    strcpy(ctx->domain, domain);

    BITSET512_ZERO_INIT(ctx->active_asm_sessions);
    ctx->session_hist.head = 0;
    ctx->session_hist.tail = 0;
    ctx->session_hist.count = 0;

    memset(ctx->udp_msgs, 0, sizeof(ctx->udp_msgs));
    for (i = 0; i < SERVER_UDP_VLEN; i++) {
        ctx->udp_iovs[i].iov_base = ctx->udp_bufs[i];
        ctx->udp_iovs[i].iov_len = SERVER_UDP_BUFSIZE;
        ctx->udp_msgs[i].msg_hdr.msg_iov = &ctx->udp_iovs[i];
        ctx->udp_msgs[i].msg_hdr.msg_iovlen = 1;
    }

    ctx->epollfd = epoll_create1(0);
    if (ctx->epollfd < 0) {
        elog_e("Failed to create epoll instance");
        return -1;
    }

    saddrlen = sizeof(saddr);
    if (net_resolve_saddr(dns_listen_addr, AF_UNSPEC, (struct sockaddr*)&saddr, &saddrlen, "53") != 0) {
        log_e("Failed to resolve DNS listen address '%s'", dns_listen_addr);
        goto err_close_epoll;
    }
    ctx->dns_sockfd = socket(saddr.ss_family, SOCK_DGRAM | SOCK_NONBLOCK, 0);
    if (ctx->dns_sockfd < 0) {
        elog_e("Failed to create DNS socket");
        goto err_close_epoll;
    }
    if (saddr.ss_family == AF_INET6) {
        optval = 0;
        if (setsockopt(ctx->dns_sockfd, SOL_IPV6, IPV6_V6ONLY, &optval, sizeof(optval)) != 0) {
            elog_w("Failed to disable V6 only on DNS socket");
        }
    }
    if (bind(ctx->dns_sockfd, (struct sockaddr*)&saddr, saddrlen) != 0) {
        elog_e("Failed to bind DNS socket");
        goto err_close_dns;
    }
    ev.data.fd = ctx->dns_sockfd;
    ev.events = EPOLLIN;
    if (epoll_ctl(ctx->epollfd, EPOLL_CTL_ADD, ctx->dns_sockfd, &ev) != 0) {
        elog_e("Failed to add DNS socket to epoll instance");
        goto err_close_dns;
    }

    saddrlen = sizeof(saddr);
    if (net_resolve_saddr(dest_addr, AF_UNSPEC, (struct sockaddr*)&saddr, &saddrlen, NULL) != 0) {
        log_e("Failed to resolve destination address '%s'", dest_addr);
        return -1;
    }
    ctx->dest_sockfd = socket(saddr.ss_family, SOCK_DGRAM | SOCK_NONBLOCK, 0);
    if (ctx->dest_sockfd < 0) {
        elog_e("Failed to create destination socket");
        goto err_close_dns;
    }
    if (connect(ctx->dest_sockfd, (struct sockaddr*)&saddr, saddrlen) != 0) {
        elog_e("Failed to connect destination socket");
        goto err_close_dest;
    }
    ev.data.fd = ctx->dest_sockfd;
    ev.events = EPOLLIN;
    if (epoll_ctl(ctx->epollfd, EPOLL_CTL_ADD, ctx->dest_sockfd, &ev) != 0) {
        elog_e("Failed to add dest socket to epoll instance");
        goto err_close_dest;
    }

    if (ds_src_addr) {
        saddrlen = sizeof(saddr);
        if (net_resolve_saddr(ds_src_addr, AF_UNSPEC, (struct sockaddr*)&saddr, &saddrlen, "0") != 0) {
            log_e("Failed to resolve downstream source address '%s'", dns_listen_addr);
            goto err_close_dest;
        }
        ctx->ds_sockfd = socket(saddr.ss_family, SOCK_DGRAM | SOCK_NONBLOCK, 0);
        if (ctx->ds_sockfd < 0) {
            elog_e("Failed to create downstream socket");
            goto err_close_dest;
        }
        optval = 1;
        if (setsockopt(ctx->ds_sockfd, SOL_IP, IP_TRANSPARENT, &optval, sizeof(optval)) != 0) {
            elog_e("Failed to enable IP_TRANSPARENT on downstream socket");
            goto err_close_ds;
        }
        if (bind(ctx->ds_sockfd, (struct sockaddr*)&saddr, saddrlen) != 0) {
            elog_e("Failed to bind downstream socket");
            goto err_close_ds;
        }
        saddrlen = sizeof(saddr);
        if (net_resolve_saddr(ds_addr, AF_UNSPEC, (struct sockaddr*)&saddr, &saddrlen, NULL) != 0) {
            log_e("Failed to resolve downstream address '%s'", ds_addr);
            goto err_close_dest;
        }
        if (connect(ctx->ds_sockfd, (struct sockaddr*)&saddr, saddrlen) != 0) {
            elog_e("Failed to connect downstream socket");
            goto err_close_ds;
        }
    } else {
        saddrlen = sizeof(saddr);
        if (net_resolve_saddr(ds_addr, AF_UNSPEC, (struct sockaddr*)&saddr, &saddrlen, NULL) != 0) {
            log_e("Failed to resolve downstream address '%s'", ds_addr);
            goto err_close_dest;
        }
        ctx->ds_sockfd = socket(saddr.ss_family, SOCK_DGRAM | SOCK_NONBLOCK, 0);
        if (ctx->ds_sockfd < 0) {
            elog_e("Failed to create downstream socket");
            goto err_close_dest;
        }
        if (connect(ctx->ds_sockfd, (struct sockaddr*)&saddr, saddrlen) != 0) {
            elog_e("Failed to connect downstream socket");
            goto err_close_ds;
        }
    }

    return 0;

err_close_ds:
    close(ctx->ds_sockfd);
err_close_dest:
    close(ctx->dest_sockfd);
err_close_dns:
    close(ctx->dns_sockfd);
err_close_epoll:
    close(ctx->epollfd);

    return -1;
}

int jank_server_run(jank_server_ctx_t* ctx)
{
    int sigfd;
    uint32_t signo;

    int timerfd;

    struct epoll_event events[EPOLL_MAX_EVENTS];
    int ret, i;

    log_i("Domain: %s", ctx->domain);
    log_i("DNS listening on %s", net_sockname_to_str(ctx->dns_sockfd));
    log_i("Downstream at %s - Source: %s", net_peername_to_str(ctx->ds_sockfd),
        net_sockname_to_str(ctx->ds_sockfd));
    log_i("Destination at %s", net_peername_to_str(ctx->dest_sockfd));

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

    timerfd = timerfd_open(EXPIRY_TIMER_INTERVAL, true);
    if (timerfd < 0) {
        goto err_close_sigfd;
    }
    events[0].data.fd = timerfd;
    events[0].events = EPOLLIN;
    if (epoll_ctl(ctx->epollfd, EPOLL_CTL_ADD, timerfd, &events[0]) != 0) {
        elog_e("Failed to add timerfd to epoll instance");
        goto err_close_timer;
    }

    for (;;) {
        ret = epoll_wait(ctx->epollfd, events, EPOLL_MAX_EVENTS, -1);
        if (ret < 0) {
            if (errno == EINTR) {
                continue;
            }
            elog_e("epoll_wait failed");
            goto err_close_timer;
        }

        for (i = 0; i < ret; i++) {
            if (events[i].data.fd == ctx->dns_sockfd) {
                if (handle_dns_events(ctx, events[i].data.fd, events[i].events) < 0) {
                    log_e("Failed to handle DNS socket events");
                    goto err_close_timer;
                }
            } else if (events[i].data.fd == ctx->dest_sockfd) {
                if (handle_dest_events(ctx, events[i].data.fd, events[i].events) < 0) {
                    log_e("Failed to handle destination socket events");
                    goto err_close_timer;
                }
            } else if (events[i].data.fd == timerfd) {
                if (timerfd_get_expire(timerfd, NULL) != 0) {
                    log_e("Failed to read expirations from timer");
                    goto err_close_timer;
                }

                handle_expiry(ctx);
            } else if (events[i].data.fd == sigfd) {
                if (sigfd_read(events[i].data.fd, &signo) <= 0) {
                    elog_e("Failed to read signals");
                    goto err_close_timer;
                }
                log_i("Received SIG%s, stopping...", sigfd_sig_name(signo));
                goto stop;
            }
        }
    }

stop:
    sigfd_close(sigfd);
    return 0;

err_close_timer:
    close(timerfd);
err_close_sigfd:
    sigfd_close(sigfd);
    return -1;
}

int jank_server_destroy(jank_server_ctx_t* ctx)
{
    int ret = 0;

    if (close(ctx->dest_sockfd) != 0) {
        elog_w("Failed to close destination socket");
        ret = 1;
    }
    if (close(ctx->ds_sockfd) != 0) {
        elog_w("Failed to close downstream socket");
        ret = 1;
    }
    if (close(ctx->dns_sockfd) != 0) {
        elog_w("Failed to create DNS socket");
        ret = 1;
    }
    if (close(ctx->epollfd) != 0) {
        elog_w("Failed to close epoll instance");
        ret = 1;
    }

    return ret;
}

int handle_dns_events(jank_server_ctx_t* ctx, int fd, int events)
{
    int error;
    socklen_t errorlen;

    char query_buf[DNS_MIN_BUFSIZE];
    char reply_buf[DNS_MIN_BUFSIZE];
    dnserr_t dns_ret;
    ssize_t reply_size;

    struct sockaddr_storage saddr;
    socklen_t saddrlen;
    ssize_t recvd;
    ssize_t sent;

    char domain[DNS_MAX_DOMAIN_LEN + 1];
    size_t domain_len;
    rcode_t rcode;

    if (events & EPOLLERR) {
        error = 0;
        errorlen = sizeof(error);

        if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &errorlen) != 0) {
            elog_w("Failed to read error on DNS socket");
        } else {
            errno = error;
            elog_w("Destination socket error");
        }
    }
    if (events & EPOLLIN) {
    retry_recv:
        saddrlen = sizeof(saddr);
        recvd = recvfrom(fd, query_buf, sizeof(query_buf), 0, (struct sockaddr*)&saddr, &saddrlen);
        if (recvd < 0) {
            if (errno == EINTR) {
                goto retry_recv;
            }
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                return 0;
            }
            elog_e("Failed to receive datagram on DNS socket");
            return -1;
        }

        dns_ret = dns_parse_query(query_buf, recvd, domain, sizeof(domain), &domain_len, NULL, NULL);
        if (dns_ret != DNSERR_SUCCESS) {
            log_d("%s - Received invalid DNS query: %s",
                net_saddr_to_str((struct sockaddr*)&saddr), dnserr_str(dns_ret));
            return 0;
        }
        log_t("%s - Received DNS query for domain: %s",
            net_saddr_to_str((struct sockaddr*)&saddr), domain);

        if (domain_len <= ctx->domain_len
            || domain[domain_len - ctx->domain_len - 1] != '.'
            || memcmp(domain + domain_len - ctx->domain_len, ctx->domain, ctx->domain_len) != 0) {
            log_d("%s - Refusing to answer DNS query for domain %s",
                net_saddr_to_str((struct sockaddr*)&saddr), domain);
            rcode = RCODE_REFUSED;
        } else {
            if (!handle_dns_query(ctx, domain, domain_len)) {
                log_d("DNS query handler rejected query, not sending response");
                return 0;
            }
            rcode = RCODE_NXDOMAIN;
        }

        reply_size = dns_compose_reply_empty(query_buf, recvd, rcode, reply_buf, sizeof(reply_buf));
        if (reply_size < 0) {
            log_w("%s - Failed to compose DNS reply for domain %s: %s",
                net_saddr_to_str((struct sockaddr*)&saddr), domain,
                dnserr_str(reply_size));
            return 0;
        }
    retry_send:
        sent = sendto(fd, reply_buf, reply_size, 0, (struct sockaddr*)&saddr, saddrlen);
        if (sent < 0) {
            if (errno == EINTR) {
                goto retry_send;
            }
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                log_d("%s - DNS send buffer full, dropping reply",
                    net_saddr_to_str((struct sockaddr*)&saddr));
                return 0;
            }
            elog_e("%s - Failed to send DNS reply", net_saddr_to_str((struct sockaddr*)&saddr));
            return 1;
        }
    }
    return 0;
}

int handle_dest_events(jank_server_ctx_t* ctx, int fd, int events)
{
    int error;
    socklen_t errorlen;

    int nrecvd;
    int nsent;
    int total_sent;

    int i;

    if (events & EPOLLERR) {
        error = 0;
        errorlen = sizeof(error);

        if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &errorlen) != 0) {
            elog_w("Failed to read error on destination socket");
        } else if (error == ECONNREFUSED) {
            log_w("Cannot reach destination %s", net_peername_to_str(fd));
        } else {
            errno = error;
            elog_w("Destination socket error");
        }
    }
    if (events & EPOLLIN) {
        for (i = 0; i < SERVER_UDP_VLEN; i++) {
            ctx->udp_msgs[i].msg_hdr.msg_iov[0].iov_len = SERVER_UDP_BUFSIZE;
        }
    retry_recv:
        nrecvd = recvmmsg(fd, ctx->udp_msgs, SERVER_UDP_VLEN, 0, NULL);
        if (nrecvd < 0) {
            if (errno == EINTR) {
                goto retry_recv;
            }
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                return 0;
            }
            elog_e("Failed to receive datagrams on destination socket");
            return -1;
        }
        for (i = 0; i < nrecvd; i++) {
            ctx->udp_msgs[i].msg_hdr.msg_iov[0].iov_len = ctx->udp_msgs[i].msg_len;
            log_t("Received datagrams #%d of size %u from destination",
                i, ctx->udp_msgs[i].msg_len);
        }

        total_sent = 0;
        while (total_sent < nrecvd) {
            nsent = sendmmsg(ctx->ds_sockfd, ctx->udp_msgs + total_sent,
                nrecvd - total_sent, 0);
            if (nsent < 0) {
                if (errno == EINTR) {
                    continue;
                }
                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                    log_d("Downstream socket send buffer full, dropping %d datagrams",
                        nrecvd - total_sent);
                    break;
                }
                elog_e("Failed to send datagrams to downstream");
                return 1;
            }
            log_t("Sent %d/%d datagrams to downstream", nsent, nrecvd);
            total_sent += nsent;
        }
    }
    return 0;
}

bool handle_dns_query(jank_server_ctx_t* ctx, char* domain, size_t domain_len)
{
    metadata_t md;

    char payload[PROTO_FRAG_LEN_MAX];
    ssize_t payload_len;

    asm_session_t* asm_session;
    char* assembled;
    size_t assembled_len;

    ssize_t asm_session_idx;
    protoerr_t proto_ret;
    ssize_t ret;

    payload_len = protocol_decode_domain(domain, domain_len,
        ctx->domain, ctx->domain_len, &md, payload, sizeof(payload));
    if (payload_len < 0) {
        log_w("Failed to extract paylaod from domain: %s", protoerr_str(payload_len));
        return false;
    }

    if (session_hist_find(ctx, md.session_id)) {
        log_d("Ingoring duplicate session %u", md.session_id);
        return false;
    }

    asm_session_idx = asm_session_find(ctx, md.session_id, &asm_session);
    if (asm_session_idx < 0) {
        asm_session_idx = asm_session_alloc(ctx, md.session_id, &asm_session);
        if (asm_session_idx < 0) {
            log_d("No assembler available for S%u, reallocating oldest session", md.session_id);
            asm_session_idx = asm_session_realloc_oldest(ctx, md.session_id, &asm_session);
            if (asm_session_idx < 0) {
                log_e("Failed to reallocate session");
                return true;
            }
        }
    }

    proto_ret = frag_assembler_add(&asm_session->assembler, md.frag_idx, md.last_frag,
        payload, payload_len);
    if (proto_ret == PROTOERR_DUP) {
        log_t("Dropping duplicate from #%u on S%u", md.frag_idx, md.session_id);
        return false;
    }
    if (proto_ret != PROTOERR_SUCCESS) {
        log_e("Failed to add fragment #%u to S%u: %s", md.frag_idx, md.session_id,
            protoerr_str(proto_ret));
        asm_session_evict(ctx, asm_session_idx);
        return false;
    }
    asm_session->timestamp = timestamp_mono();
    log_t("Added fragment #%u of size %zd for S%u", md.frag_idx, payload_len, md.session_id);

    proto_ret = frag_assembler_assemble(&asm_session->assembler, &assembled, &assembled_len);
    if (proto_ret == PROTOERR_SUCCESS) {
        log_t("Assembled payload of length %zu for S%u", assembled_len, asm_session->session_id);
        asm_session_evict(ctx, asm_session_idx);

    retry_send:
        ret = send(ctx->dest_sockfd, assembled, assembled_len, 0);
        if (ret < 0) {
            if (errno == EINTR) {
                goto retry_send;
            }
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                log_d("Destination socket send buffer full, dropping datagram");
                return true;
            }
            elog_e("Failed to send datagram on destination socket");
        }
        return true;
    } else if (proto_ret != PROTOERR_INCOMPLETE) {
        log_e("Failed to assemble fragments for S%u: %s", md.session_id,
            protoerr_str(proto_ret));
        asm_session_evict(ctx, asm_session_idx);
        return false;
    }
    return true;
}

void handle_expiry(jank_server_ctx_t* ctx)
{
    ssize_t index;
    uint64_t timestamp;

    session_hist_entry_t* hist_entry = NULL;

    timestamp = timestamp_mono();
    BITSET512_FOR_EACH_SET(ctx->active_asm_sessions, index)
    {
        if (timestamp - ctx->asm_sessions[index].timestamp >= ASM_SESSION_EXPIRY) {
            BITSET512_CLEAR_BIT(ctx->active_asm_sessions, index);
            session_hist_push(ctx, ctx->asm_sessions[index].session_id, timestamp);
            log_t("Evicted expired assembler S%u", ctx->asm_sessions[index].session_id);
        }
    }

    while ((hist_entry = session_hist_peek(ctx))) {
        if (timestamp - hist_entry->timestamp >= SESSION_HIST_EXPIRY) {
            session_hist_pop(ctx);
            log_t("Popped session %u from history", hist_entry->session_id);
        } else {
            break;
        }
    }
}

ssize_t asm_session_find(jank_server_ctx_t* ctx, uint32_t session_id, asm_session_t** session)
{
    ssize_t index;
    BITSET512_FOR_EACH_SET(ctx->active_asm_sessions, index)
    {
        if (ctx->asm_sessions[index].session_id == session_id) {
            *session = &ctx->asm_sessions[index];
            return index;
        }
    }
    return -1;
}

ssize_t asm_session_alloc(jank_server_ctx_t* ctx, uint32_t session_id, asm_session_t** session)
{
    ssize_t index;
    index = BITSET512_FIRST_UNSET(ctx->active_asm_sessions);
    if (index < 0) {
        return -1;
    }

    ctx->asm_sessions[index].session_id = session_id;
    ctx->asm_sessions[index].timestamp = 0;
    frag_assembler_init(&ctx->asm_sessions[index].assembler);
    *session = &ctx->asm_sessions[index];

    BITSET512_SET_BIT(ctx->active_asm_sessions, index);
    return index;
}

void asm_session_evict(jank_server_ctx_t* ctx, size_t index)
{
    BITSET512_CLEAR_BIT(ctx->active_asm_sessions, index);
    session_hist_push(ctx, ctx->asm_sessions[index].session_id,
        timestamp_mono());
}

ssize_t asm_session_realloc_oldest(jank_server_ctx_t* ctx, uint32_t session_id, asm_session_t** session)
{
    ssize_t index = 0;
    uint64_t min_timestamp = UINT64_MAX;
    ssize_t min_index = -1;

    BITSET512_FOR_EACH_SET(ctx->active_asm_sessions, index)
    {
        if (ctx->asm_sessions[index].timestamp < min_timestamp) {
            min_timestamp = ctx->asm_sessions[index].timestamp;
            min_index = index;
        }
    }
    if (min_index > 0) {
        asm_session_evict(ctx, min_index);
        ctx->asm_sessions[min_index].session_id = session_id;
        ctx->asm_sessions[min_index].timestamp = 0;
        frag_assembler_init(&ctx->asm_sessions[min_index].assembler);
        BITSET512_SET_BIT(ctx->active_asm_sessions, min_index);

        *session = &ctx->asm_sessions[min_index];
    }
    return min_index;
}

void session_hist_push(jank_server_ctx_t* ctx, uint32_t session_id, uint64_t timestamp)
{
    ctx->session_hist.entries[ctx->session_hist.tail].session_id = session_id;
    ctx->session_hist.entries[ctx->session_hist.tail].timestamp = timestamp;

    ctx->session_hist.tail = (ctx->session_hist.tail + 1) % SERVER_MAX_SESSION_HIST;

    if (ctx->session_hist.count == SERVER_MAX_SESSION_HIST) {
        ctx->session_hist.head = (ctx->session_hist.head + 1) % SERVER_MAX_SESSION_HIST;
    } else {
        ctx->session_hist.count++;
    }
}

void session_hist_pop(jank_server_ctx_t* ctx)
{
    if (ctx->session_hist.count == 0) {
        return;
    }

    ctx->session_hist.head = (ctx->session_hist.head + 1) % SERVER_MAX_SESSION_HIST;
    ctx->session_hist.count--;
}

session_hist_entry_t* session_hist_peek(jank_server_ctx_t* ctx)
{
    if (ctx->session_hist.count == 0) {
        return NULL;
    }

    return &ctx->session_hist.entries[ctx->session_hist.head];
}

session_hist_entry_t* session_hist_find(jank_server_ctx_t* ctx, uint32_t session_id)
{
    size_t index;
    size_t i;

    for (i = 0; i < ctx->session_hist.count; i++) {
        index = (ctx->session_hist.head + i) % SERVER_MAX_SESSION_HIST;
        if (ctx->session_hist.entries[index].session_id == session_id) {
            return &ctx->session_hist.entries[index];
        }
    }
    return NULL;
}
