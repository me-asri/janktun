#include "args.h"

#include <stdlib.h>
#include <stddef.h>
#include <stdarg.h>
#include <string.h>
#include <stdio.h>

#include <errno.h>
#include <unistd.h>

#include "log.h"
#include "dns.h"
#include "client.h"

#define _STR(x) #x
#define STR(x) _STR(x)

#define DEFAULT_DNS_LISTEN_ADDR "[::]:53"
#define DEFAULT_LOG_LEVEL LOG_INFO

#define ENV_PREFIX "JANKTUN_"
#define ENV_VERBOSITY ENV_PREFIX "VERBOSITY"
#define ENV_LOG_NO_TIME ENV_PREFIX "LOG_NO_TIME"
#define ENV_LOG_NO_COLOR ENV_PREFIX "LOG_NO_COLOR"
#define ENV_DOMAIN ENV_PREFIX "DOMAIN"
#define ENV_DEST_ADDR ENV_PREFIX "DEST_ADDR"
#define ENV_DS_SRC_ADDR ENV_PREFIX "DOWNSTREAM_SRC_ADDR"
#define ENV_DS_ADDR ENV_PREFIX "DOWNSTREAM_ADDR"
#define ENV_DNS_LISTEN_ADDR ENV_PREFIX "DNS_LISTEN_ADDR"
#define ENV_RESOLVERS ENV_PREFIX "RESOLVERS"
#define ENV_DOMAIN_LEN ENV_PREFIX "DOMAIN_LEN"
#define ENV_DS_LISTEN_ADDR ENV_PREFIX "DOWNSTREAM_LISTEN_ADDR"
#define ENV_INBOUND_LISTEN_ADDR ENV_PREFIX "INBOUND_LISTEN_ADDR"

static int parse_size_str(const char* str, size_t* out);

static void print_usage(FILE* stream, const char* progname);
static void print_error(const char* progname, const char* fmt, ...);

static int parse_server_args(jank_args_t* args, int argc, char** argv);
static int parse_client_args(jank_args_t* args, int argc, char** argv);

int jank_args_parse(jank_args_t* args, int argc, char** argv)
{
    char* env;

    if (argc < 2 || argv[1][0] == '-') {
        print_error(argv[0], "No operation specified");
        return -1;
    }

    memset(args, 0, sizeof(*args));
    args->domain = getenv(ENV_DOMAIN);
    if (log_level_parse(getenv(ENV_VERBOSITY), &args->log_level) != 0) {
        args->log_level = DEFAULT_LOG_LEVEL;
    }
    if ((env = getenv(ENV_LOG_NO_COLOR)) && *env) {
        args->log_flags |= LOG_NO_COLOR;
    }
    if ((env = getenv(ENV_LOG_NO_TIME)) && *env) {
        args->log_flags |= LOG_NO_TIME;
    }

    if (strcmp(argv[1], "server") == 0) {
        args->op = JANK_OP_SERVER;
        return parse_server_args(args, argc, argv);
    } else if (strcmp(argv[1], "client") == 0) {
        args->op = JANK_OP_CLIENT;
        return parse_client_args(args, argc, argv);
    } else {
        print_error(argv[0], "Invalid operation '%s'", argv[1]);
        return -1;
    }
}

int parse_server_args(jank_args_t* args, int argc, char** argv)
{
    args->server.dest_addr = getenv(ENV_DEST_ADDR);
    args->server.ds_src_addr = getenv(ENV_DS_SRC_ADDR);
    args->server.ds_addr = getenv(ENV_DS_ADDR);
    args->server.dns_listen_addr = getenv(ENV_DNS_LISTEN_ADDR);
    if (!args->server.dns_listen_addr) {
        args->server.dns_listen_addr = DEFAULT_DNS_LISTEN_ADDR;
    }

    int c;
    while ((c = getopt(argc - 1, argv + 1, "hn:v:l:d:s:D:")) != -1) {
        switch (c) {
        case 'D':
            args->server.dest_addr = optarg;
            break;
        case 's':
            args->server.ds_src_addr = optarg;
            break;
        case 'd':
            args->server.ds_addr = optarg;
            break;
        case 'l':
            args->server.dns_listen_addr = optarg;
            break;
        case 'n':
            args->domain = optarg;
            break;
        case 'v':
            if (log_level_parse(optarg, &args->log_level) != 0) {
                print_error(argv[0], "Invalid verbosity '%s'", optarg);
                return -1;
            }
            break;
        case 'h':
            print_usage(stdout, argv[0]);
            return 0;
        case '?':
            print_usage(stderr, argv[0]);
            return -1;
        default:
            break;
        }
    }

    if (!args->domain) {
        print_error(argv[0], "No domain name specified");
        return -1;
    }
    if (!args->server.ds_addr) {
        print_error(argv[0], "Downstream destination address not specified");
        return -1;
    }
    if (!args->server.dest_addr) {
        print_error(argv[0], "Destination address not specified");
        return -1;
    }
    return 1;
}

int parse_client_args(jank_args_t* args, int argc, char** argv)
{
    int c;

    char* resolvers_env;
    size_t resolvers_count = 0;

    char* resolver;
    char* resolver_sptr = NULL;

    resolvers_env = getenv(ENV_RESOLVERS);
    if (resolvers_env) {
        strlcpy(args->client.resolvers_env_dup, resolvers_env,
            sizeof(args->client.resolvers_env_dup));

        resolver = strtok_r(args->client.resolvers_env_dup, " ", &resolver_sptr);
        while (resolver != NULL && resolvers_count < CLIENT_MAX_RESOLVERS - 1) {
            args->client.resolvers[resolvers_count++] = resolver;
            resolver = strtok_r(NULL, " ", &resolver_sptr);
        }
        args->client.resolvers[resolvers_count] = NULL;
    }
    if (parse_size_str(getenv(ENV_DOMAIN_LEN), &args->client.max_domain_len) != 0) {
        args->client.max_domain_len = DNS_MAX_DOMAIN_LEN;
    }
    args->client.ds_src_addr = getenv(ENV_DS_SRC_ADDR);
    args->client.ds_listen_addr = getenv(ENV_DS_LISTEN_ADDR);
    args->client.inbound_listen_addr = getenv(ENV_INBOUND_LISTEN_ADDR);

    while ((c = getopt(argc - 1, argv + 1, "hn:v:n:l:d:s:L:r:")) != -1) {
        switch (c) {
        case 'r':
            if (resolvers_count >= CLIENT_MAX_RESOLVERS) {
                print_error(argv[0], "More than %zu resolvers may not be specified.",
                    CLIENT_MAX_RESOLVERS);
                return -1;
            }
            args->client.resolvers[resolvers_count++] = optarg;
            args->client.resolvers[resolvers_count] = NULL;
            break;
        case 'L':
            if (parse_size_str(optarg, &args->client.max_domain_len) != 0) {
                print_error(argv[0], "Invalid domain length value '%s'", optarg);
                return -1;
            }
            break;
        case 's':
            args->client.ds_src_addr = optarg;
            break;
        case 'd':
            args->client.ds_listen_addr = optarg;
            break;
        case 'l':
            args->client.inbound_listen_addr = optarg;
            break;
        case 'n':
            args->domain = optarg;
            break;
        case 'v':
            if (log_level_parse(optarg, &args->log_level) != 0) {
                print_error(argv[0], "Invalid verbosity '%s'", optarg);
                return -1;
            }
            break;
        case 'h':
            print_usage(stdout, argv[0]);
            return 0;
        case '?':
            print_usage(stderr, argv[0]);
            return -1;
        default:
            break;
        }
    }
    args->client.resolvers[resolvers_count] = NULL;

    if (!args->domain) {
        print_error(argv[0], "No domain name specified");
        return -1;
    }
    if (!args->client.inbound_listen_addr) {
        print_error(argv[0], "Inbound listen address not specified");
        return -1;
    }
    if (!args->client.ds_listen_addr) {
        print_error(argv[0], "Downstream listen address not specified");
        return -1;
    }
    if (!args->client.resolvers[0]) {
        print_error(argv[0], "No resolver specified");
        return -1;
    }
    return 1;
}

void print_usage(FILE* stream, const char* progname)
{
    /* clang-format off */
    static const char USAGE[] = "Usage: %1$s [OPERATION] [OPTION...]\n"
                                "\n"
                                "Options:\n"
                                "   -n <domain>       domain name\n"
                                "   -v <verbosity>    set logging verbosity "
#ifndef NDEBUG
                                "(TRACE, DEBUG, INFO, WARN, ERROR - default: %2$s)\n"
#else
                                "(DEBUG, INFO, WARN, ERROR - default: %2$s)\n"
#endif
                                "   -h                show this help message\n"
                                "\n"
                                " Oeprations:\n"
                                "   server            run server\n"
                                "   client            run client\n"
                                "\n"
                                " Server options:\n"
                                "   -l <addr[:port]>  DNS listen address (default: " DEFAULT_DNS_LISTEN_ADDR ")\n"
                                "   -d <addr:port>    downstream destination address\n"
                                "   -s <addr[:port]>  downstream source address (optional)\n"
                                "   -D <addr:port>    destination address\n"
                                "\n"
                                " Client options:\n"
                                "   -l <addr:port>    inbound listen address\n"
                                "   -d <addr:port>    downstream listen address\n"
                                "   -s <addr:port>    downstream source address (optional)\n"
                                "   -L <length>       maximum domain length (default: " STR(DNS_MAX_DOMAIN_LEN) ")\n"
                                "   -r <addr[:port]>  resolver(s), can be specified multiple times up to " STR(CLIENT_MAX_RESOLVERS) " times\n";
    /* clang-format on */
    fprintf(stream, USAGE, progname, log_level_str(DEFAULT_LOG_LEVEL));
}

void print_error(const char* progname, const char* fmt, ...)
{
    va_list args;

    flockfile(stderr);

    fprintf(stderr, "%s: ", progname);
    va_start(args, fmt);
    vfprintf(stderr, fmt, args);
    va_end(args);
    fputc('\n', stderr);
    print_usage(stderr, progname);

    funlockfile(stderr);
}

int parse_size_str(const char* str, size_t* out)
{
    char* endptr = NULL;
    size_t num;

    if (!str) {
        return 1;
    }

    errno = 0;
    num = strtoul(str, &endptr, 10);
    if (*endptr != '\0' || errno == ERANGE) {
        return 1;
    }

    *out = num;
    return 0;
}
