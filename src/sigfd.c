#include "sigfd.h"

#include <stddef.h>
#include <stdarg.h>
#include <stdint.h>
#include <string.h>

#include <unistd.h>
#include <signal.h>
#include <errno.h>

#include <sys/types.h>
#include <sys/signalfd.h>

#include "log.h"

static thread_local bool active = false;
static thread_local sigset_t mask;

int sigfd_create(unsigned int count, ...)
{
    int fd;

    va_list args;
    unsigned int n;

    if (active) {
        log_e("Only one signalfd per thread allowed");
        return -1;
    }

    sigemptyset(&mask);

    va_start(args, count);
    for (n = 0; n < count; n++) {
        sigaddset(&mask, va_arg(args, uint32_t));
    }
    va_end(args);

    if (pthread_sigmask(SIG_BLOCK, &mask, NULL) != 0) {
        elog_e("Failed to mask signals");
        return -1;
    }

    fd = signalfd(-1, &mask, SFD_NONBLOCK);
    if (fd < 0) {
        elog_e("signalfd() failed");

        pthread_sigmask(SIG_UNBLOCK, &mask, NULL);
        return -1;
    }

    active = true;
    return fd;
}

int sigfd_close(int fd)
{
    int ret = 0;

    if (pthread_sigmask(SIG_UNBLOCK, &mask, NULL) != 0) {
        elog_e("Failed to unblock signals");
        ret = -1;
    }
    if (close(fd) != 0) {
        elog_e("Failed to close signalfd");
        ret = -1;
    }

    active = false;
    return ret;
}

ssize_t sigfd_read(int fd, uint32_t* signo)
{
    struct signalfd_siginfo siginfo;

    ssize_t nread;
    ssize_t signals = 0;

    for (;;) {
        nread = read(fd, &siginfo, sizeof(siginfo));
        if (nread < 0) {
            if (errno == EINTR) {
                continue;
            } else if (errno == EAGAIN || errno == EWOULDBLOCK) {
                break;
            } else {
                elog_e("Failed to read signalfd");
                return -1;
            }
        }
        if (nread != sizeof(siginfo)) {
            log_e("Invalid read size from signfd: %d", nread);
            return -1;
        }

        if (signo) {
            *signo = siginfo.ssi_signo;
        }
        signals++;
    }

    return signals;
}

const char* sigfd_sig_name(uint32_t signo)
{
    return sigabbrev_np(signo);
}