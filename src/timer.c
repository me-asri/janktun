#include "timer.h"

#include <stddef.h>
#include <stdint.h>
#include <time.h>

#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/timerfd.h>

#include "log.h"

int timerfd_open(uint64_t millis, bool repeating)
{
    int fd = -1;
    struct itimerspec ts;

    fd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK);
    if (fd < 0) {
        elog_e("Failed to create timerfd");
        return -1;
    }

    ts.it_value.tv_sec = millis / 1000;
    ts.it_value.tv_nsec = (millis % 1000) * 1000000;
    if (repeating) {
        ts.it_interval = ts.it_value;
    } else {
        ts.it_interval.tv_sec = 0;
        ts.it_interval.tv_nsec = 0;
    }
    if (timerfd_settime(fd, 0, &ts, NULL) != 0) {
        elog_e("Failed to arm timerfd");

        close(fd);
        return -1;
    }

    return fd;
}

int timerfd_get_expire(int fd, uint64_t* expirations)
{
    uint64_t buf;
    ssize_t nread;

retry_read:
    nread = read(fd, &buf, sizeof(buf));
    if (nread < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return 0;
        } else if (errno == EINTR) {
            goto retry_read;
        } else {
            elog_e("Failed to read timerfd");
            return -1;
        }
    }
    if (nread != sizeof(buf)) {
        log_e("Invalid read size from timerfd: %zd", nread);
        return -1;
    }

    if (expirations != NULL) {
        *expirations = buf;
    }

    return 0;
}
