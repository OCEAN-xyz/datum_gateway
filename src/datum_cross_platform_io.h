/* datum_cross_platform_io.h - Cross-platform I/O abstraction */

#ifndef DATUM_CROSS_PLATFORM_IO_H
#define DATUM_CROSS_PLATFORM_IO_H

#ifdef __APPLE__
#include <sys/event.h>
#include <sys/time.h>
#include <unistd.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <pthread/pthread.h>
#define IO_HANDLE int
#define IO_EVENT_READ EVFILT_READ
#define IO_EVENT_ERROR EVFILT_EXCEPT
#define IO_MAX_EVENTS 32

static int datum_io_create() {
    return kqueue();
}

static int datum_io_add(IO_HANDLE kq, uintptr_t fd, struct kevent *evSet) {
    evSet->ident = fd;
    EV_SET(evSet, fd, EVFILT_READ, EV_ADD, 0, 0, NULL);
    return kevent(kq, evSet, 1, NULL, 0, NULL);
}

static int datum_io_delete(IO_HANDLE kq, uintptr_t fd, struct kevent *evSet)
{
    if (evSet) {
        evSet->ident = fd;
    }
    EV_SET(evSet, fd, EVFILT_READ, EV_DELETE, 0, 0, NULL);
    return kevent(kq, evSet, 1, NULL, 0, NULL);
}

static int datum_io_modify(IO_HANDLE kq, uintptr_t fd, struct kevent *evSet)
{
    if (evSet) {
        evSet->ident = fd;
    }
    EV_SET(evSet, fd, EVFILT_READ, EV_ADD | EV_ENABLE, 0, 0, NULL);
    return kevent(kq, evSet, 1, NULL, 0, NULL);
}

static int datum_io_wait(IO_HANDLE kq, struct kevent* events, int max_events, int timeout_ms) {
    struct timespec ts = {
        .tv_sec = timeout_ms / 1000,
        .tv_nsec = (timeout_ms % 1000) * 1000000
    };
    return kevent(kq, NULL, 0, events, max_events, &ts);
}

static int portable_mutex_timedlock(pthread_mutex_t *mutex, const struct timespec *timeout) {
    while (nanosleep(timeout, NULL) == -1 && errno == EINTR) continue;
    return pthread_mutex_trylock(mutex);
}

#elif defined(__linux__)
#include <sys/epoll.h>
#include <unistd.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#define IO_HANDLE int
#define IO_EVENT_READ EPOLLIN
#define IO_EVENT_ERROR (EPOLLERR | EPOLLHUP)
#define IO_MAX_EVENTS 32

static int datum_io_create(int flags) {
    return epoll_create1(flags);
}

static int datum_io_add(IO_HANDLE epfd, uintptr_t fd, struct epoll_event *ev) {
    if (ev) {
        ev->events =  EPOLLIN | EPOLLERR | EPOLLHUP;
        ev->data.fd = fd;
    }
    return epoll_ctl(epfd, EPOLL_CTL_ADD, fd, ev);
}

static int datum_io_delete(IO_HANDLE epfd, uintptr_t fd, struct epoll_event *ev) {
    return epoll_ctl(epfd, EPOLL_CTL_DEL, fd, ev);
}

static int datum_io_modify(IO_HANDLE epfd, uintptr_t fd, struct epoll_event *ev) {
    return epoll_ctl(epfd, EPOLL_CTL_MOD, fd, ev);
}

static int datum_io_wait(IO_HANDLE epfd, struct epoll_event* events, int max_events, int timeout_ms) {
    return epoll_wait(epfd, events, max_events, timeout_ms);
}

int portable_mutex_timedlock(pthread_mutex_t *mutex, const struct timespec *timeout) {
    return pthread_mutex_timedlock(mutex, timeout);
}

#else
#error Platform not supported
#endif

#endif // DATUM_CROSS_PLATFORM_IO_H

