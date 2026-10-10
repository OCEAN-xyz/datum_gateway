#ifndef PORTABLE_MUTEX_H
#define PORTABLE_MUTEX_H

#ifdef __APPLE__
#include <pthread.h>
#include <time.h>
#include <errno.h>

// A struct to manage the state for a timed mutex on Apple
typedef struct {
    pthread_cond_t cond;
    int locked;
} timed_mutex_state_t;

// State management functions for timed mutexes on Apple
void apple_timed_mutex_init(timed_mutex_state_t *state);
int apple_mutex_timedlock(pthread_mutex_t *mutex, timed_mutex_state_t *state, const struct timespec *abstime);
void apple_mutex_lock(pthread_mutex_t *mutex, timed_mutex_state_t *state);
void apple_mutex_unlock(pthread_mutex_t *mutex, timed_mutex_state_t *state);
void apple_timed_mutex_destroy(timed_mutex_state_t *state);
#endif // __APPLE__

#endif // PORTABLE_MUTEX_H

