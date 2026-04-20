#include "portable_mutex.h"

#ifdef __APPLE__
void apple_timed_mutex_init(timed_mutex_state_t *state) {
    pthread_cond_init(&state->cond, NULL);
    state->locked = 0;
}

int apple_mutex_timedlock(pthread_mutex_t *mutex, timed_mutex_state_t *state, const struct timespec *abstime) {
    int rc;
    pthread_mutex_lock(mutex);
    while (state->locked) {
        rc = pthread_cond_timedwait(&state->cond, mutex, abstime);
        if (rc == ETIMEDOUT) {
            pthread_mutex_unlock(mutex);
            return ETIMEDOUT;
        }
        if (rc != 0) {
            pthread_mutex_unlock(mutex);
            return rc;
        }
    }
    state->locked = 1;
    pthread_mutex_unlock(mutex);
    return 0;
}

void apple_mutex_lock(pthread_mutex_t *mutex, timed_mutex_state_t *state) {
    pthread_mutex_lock(mutex);
    while (state->locked) {
        pthread_cond_wait(&state->cond, mutex);
    }
    state->locked = 1;
    pthread_mutex_unlock(mutex);
}

void apple_mutex_unlock(pthread_mutex_t *mutex, timed_mutex_state_t *state) {
    pthread_mutex_lock(mutex);
    state->locked = 0;
    pthread_cond_signal(&state->cond);
    pthread_mutex_unlock(mutex);
}

void apple_timed_mutex_destroy(timed_mutex_state_t *state) {
    pthread_cond_destroy(&state->cond);
}
#endif // __APPLE__

