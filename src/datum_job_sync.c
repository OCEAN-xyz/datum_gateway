/*
 *
 * DATUM Gateway - Job Coordination Implementation
 * Decentralized Alternative Templates for Universal Mining
 *
 * https://ocean.xyz
 *
 * Copyright (c) 2025 Bitcoin Ocean, LLC
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <pthread.h>
#include <sodium.h>

#include "datum_job_sync.h"
#include "datum_protocol.h"
#include "datum_stratum.h"
#include "datum_logger.h"
#include "datum_conf.h"
#include "datum_utils.h"

// Global job synchronization state
T_JOB_SYNC_STATE global_job_sync_state;

// Initialize job synchronization subsystem
int datum_job_sync_init(void) {
    memset(&global_job_sync_state, 0, sizeof(T_JOB_SYNC_STATE));

    // Initialize the lock
    if (pthread_rwlock_init(&global_job_sync_state.lock, NULL) != 0) {
        DLOG_ERROR("Failed to initialize job sync lock");
        return -1;
    }

    // Set default configuration
    global_job_sync_state.session.sync_interval_ms = 5000; // 5 seconds default
    global_job_sync_state.session.enabled = datum_config.datum_enable_job_coordination;

    // Generate gateway ID if not configured
    if (!global_job_sync_state.session.gateway_id[0]) {
        snprintf(global_job_sync_state.session.gateway_id,
                sizeof(global_job_sync_state.session.gateway_id),
                "DG%08X", (uint32_t)time(NULL));
    }

    // Generate session ID
    global_job_sync_state.session.session_id = ((uint64_t)time(NULL) << 32) | (uint64_t)rand();

    DLOG_INFO("Job synchronization initialized: gateway_id=%s, session_id=%lx, enabled=%d",
              global_job_sync_state.session.gateway_id,
              global_job_sync_state.session.session_id,
              global_job_sync_state.session.enabled);

    return 0;
}

// Cleanup job synchronization subsystem
void datum_job_sync_cleanup(void) {
    pthread_rwlock_destroy(&global_job_sync_state.lock);
    memset(&global_job_sync_state, 0, sizeof(T_JOB_SYNC_STATE));
}

// Start a new sync session with the pool
int datum_job_sync_start_session(const char *gateway_id) {
    pthread_rwlock_wrlock(&global_job_sync_state.lock);

    // Update gateway ID if provided
    if (gateway_id && gateway_id[0]) {
        strncpy(global_job_sync_state.session.gateway_id, gateway_id,
                sizeof(global_job_sync_state.session.gateway_id) - 1);
    }

    // Reset session statistics
    global_job_sync_state.session.jobs_synced = 0;
    global_job_sync_state.session.jobs_acknowledged = 0;
    global_job_sync_state.session.sync_failures = 0;
    global_job_sync_state.session.initialized = false;

    // Clear job cache
    global_job_sync_state.job_count = 0;
    global_job_sync_state.current_index = 0;
    memset(global_job_sync_state.jobs, 0, sizeof(global_job_sync_state.jobs));

    pthread_rwlock_unlock(&global_job_sync_state.lock);

    // Send initialization message to pool
    // TODO: Implement protocol message sending

    DLOG_INFO("Started new job sync session: gateway_id=%s",
              global_job_sync_state.session.gateway_id);

    return 0;
}

// Synchronize a new Stratum job with the pool
int datum_job_sync_add(T_DATUM_STRATUM_JOB *job, bool urgent) {
    if (!job || !global_job_sync_state.session.enabled) {
        return -1;
    }

    pthread_rwlock_wrlock(&global_job_sync_state.lock);

    // Find or create entry
    uint32_t idx = global_job_sync_state.current_index;
    T_SYNC_JOB_ENTRY *entry = &global_job_sync_state.jobs[idx];

    // Clear previous entry
    memset(entry, 0, sizeof(T_SYNC_JOB_ENTRY));

    // Fill in sync data
    T_DATUM_JOB_SYNC *sync = &entry->sync_data;

    // Job identification
    sync->datum_job_id = job->datum_job_idx;
    strncpy(sync->stratum_job_id, job->job_id, sizeof(sync->stratum_job_id) - 1);
    strncpy(sync->gateway_id, global_job_sync_state.session.gateway_id,
            sizeof(sync->gateway_id) - 1);

    // Block template metadata
    memcpy(sync->prevhash, job->prevhash_bin, 32);
    sync->version = job->version_uint;
    sync->nbits = job->nbits_uint;
    sync->base_ntime = strtoul(job->ntime, NULL, 16);
    sync->height = job->height;

    // Merkle tree data
    sync->merkle_branch_count = job->merklebranch_count;

    // Calculate merkle root with empty coinbase
    unsigned char empty_coinbase_hash[32];
    memset(empty_coinbase_hash, 0, 32);
    stratum_job_merkle_root_calc(job, empty_coinbase_hash, sync->merkle_root_empty);

    // Coinbase information
    for (int i = 0; i < MAX_COINBASE_TYPES; i++) {
        sync->coinbase_size[i] = job->coinbase[i].coinb1_len + job->coinbase[i].coinb2_len;
        sync->has_coinbase[i] = (sync->coinbase_size[i] > 0);
    }
    sync->coinbase_value = job->coinbase_value;

    // Difficulty requirements - simplified for now
    sync->min_diff = 1; // Will be updated based on vardiff
    sync->pool_diff = 1;

    // Extranonce configuration
    sync->enprefix = job->enprefix;
    sync->extranonce1_len = 4; // Standard for now
    sync->extranonce2_len = 8; // Standard for now

    // Timestamp and flags
    sync->created_tsms = job->tsms;
    sync->sync_flags = urgent ? JOB_SYNC_FLAG_URGENT : 0;

    // Generate HMAC
    datum_job_sync_generate_hmac(sync);

    // Update entry metadata
    entry->stratum_job = job;
    entry->status = JOB_SYNC_STATUS_PENDING;
    entry->sent_tsms = current_time_millis();
    entry->retry_count = 0;

    // Update indices
    global_job_sync_state.current_index = (idx + 1) % MAX_SYNC_JOBS;
    if (global_job_sync_state.job_count < MAX_SYNC_JOBS) {
        global_job_sync_state.job_count++;
    }

    global_job_sync_state.session.jobs_synced++;

    pthread_rwlock_unlock(&global_job_sync_state.lock);

    // Send sync message to pool
    // TODO: Queue message for sending via datum_protocol

    DLOG_DEBUG("Added job for sync: stratum_id=%s, datum_id=%d, urgent=%d",
               job->job_id, job->datum_job_idx, urgent);

    return 0;
}

// Handle job sync acknowledgment from pool
int datum_job_sync_handle_ack(unsigned char datum_job_id, bool success) {
    pthread_rwlock_wrlock(&global_job_sync_state.lock);

    // Find the job entry
    T_SYNC_JOB_ENTRY *entry = NULL;
    for (uint32_t i = 0; i < global_job_sync_state.job_count; i++) {
        if (global_job_sync_state.jobs[i].sync_data.datum_job_id == datum_job_id &&
            global_job_sync_state.jobs[i].status == JOB_SYNC_STATUS_SENT) {
            entry = &global_job_sync_state.jobs[i];
            break;
        }
    }

    if (!entry) {
        pthread_rwlock_unlock(&global_job_sync_state.lock);
        DLOG_WARN("Received ACK for unknown job: datum_id=%d", datum_job_id);
        return -1;
    }

    // Update status
    if (success) {
        entry->status = JOB_SYNC_STATUS_ACKNOWLEDGED;
        entry->ack_tsms = current_time_millis();
        global_job_sync_state.session.jobs_acknowledged++;
        global_job_sync_state.session.last_sync_tsms = entry->ack_tsms;

        DLOG_DEBUG("Job sync acknowledged: datum_id=%d, stratum_id=%s",
                   datum_job_id, entry->sync_data.stratum_job_id);
    } else {
        entry->status = JOB_SYNC_STATUS_FAILED;
        global_job_sync_state.session.sync_failures++;

        DLOG_WARN("Job sync failed: datum_id=%d, stratum_id=%s",
                  datum_job_id, entry->sync_data.stratum_job_id);
    }

    pthread_rwlock_unlock(&global_job_sync_state.lock);
    return 0;
}

// Generate HMAC for sync message
void datum_job_sync_generate_hmac(T_DATUM_JOB_SYNC *sync) {
    if (!sync) return;

    // Calculate HMAC over the sync data (excluding the HMAC field itself)
    crypto_auth_hmacsha256(
        sync->hmac,
        (unsigned char*)sync,
        sizeof(T_DATUM_JOB_SYNC) - sizeof(sync->hmac),
        global_job_sync_state.shared_secret
    );
}

// Validate HMAC on sync message
bool datum_job_sync_validate_hmac(const T_DATUM_JOB_SYNC *sync) {
    if (!sync) return false;

    unsigned char calculated_hmac[32];

    // Calculate HMAC over the sync data (excluding the HMAC field)
    crypto_auth_hmacsha256(
        calculated_hmac,
        (const unsigned char*)sync,
        sizeof(T_DATUM_JOB_SYNC) - sizeof(sync->hmac),
        global_job_sync_state.shared_secret
    );

    // Compare HMACs
    return crypto_verify_32(calculated_hmac, sync->hmac) == 0;
}

// Get synchronized job by Stratum job ID
T_SYNC_JOB_ENTRY *datum_job_sync_find_by_stratum_id(const char *job_id) {
    if (!job_id) return NULL;

    pthread_rwlock_rdlock(&global_job_sync_state.lock);

    T_SYNC_JOB_ENTRY *result = NULL;
    for (uint32_t i = 0; i < global_job_sync_state.job_count; i++) {
        if (strcmp(global_job_sync_state.jobs[i].sync_data.stratum_job_id, job_id) == 0) {
            result = &global_job_sync_state.jobs[i];
            break;
        }
    }

    pthread_rwlock_unlock(&global_job_sync_state.lock);
    return result;
}

// Get synchronized job by DATUM job ID
T_SYNC_JOB_ENTRY *datum_job_sync_find_by_datum_id(unsigned char datum_job_id) {
    pthread_rwlock_rdlock(&global_job_sync_state.lock);

    T_SYNC_JOB_ENTRY *result = NULL;
    for (uint32_t i = 0; i < global_job_sync_state.job_count; i++) {
        if (global_job_sync_state.jobs[i].sync_data.datum_job_id == datum_job_id) {
            result = &global_job_sync_state.jobs[i];
            break;
        }
    }

    pthread_rwlock_unlock(&global_job_sync_state.lock);
    return result;
}

// Periodic sync maintenance
void datum_job_sync_maintenance(void) {
    if (!global_job_sync_state.session.enabled) return;

    uint64_t now = current_time_millis();
    pthread_rwlock_wrlock(&global_job_sync_state.lock);

    // Clean up old jobs (older than 10 minutes)
    uint64_t expiry = now - (10 * 60 * 1000);

    for (uint32_t i = 0; i < global_job_sync_state.job_count; i++) {
        T_SYNC_JOB_ENTRY *entry = &global_job_sync_state.jobs[i];

        // Skip if already empty
        if (entry->status == JOB_SYNC_STATUS_NONE) continue;

        // Check if expired
        if (entry->sent_tsms < expiry) {
            DLOG_DEBUG("Expiring old sync job: stratum_id=%s, age=%lums",
                       entry->sync_data.stratum_job_id,
                       now - entry->sent_tsms);
            memset(entry, 0, sizeof(T_SYNC_JOB_ENTRY));
            continue;
        }

        // Retry failed syncs
        if (entry->status == JOB_SYNC_STATUS_PENDING &&
            entry->retry_count < 3 &&
            (now - entry->sent_tsms) > 5000) {

            entry->retry_count++;
            entry->sent_tsms = now;

            DLOG_DEBUG("Retrying job sync: stratum_id=%s, attempt=%d",
                       entry->sync_data.stratum_job_id, entry->retry_count);

            // TODO: Queue for retransmission
        }
    }

    pthread_rwlock_unlock(&global_job_sync_state.lock);
}

// Check if job synchronization is enabled and active
bool datum_job_sync_is_active(void) {
    pthread_rwlock_rdlock(&global_job_sync_state.lock);
    bool active = global_job_sync_state.session.enabled &&
                  global_job_sync_state.session.initialized;
    pthread_rwlock_unlock(&global_job_sync_state.lock);
    return active;
}

// Get current sync statistics
void datum_job_sync_get_stats(T_JOB_SYNC_SESSION *stats) {
    if (!stats) return;

    pthread_rwlock_rdlock(&global_job_sync_state.lock);
    memcpy(stats, &global_job_sync_state.session, sizeof(T_JOB_SYNC_SESSION));
    pthread_rwlock_unlock(&global_job_sync_state.lock);
}

// Configuration helpers
void datum_job_sync_set_interval(uint32_t interval_ms) {
    pthread_rwlock_wrlock(&global_job_sync_state.lock);
    global_job_sync_state.session.sync_interval_ms = interval_ms;
    pthread_rwlock_unlock(&global_job_sync_state.lock);
}

void datum_job_sync_set_gateway_id(const char *id) {
    if (!id) return;
    pthread_rwlock_wrlock(&global_job_sync_state.lock);
    strncpy(global_job_sync_state.session.gateway_id, id,
            sizeof(global_job_sync_state.session.gateway_id) - 1);
    pthread_rwlock_unlock(&global_job_sync_state.lock);
}

void datum_job_sync_set_shared_secret(const unsigned char *secret, size_t len) {
    if (!secret || len == 0) return;
    pthread_rwlock_wrlock(&global_job_sync_state.lock);
    size_t copy_len = len > 32 ? 32 : len;
    memcpy(global_job_sync_state.shared_secret, secret, copy_len);
    pthread_rwlock_unlock(&global_job_sync_state.lock);
}

// Debugging and logging
void datum_job_sync_dump_state(void) {
    pthread_rwlock_rdlock(&global_job_sync_state.lock);

    DLOG_INFO("Job Sync State Dump:");
    DLOG_INFO("  Gateway ID: %s", global_job_sync_state.session.gateway_id);
    DLOG_INFO("  Session ID: %lx", global_job_sync_state.session.session_id);
    DLOG_INFO("  Enabled: %d, Initialized: %d",
              global_job_sync_state.session.enabled,
              global_job_sync_state.session.initialized);
    DLOG_INFO("  Jobs synced: %u, acknowledged: %u, failed: %u",
              global_job_sync_state.session.jobs_synced,
              global_job_sync_state.session.jobs_acknowledged,
              global_job_sync_state.session.sync_failures);
    DLOG_INFO("  Active jobs in cache: %u", global_job_sync_state.job_count);

    for (uint32_t i = 0; i < global_job_sync_state.job_count; i++) {
        T_SYNC_JOB_ENTRY *entry = &global_job_sync_state.jobs[i];
        if (entry->status != JOB_SYNC_STATUS_NONE) {
            DLOG_INFO("    Job %u: stratum_id=%s, datum_id=%d, status=%d",
                      i, entry->sync_data.stratum_job_id,
                      entry->sync_data.datum_job_id, entry->status);
        }
    }

    pthread_rwlock_unlock(&global_job_sync_state.lock);
}