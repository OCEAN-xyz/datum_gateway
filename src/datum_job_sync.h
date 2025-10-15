/*
 *
 * DATUM Gateway - Job Coordination for Fallback Share Submission
 * Decentralized Alternative Templates for Universal Mining
 *
 * This file implements job synchronization between DATUM Gateway
 * and upstream pools to enable fallback share submission.
 *
 * https://ocean.xyz
 *
 * ---
 *
 * Copyright (c) 2025 Bitcoin Ocean, LLC
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 *
 */

#ifndef _DATUM_JOB_SYNC_H_
#define _DATUM_JOB_SYNC_H_

#include <stdbool.h>
#include <stdint.h>
#include <pthread.h>

#include "datum_stratum.h"
#include "datum_protocol.h"

// Protocol commands for job synchronization
#define DATUM_CMD_JOB_SYNC      0x30  // Gateway -> Pool: Sync job metadata
#define DATUM_CMD_JOB_SYNC_ACK  0x31  // Pool -> Gateway: Acknowledge sync
#define DATUM_CMD_SHARE_FORWARD 0x32  // Pool -> Gateway: Forward share for validation
#define DATUM_CMD_JOB_SYNC_INIT 0x33  // Gateway -> Pool: Initialize sync session

// Maximum number of jobs to keep synchronized
#define MAX_SYNC_JOBS 32

// Job synchronization flags
#define JOB_SYNC_FLAG_FULL_TEMPLATE  0x01  // Include full template data
#define JOB_SYNC_FLAG_COINBASE_ONLY  0x02  // Only sync coinbase data
#define JOB_SYNC_FLAG_URGENT         0x04  // High priority sync (new block)
#define JOB_SYNC_FLAG_COMPRESSED     0x08  // Use compression

// Job sync status
typedef enum {
    JOB_SYNC_STATUS_NONE = 0,
    JOB_SYNC_STATUS_PENDING,
    JOB_SYNC_STATUS_SENT,
    JOB_SYNC_STATUS_ACKNOWLEDGED,
    JOB_SYNC_STATUS_FAILED
} job_sync_status_t;

// Job synchronization data structure
typedef struct __attribute__((packed)) {
    // Job identification
    unsigned char datum_job_id;         // DATUM protocol job ID (0-7)
    char stratum_job_id[24];            // Full Stratum job ID as sent to miners
    char gateway_id[16];                // Unique gateway identifier

    // Block template metadata
    unsigned char prevhash[32];         // Previous block hash
    uint32_t version;                   // Block version
    uint32_t nbits;                     // Network difficulty bits
    uint32_t base_ntime;                // Base timestamp
    uint64_t height;                    // Block height

    // Merkle tree data
    uint16_t merkle_branch_count;       // Number of merkle branches
    unsigned char merkle_root_empty[32]; // Merkle root with empty coinbase

    // Coinbase information
    uint16_t coinbase_size[MAX_COINBASE_TYPES]; // Size of each coinbase type
    bool has_coinbase[MAX_COINBASE_TYPES];      // Which coinbase types are available
    uint64_t coinbase_value;            // Total coinbase value in satoshis

    // Difficulty requirements
    uint64_t min_diff;                  // Minimum share difficulty
    uint64_t pool_diff;                 // Pool's required difficulty

    // Extranonce configuration
    uint16_t enprefix;                  // Extranonce prefix
    uint8_t extranonce1_len;            // Length of extranonce1
    uint8_t extranonce2_len;            // Length of extranonce2

    // Timestamp and flags
    uint64_t created_tsms;              // When job was created (milliseconds)
    uint32_t sync_flags;                // Synchronization flags

    // Security
    unsigned char hmac[32];             // HMAC-SHA256 for authentication
} T_DATUM_JOB_SYNC;

// Job sync session information
typedef struct {
    bool enabled;                       // Is job sync enabled?
    bool initialized;                   // Has sync session been initialized?
    char gateway_id[16];                // Our gateway identifier
    uint64_t session_id;                // Current sync session ID
    uint64_t last_sync_tsms;           // Last successful sync timestamp
    uint32_t sync_interval_ms;         // Milliseconds between syncs
    uint32_t jobs_synced;               // Total jobs synchronized
    uint32_t jobs_acknowledged;         // Jobs acknowledged by pool
    uint32_t sync_failures;             // Failed sync attempts
} T_JOB_SYNC_SESSION;

// Synchronized job cache entry
typedef struct {
    T_DATUM_JOB_SYNC sync_data;        // Job synchronization data
    T_DATUM_STRATUM_JOB *stratum_job;  // Pointer to original Stratum job
    job_sync_status_t status;          // Current sync status
    uint64_t sent_tsms;                 // When sync was sent
    uint64_t ack_tsms;                  // When acknowledgment received
    uint32_t retry_count;               // Number of retry attempts
} T_SYNC_JOB_ENTRY;

// Global job synchronization state
typedef struct {
    T_JOB_SYNC_SESSION session;         // Current session info
    T_SYNC_JOB_ENTRY jobs[MAX_SYNC_JOBS]; // Synchronized jobs
    uint32_t job_count;                 // Number of jobs in cache
    uint32_t current_index;             // Current write index
    pthread_rwlock_t lock;              // Thread safety
    unsigned char shared_secret[32];    // Shared secret for HMAC
} T_JOB_SYNC_STATE;

// Function declarations

// Initialize job synchronization subsystem
int datum_job_sync_init(void);

// Cleanup job synchronization subsystem
void datum_job_sync_cleanup(void);

// Start a new sync session with the pool
int datum_job_sync_start_session(const char *gateway_id);

// Synchronize a new Stratum job with the pool
int datum_job_sync_add(T_DATUM_STRATUM_JOB *job, bool urgent);

// Handle job sync acknowledgment from pool
int datum_job_sync_handle_ack(unsigned char datum_job_id, bool success);

// Process a forwarded share from the pool
int datum_job_sync_handle_forward(const unsigned char *data, size_t len);

// Build job sync message for transmission
int datum_job_sync_build_message(T_DATUM_JOB_SYNC *sync, unsigned char *buffer, size_t max_len);

// Parse job sync message from pool
int datum_job_sync_parse_message(const unsigned char *buffer, size_t len, T_DATUM_JOB_SYNC *sync);

// Validate HMAC on sync message
bool datum_job_sync_validate_hmac(const T_DATUM_JOB_SYNC *sync);

// Generate HMAC for sync message
void datum_job_sync_generate_hmac(T_DATUM_JOB_SYNC *sync);

// Get synchronized job by Stratum job ID
// THREAD SAFETY: Caller MUST hold global_job_sync_state.lock (read or write) for
// the entire duration they use the returned pointer. Returns NULL if not found.
T_SYNC_JOB_ENTRY *datum_job_sync_find_by_stratum_id(const char *job_id);

// Get synchronized job by DATUM job ID
// THREAD SAFETY: Caller MUST hold global_job_sync_state.lock (read or write) for
// the entire duration they use the returned pointer. Returns NULL if not found.
T_SYNC_JOB_ENTRY *datum_job_sync_find_by_datum_id(unsigned char datum_job_id);

// Periodic sync maintenance (cleanup old jobs, retry failed syncs)
void datum_job_sync_maintenance(void);

// Check if job synchronization is enabled and active
bool datum_job_sync_is_active(void);

// Get current sync statistics
void datum_job_sync_get_stats(T_JOB_SYNC_SESSION *stats);

// Configuration helpers
void datum_job_sync_set_interval(uint32_t interval_ms);
void datum_job_sync_set_gateway_id(const char *id);
void datum_job_sync_set_shared_secret(const unsigned char *secret, size_t len);

// Debugging and logging
void datum_job_sync_dump_state(void);

// Protocol integration
int datum_job_sync_send_to_pool(T_DATUM_JOB_SYNC *sync);

// External globals
extern T_JOB_SYNC_STATE global_job_sync_state;

#endif /* _DATUM_JOB_SYNC_H_ */