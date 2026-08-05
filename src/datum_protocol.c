/*
 *
 * DATUM Gateway
 * Decentralized Alternative Templates for Universal Mining
 *
 * This file is part of OCEAN's Bitcoin mining decentralization
 * project, DATUM.
 *
 * https://ocean.xyz
 *
 * ---
 *
 * Copyright (c) 2024-2025 Bitcoin Ocean, LLC & Jason Hughes
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

// DATUM Client protocol implementation
// Encrypted and on the wire has 7.999 bits of entropy per byte in testing. completely uncompressed.

// TODO: Clean this up and break up various functions
// TODO: Generalize encryption related operations vs repeated code
// TODO: Implement versioning on the protocol for feature lists
// TODO: Add pool-side assistance with startup to ensure that the client's node is fully synced with the network
// TODO: Optionally allow pool to suggest node peers
// TODO: Implement graceful negotiation of chain forks
// TODO: Implement precious block for pool blocks not found by the client
// TODO: Handle network failures that aren't immediately obvious more gracefully (like not receiving responses to server commands)
// TODO: Implement resuming of work without allowing one client to cause duplicate work for another

#include <sodium.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include "datum_cross_platform_io.h"
#if defined(__APPLE__) || defined(__BSD__)
#include <sys/event.h>  // macOS uses kqueue instead of epoll
#include <mach/mach_time.h>
#else
#include <sys/epoll.h>  // Linux-specific
#endif
#include <time.h>
#include <sys/time.h>
#include <pthread.h>
#include <netinet/tcp.h>
#include <netinet/in.h>
#include <inttypes.h>

#include "datum_utils.h"
#include "datum_protocol.h"
#include "datum_conf.h"
#include "datum_stratum.h"
#include "datum_blocktemplates.h"
#include "datum_coinbaser.h"
#include "datum_queue.h"
#include "git_version.h"

atomic_int datum_protocol_client_active = 0;

DATUM_ENC_KEYS local_datum_keys;
DATUM_ENC_KEYS session_datum_keys;
DATUM_ENC_KEYS session_remote_datum_keys;
DATUM_ENC_KEYS pool_keys;

DATUM_ENC_PRECOMP session_precomp;

unsigned char datum_state = 0;

int server_out_buf = 0;
int server_in_buf = 0;
int protocol_state = 0;

unsigned char server_send_buffer[DATUM_PROTOCOL_BUFFER_SIZE];
unsigned char server_recv_buffer[DATUM_PROTOCOL_BUFFER_SIZE];

uint32_t sending_header_key = 0xDC871829; // initial send header key ... changed by handshake function
uint32_t receiving_header_key = 0; // set by handshake function

unsigned char session_nonce_sender[crypto_box_NONCEBYTES];
unsigned char session_nonce_receiver[crypto_box_NONCEBYTES];

pthread_mutex_t datum_protocol_sender_stage1_lock = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t datum_protocol_send_buffer_lock = PTHREAD_MUTEX_INITIALIZER;

unsigned char datum_protocol_next_job_idx = 0;
pthread_mutex_t datum_protocol_next_job_idx_lock = PTHREAD_MUTEX_INITIALIZER;

T_DATUM_PROTOCOL_JOB datum_jobs[MAX_DATUM_PROTOCOL_JOBS];
pthread_rwlock_t datum_jobs_rwlock = PTHREAD_RWLOCK_INITIALIZER;

// Share tallies for decentralized mining
uint64_t datum_accepted_share_count = 0;
uint64_t datum_accepted_share_diff = 0;
uint64_t datum_rejected_share_count = 0;
uint64_t datum_rejected_share_diff = 0;

uint64_t datum_last_accepted_share_tsms = 0;
uint64_t datum_last_accepted_share_local_tsms = 0;

uint64_t datum_protocol_mainloop_tsms = 0;

uint64_t latest_server_msg_tsms = 0;

// may be used by this thread when crafting replies to server commands
unsigned char temp_data[DATUM_PROTOCOL_MAX_CMD_DATA_SIZE + 16384];

unsigned char datum_protocol_setup_new_job_idx(void *sx) {
	// Called by the stratum job updater.  Must be thread safe.
	// give the stratum job updater a new job ID for us to work with
	// The server will track up to 8 unique jobs.
	T_DATUM_STRATUM_JOB *s = (T_DATUM_STRATUM_JOB *)sx;
	unsigned char a;
	pthread_mutex_lock(&datum_protocol_next_job_idx_lock);
	a = datum_protocol_next_job_idx;
	datum_protocol_next_job_idx++;
	if (datum_protocol_next_job_idx >= MAX_DATUM_PROTOCOL_JOBS) {
		datum_protocol_next_job_idx = 0;
	}
	pthread_mutex_unlock(&datum_protocol_next_job_idx_lock);
	
	pthread_rwlock_wrlock(&datum_jobs_rwlock);
	
	memset(&datum_jobs[a], 0, sizeof(T_DATUM_PROTOCOL_JOB));
	
	datum_jobs[a].sjob = s;
	datum_jobs[a].datum_job_id = a;
	
	pthread_rwlock_unlock(&datum_jobs_rwlock);
	
	return a;
}

static inline void datum_xor_header_key(void *h, uint32_t key) {
	*((uint32_t *)h) ^= key;
}

uint32_t datum_header_xor_feedback(const uint32_t i) {
	uint32_t s = 0xb10cfeed;
	uint32_t h = s;
	uint32_t k = i;
	k *= 0xcc9e2d51;
	k = (k << 15) | (k >> 17);
	k *= 0x1b873593;
	h ^= k;
	h = (h << 13) | (h >> 19);
	h = h * 5 + 0xe6546b64;
	h ^= 4;
	h ^= h >> 16;
	h *= 0x85ebca6b;
	h ^= h >> 13;
	h *= 0xc2b2ae35;
	h ^= h >> 16;
	return h;
}

// Take the hexidecimal public key string and store it in a DATUM_ENC_KEYS
int datum_pubkey_to_struct(const char *input, DATUM_ENC_KEYS *key) {
	int i;
	if (input[0] == 0) return -1;
	
	if (strlen(input) != 128) {
		DLOG_FATAL("Pool public key is not the correct length!");
		return -1;
	}
	
	for(i=0;i<32;i++) {
		key->pk_ed25519[i] = hex2bin_uchar(&input[i<<1]);
	}
	for(i=0;i<32;i++) {
		key->pk_x25519[i] = hex2bin_uchar(&input[64+(i<<1)]);
	}
	
	return 0;
}

// Prepare session encryption precomputation
void datum_encrypt_prep_precomp(DATUM_ENC_KEYS *remote, DATUM_ENC_KEYS *local, DATUM_ENC_PRECOMP *precomp) {
	precomp->local = local;
	precomp->remote = remote;
	
	if (crypto_box_beforenm(precomp->precomp_remote, remote->pk_x25519, local->sk_x25519) != 0) {
		DLOG_ERROR("Could not precompute encryption keys.");
	}
}

// Buffer data to the server.  Raw, already encrypted and part of the protocol.
int datum_protocol_chars_to_server(unsigned char *s, int len) {
	if (!len) return 0;
	pthread_mutex_lock(&datum_protocol_send_buffer_lock);
	if ((server_out_buf + len) >= DATUM_PROTOCOL_BUFFER_SIZE) {
		pthread_mutex_unlock(&datum_protocol_send_buffer_lock);
		return -1;
	}
	if (len > (DATUM_PROTOCOL_BUFFER_SIZE-(server_out_buf)-1)) {
		len = DATUM_PROTOCOL_BUFFER_SIZE-(server_out_buf)-1;
	}
	if ((server_out_buf+len) >= DATUM_PROTOCOL_BUFFER_SIZE) {
		DLOG_ERROR("DATUM Server send overrun!");
		pthread_mutex_unlock(&datum_protocol_send_buffer_lock);
		return -1;
	}
	memcpy(&server_send_buffer[server_out_buf], s, len);
	server_out_buf += len;
	pthread_mutex_unlock(&datum_protocol_send_buffer_lock);
	return len;
}

int datum_protocol_mining_cmd(void *data, int len) {
	// protocol cmd 5
	// encypt and send a standard mining sub-command
	// this can be called from other threads so must be thread safe!
	T_DATUM_PROTOCOL_HEADER h;
	int i;
	
	memset(&h, 0, sizeof(T_DATUM_PROTOCOL_HEADER));
	
	h.is_encrypted_channel = true;
	h.proto_cmd = 5;
	h.cmd_len = len;
	h.cmd_len += crypto_box_MACBYTES;
	
	// sends of encrypted data must remain ordered
	// we have to lock here for both the header obfuscation and the nonce increment
	pthread_mutex_lock(&datum_protocol_sender_stage1_lock);
	
	crypto_box_easy_afternm(data, data, len, session_nonce_sender, session_precomp.precomp_remote);
	//DLOG_DEBUG("mining cmd 5--- len %d, send header key %8.8x, raw %8.8lx", h.cmd_len, sending_header_key, (unsigned long)upk_u32le(h, 0));
	datum_xor_header_key(&h, sending_header_key);
	sending_header_key = datum_header_xor_feedback(sending_header_key);
	datum_increment_session_nonce(session_nonce_sender);
	
	i = datum_protocol_chars_to_server((unsigned char *)&h, sizeof(T_DATUM_PROTOCOL_HEADER));
	if (i < 1) {
		pthread_mutex_unlock(&datum_protocol_sender_stage1_lock);
		return -1;
	}
	i = datum_protocol_chars_to_server((unsigned char *)data, len + crypto_box_MACBYTES);
	if (i < 1) {
		pthread_mutex_unlock(&datum_protocol_sender_stage1_lock);
		return -1;
	}
	pthread_mutex_unlock(&datum_protocol_sender_stage1_lock);
	
	return 0;
}

pthread_mutex_t datum_protocol_coinbaser_fetch_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t datum_protocol_coinbaser_fetch_cond = PTHREAD_COND_INITIALIZER;
unsigned char datum_coinbaser_v2_response_buf[2][32768] = { 0 };
unsigned char *datum_coinbaser_v2_response = NULL;
unsigned char datum_coinbaser_v2_response_buf_idx = 0;
uint64_t datum_coinbaser_v2_response_value[2] = { 0, 0 };
int datum_coinbaser_v2_response_len[2] = { 0, 0 };

int datum_protocol_coinbaser_fetch_response(int len, unsigned char *data) {
	if (len < 12) {
		DLOG_DEBUG("Invalid coinbaser received!");
		return 0;
	}
	
	// Coinbaser response from server. stash appropriately!
	struct timespec ts;
	int rc;
	clock_gettime(CLOCK_REALTIME, &ts);
	ts.tv_sec += 5; // Set timeout to 5 seconds from now
	uint32_t x;
	uint64_t v;
	
	v = upk_u64le(data, 0);
	x = upk_u32le(data, 8);
	
	if ((x > 32768-1) || (x<1) || x > (unsigned int)(len - 12)) {
		DLOG_DEBUG("Invalid coinbaser received! %lu %lu", (unsigned long)x, (unsigned long)(len-12));
		return 0;
	}
	
	rc = portable_mutex_timedlock(&datum_protocol_coinbaser_fetch_mutex, &ts);
	if (rc != 0) {
		DLOG_DEBUG("Could not get a lock on the coinbaser reception mutex after 5 seconds... bug?");
		return 0;
	}
	
	// mutex is locked
	if (datum_coinbaser_v2_response_buf_idx == 0) {
		datum_coinbaser_v2_response_buf_idx = 1;
	} else {
		datum_coinbaser_v2_response_buf_idx = 0;
	}
	datum_coinbaser_v2_response = datum_coinbaser_v2_response_buf[datum_coinbaser_v2_response_buf_idx];
	memcpy(datum_coinbaser_v2_response, &data[12], x);
	datum_coinbaser_v2_response_value[datum_coinbaser_v2_response_buf_idx] = v;
	datum_coinbaser_v2_response_len[datum_coinbaser_v2_response_buf_idx] = x;
	
	pthread_cond_signal(&datum_protocol_coinbaser_fetch_cond); // Signal the condition variable
	pthread_mutex_unlock(&datum_protocol_coinbaser_fetch_mutex);
	
	return 1;
}

int datum_protocol_coinbaser_fetch(void *sptr) {
	// Called by the coinbaser thread to request a coinbase split
	// The coinbaser thread expects this to actually result in a processed coinbase split, so we need to churn
	// here until that's ready or times out.
	T_DATUM_STRATUM_JOB *s = (T_DATUM_STRATUM_JOB *)sptr;
	uint64_t value = s->coinbase_value;
	unsigned char msg[128 + crypto_box_MACBYTES];
	int i = 0, j;
	int rc;
	struct timespec ts;
	
	s->available_coinbase_outputs_count = 0;
	
	if (value < 31250000) { // mainnet epoch V
		return 0;
	}
	
	msg[0] = 0x10; i++; // Fetch Coinbaser subcmd
	pk_u64le(msg, 1, value); i += 8;  // value we have available with this job
	
	// the job's previous block hash.  this ensures that the remote end knows which block this payout is related to
	// in the event of a chain split.
	memcpy(&msg[i], s->prevhash_bin, 32); i+=32;
	msg[i] = 0xFE; i++;
	
	// pad
	j = 1 + (rand() % 80);
	memset(&msg[i], rand(), j);
	i+=j;
	
	if (datum_protocol_client_active != 3) {
		return 0;
	}
	
	datum_protocol_mining_cmd(msg, i);
	
	// spin here for up to 5 seconds while awaiting a coinbaser response from DATUM Prime
	clock_gettime(CLOCK_REALTIME, &ts);
	ts.tv_sec += 5; // Set timeout to 5 seconds
	
	pthread_mutex_lock(&datum_protocol_coinbaser_fetch_mutex);
	
	rc = pthread_cond_timedwait(&datum_protocol_coinbaser_fetch_cond, &datum_protocol_coinbaser_fetch_mutex, &ts);
	if (rc == ETIMEDOUT) {
		pthread_mutex_unlock(&datum_protocol_coinbaser_fetch_mutex);
		DLOG_DEBUG("Timeout waiting for coinbaser response from DATUM Prime");
		return 0;
	}
	
	if (rc != 0) {
		DLOG_DEBUG("Error waiting for coinbaser response from DATUM Prime");
		pthread_mutex_unlock(&datum_protocol_coinbaser_fetch_mutex);
		return 0;
	}
	i = 0;
	
	// process received coinbase
	if ((datum_coinbaser_v2_response) && (datum_coinbaser_v2_response_value[datum_coinbaser_v2_response_buf_idx] == value)) {
		i = datum_coinbaser_v2_parse(s, datum_coinbaser_v2_response, datum_coinbaser_v2_response_len[datum_coinbaser_v2_response_buf_idx], false);
	}
	
	pthread_mutex_unlock(&datum_protocol_coinbaser_fetch_mutex);
	return i;
}

int datum_protocol_ping_response(T_DATUM_PROTOCOL_HEADER *h, unsigned char *data) {
	// TODO: Not implemented, but should be done for keepalive
	return 1;
}

int datum_protocol_client_configure(int len, unsigned char *data) {
	// Server->Client configuration changes.  This can be called at any time by the server
	// to make updates to these important variables.
	int i=0;
	unsigned char a;
	DLOG_DEBUG("client configuration cmd received from DATUM server");
	char msg[1024];
	
	if (i >= len || data[i] != 1) {
err:
		DLOG_ERROR("Bad configuration version from server. Is this client up to date?");
		return 0;
	}
	
	i++;
	
	// read pool addr script
	if (i >= len) goto err;
	a = data[i]; i++;
	if (i + a > len) goto err;
	memcpy(datum_config.override_mining_pool_scriptsig, &data[i], a); i+=a;
	datum_config.override_mining_pool_scriptsig_len = a;
	
	// prime ID
	if (i + 4 > len) goto err;
	datum_config.prime_id = upk_u32le(data, i); i+=4;
	
	// pool coinbase tag
	if (i >= len) goto err;
	a = data[i]; i++;
	if (i + a > len) goto err;
	memcpy(datum_config.override_mining_coinbase_tag_primary, &data[i], a); i+=a;
	datum_config.override_mining_coinbase_tag_primary[a] = 0;
	
	if (i + 8 > len) goto err;
	datum_config.override_vardiff_min = upk_u64le(data, i); i+=8;
	if (datum_config.override_vardiff_min != roundDownToPowerOfTwo_64(datum_config.override_vardiff_min)) {
		DLOG_WARN("Server specified a minimum difficulty that is not a power of two! Is your client up to date? Rounding up to a power of two! (%"PRIu64" to %"PRIu64")", datum_config.override_vardiff_min, roundDownToPowerOfTwo_64(datum_config.override_vardiff_min)<<1);
		datum_config.override_vardiff_min = roundDownToPowerOfTwo_64(datum_config.override_vardiff_min)<<1;
	}
	
	if (i + 2 > len) goto err;
	if ((data[i] != 0) || (data[i+1] != 0xFE)) {
		DLOG_ERROR("Invalid data structure in configuration :(  Is this client up to date???");
		return 0;
	}
	
	memset(msg, 0, (datum_config.override_mining_pool_scriptsig_len<<1)+2);
	for(i=0;i<datum_config.override_mining_pool_scriptsig_len;i++) {
		uchar_to_hex(&msg[i<<1], datum_config.override_mining_pool_scriptsig[i]);
	}
	
	DLOG_DEBUG("DATUM Pool Payout Scriptsig: (len %d) %s",datum_config.override_mining_pool_scriptsig_len, msg);
	DLOG_DEBUG("DATUM Pool Coinbase Tag:     \"%s\"",datum_config.override_mining_coinbase_tag_primary);
	DLOG_DEBUG("DATUM Pool Prime ID:         %8.8lx", (unsigned long)datum_config.prime_id);
	DLOG_DEBUG("DATUM Pool Min Diff:         %"PRIu64,datum_config.override_vardiff_min);
	
	datum_state = 3; // fully ready to make work
	
	return 1;
}

int datum_protocol_job_validation_stxlist(unsigned char *data) {
	// similar to compact blocks, we're going to send a list of short transaction IDs for the requested job
	unsigned char job_index = data[0];
	T_DATUM_PROTOCOL_JOB *dj;
	T_DATUM_STRATUM_JOB *sj;
	T_DATUM_TEMPLATE_DATA *block_template;
	unsigned char msg[128*1024];
	uint64_t siphash;
	unsigned char siphash_key[16];
	unsigned char crosscheck[32] = { // starting point for the txn hash crosscheck
		0xA3, 0x4F, 0xC1, 0x9C, 0x5E, 0x88, 0x76, 0x12,
		0x0A, 0x79, 0x3E, 0xF1, 0x6C, 0x93, 0x54, 0xAF,
		0xB8, 0x1D, 0xE8, 0x5A, 0x20, 0xC7, 0x94, 0x38,
		0x6F, 0xA1, 0x02, 0xD9, 0x4A, 0x7B, 0xF0, 0x11
	};
	
	int i = 0, j;
	
	if (job_index >= 8) {
		// error response to 0x50 0x10
		msg[i] = 0x50; i++;
		msg[i] = 0x90; i++;
		msg[i] = 0xFF; i++;
		msg[i] = 0xF3; i++;
		
		// pad with some randomness
		j = 1 + (rand() % 100);
		memset(&msg[i], rand(), j);
		i+=j;
		
		datum_protocol_mining_cmd(msg, i);
		return 1;
	}
	
	pthread_rwlock_rdlock(&datum_jobs_rwlock);
	
	dj = &datum_jobs[job_index];
	
	sj = dj->sjob;
	if (!sj) {
		pthread_rwlock_unlock(&datum_jobs_rwlock);
		// error response to 0x50 0x10
		msg[i] = 0x50; i++;
		msg[i] = 0x90; i++;
		msg[i] = job_index; i++;
		msg[i] = 0xF0; i++;
		
		// pad with some randomness
		j = 1 + (rand() % 100);
		memset(&msg[i], rand(), j);
		i+=j;
		
		datum_protocol_mining_cmd(msg, i);
		
		return 1;
	}
	
	block_template = sj->block_template;
	if (!block_template) {
		pthread_rwlock_unlock(&datum_jobs_rwlock);
		// error response to 0x50 0x10
		msg[i] = 0x50; i++;
		msg[i] = 0x90; i++;
		msg[i] = job_index; i++;
		msg[i] = 0xF1; i++;
		
		// pad with some randomness
		j = 1 + (rand() % 100);
		memset(&msg[i], rand(), j);
		i+=j;
		
		datum_protocol_mining_cmd(msg, i);
		return 1;
	}
	
	if (block_template->txn_count == 0) {
		pthread_rwlock_unlock(&datum_jobs_rwlock);
		
		// there are no transactions in this block...
		// normal response, except our tx count is 0
		// since tx count = 0, we dont need anything else
		msg[i] = 0x50; i++;
		msg[i] = 0x90; i++;
		msg[i] = job_index; i++;
		msg[i] = 0x01; i++;
		msg[i++] = 0; msg[i++] = 0;
		
		// no need to send the crosscheck... there's nothing to crosscheck!
		
		// pad with some randomness
		j = 1 + (rand() % 100);
		memset(&msg[i], rand(), j);
		i+=j;
		
		datum_protocol_mining_cmd(msg, i);
		return 1;
	}
	
	if (block_template->txn_count > 16383) {
		pthread_rwlock_unlock(&datum_jobs_rwlock);
		// error response to 0x50 0x10
		msg[i] = 0x50; i++;
		msg[i] = 0x90; i++;
		msg[i] = job_index; i++;
		msg[i] = 0xF2; i++;
		
		// pad with some randomness
		j = 1 + (rand() % 100);
		memset(&msg[i], rand(), j);
		i+=j;
		
		datum_protocol_mining_cmd(msg, i);
		return 1;
	}
	
	// ok, we're good
	msg[i] = 0x50; i++;
	msg[i] = 0x90; i++;
	msg[i] = job_index; i++;
	msg[i] = 0x01; i++;
	pk_u16le(msg, i, block_template->txn_count); i += 2;
	
	// we don't have the benefit that compact blocks have of fully having something unknown to an attacker before an attack
	// like the block hash.  so we'll do the next best thing and use the client's public signing key mixed with the pool's
	// as the "key" for siphash
	for(j=0;j<16;j++) {
		siphash_key[j] = (local_datum_keys.pk_ed25519[j] ^ pool_keys.pk_ed25519[j]) ^ 0x55;
	}
	for(j=0;j<block_template->txn_count;j++) {
		siphash = datum_siphash_mod8(block_template->txns[j].hash_bin, 32, siphash_key);
		
		// store 48-bits of the hash in the message
		pk_u32le(msg, i, siphash & 0xFFFFFFFF); i += 4;
		pk_u16le(msg, i, (siphash >> 32) & 0xFFFF); i += 2;
		
		// keep a running xor of all hashes for a final crosscheck
		// not intended to be secure, but is fast enough for an initial server side pass/fail
		// should be virtually impossible, due to the search space, to attack anyway
		for (int k = 0; k < 0x20; ++k) crosscheck[k] ^= block_template->txns[j].hash_bin[k];
	}
	
	// we dont need the template data anymore, unlock!
	pthread_rwlock_unlock(&datum_jobs_rwlock);
	
	// cap off the message with the running XOR
	memcpy(&msg[i], &crosscheck[0], 0x20); i += 0x20;
	msg[i] = 0xFE; i++;
	
	// pad with some randomness
	j = 1 + (rand() % 111);
	memset(&msg[i], rand(), j);
	i+=j;
	datum_protocol_mining_cmd(msg, i); // let 'er rip
	
	DLOG_DEBUG("sent short txn list to server for job %d (%d bytes)",job_index,i);
	
	return 1;
}

int datum_protocol_job_validation_stxlist_byid(unsigned char *data) {
	// the server is requesting missing transactions
	// send them
	unsigned char job_index = data[0];
	uint16_t req_count = upk_u16le(data, 1);
	
	T_DATUM_PROTOCOL_JOB *dj;
	T_DATUM_STRATUM_JOB *sj;
	T_DATUM_TEMPLATE_DATA *block_template;
	unsigned char *msg = &temp_data[0]; // global temp var for constructing messages within the datum protocol thread
	uint16_t req_id;
	
	int i = 0, j,k=3;
	
	if (job_index >= 8) {
		// error response to 0x50 0x11
		msg[i] = 0x50; i++;
		msg[i] = 0x91; i++;
		msg[i] = 0xFF; i++;
		msg[i] = 0xF3; i++;
		
		// pad with some randomness
		j = 1 + (rand() % 100);
		memset(&msg[i], rand(), j);
		i+=j;
		
		datum_protocol_mining_cmd(msg, i);
		return 1;
	}
	
	pthread_rwlock_rdlock(&datum_jobs_rwlock);
	
	dj = &datum_jobs[job_index];
	
	sj = dj->sjob;
	if (!sj) {
		pthread_rwlock_unlock(&datum_jobs_rwlock);
		// error response to 0x50 0x11
		msg[i] = 0x50; i++;
		msg[i] = 0x91; i++;
		msg[i] = job_index; i++;
		msg[i] = 0xF0; i++;
		
		// pad with some randomness
		j = 1 + (rand() % 100);
		memset(&msg[i], rand(), j);
		i+=j;
		
		datum_protocol_mining_cmd(msg, i);
		
		return 1;
	}
	
	block_template = sj->block_template;
	if (!block_template) {
		pthread_rwlock_unlock(&datum_jobs_rwlock);
		// error response to 0x50 0x11
		msg[i] = 0x50; i++;
		msg[i] = 0x91; i++;
		msg[i] = job_index; i++;
		msg[i] = 0xF1; i++;
		
		// pad with some randomness
		j = 1 + (rand() % 100);
		memset(&msg[i], rand(), j);
		i+=j;
		
		datum_protocol_mining_cmd(msg, i);
		return 1;
	}
	
	if ((req_count == 0) || (req_count > block_template->txn_count)) {
		pthread_rwlock_unlock(&datum_jobs_rwlock);
		// error response to 0x50 0x11
		msg[i] = 0x50; i++;
		msg[i] = 0x91; i++;
		msg[i] = job_index; i++;
		msg[i] = 0xF4; i++;
		
		// pad with some randomness
		j = 1 + (rand() % 100);
		memset(&msg[i], rand(), j);
		i+=j;
		
		datum_protocol_mining_cmd(msg, i);
		return 1;
	}
	
	// ok, make it happen.
	msg[i] = 0x50; i++;
	msg[i] = 0x91; i++;
	msg[i] = job_index; i++;
	msg[i] = 0x01; i++;
	pk_u16le(msg, i, req_count); i += 2;
	
	for(j=0;j<req_count;j++) {
		req_id = upk_u16le(data, k); k += 2;
		
		if (req_id >= block_template->txn_count) {
			// error....
			pthread_rwlock_unlock(&datum_jobs_rwlock);
			// error response to 0x50 0x11
			i = 0; // reset index
			msg[i] = 0x50; i++;
			msg[i] = 0x91; i++;
			msg[i] = job_index; i++;
			msg[i] = 0xF4; i++;
			
			// pad with some randomness
			j = 1 + (rand() % 100);
			memset(&msg[i], rand(), j);
			i+=j;
			
			datum_protocol_mining_cmd(msg, i);
			return 1;
		}
		
		// size is stored as 3 bytes for consistency.
		// this is technically redundant, as the server can derive this by decoding the transaction
		// however, we're future-proofing just a little here for a tiny bit of overhead.
		pk_u16le(msg, i, ((uint32_t)(block_template->txns[req_id].size) & 0xFFFF)); i += 2;
		msg[i] = (uint16_t)((block_template->txns[req_id].size >> 16) & 0xFF); i++;
		memcpy(&msg[i], block_template->txns[req_id].txn_data_binary, block_template->txns[req_id].size);
		i += block_template->txns[req_id].size;
	}
	
	// done with the job.
	pthread_rwlock_unlock(&datum_jobs_rwlock);
	msg[i] = 0xFE; i++;
	
	// pad with some randomness
	j = 1 + (rand() % 111);
	memset(&msg[i], rand(), j);
	i+=j;
	datum_protocol_mining_cmd(msg, i); // let 'er rip
	
	DLOG_DEBUG("sent full txns to server for job %d (%d bytes for %d txns)",job_index,i,(int)req_count);
	
	return 1;
}

int datum_protocol_job_validation_sblock(unsigned char *data) {
	// the server decided our template probably is too unique from what it knows about, or was
	// otherwise not able to validate the block using faster negotiations.
	// It would like us to just send the entire transaction blob for validation as-is.
	// This is reasonable and required.  The server should already have the rest of the data needed
	// to construct a block to fully validate.
	
	unsigned char job_index = data[0];
	
	T_DATUM_PROTOCOL_JOB *dj;
	T_DATUM_STRATUM_JOB *sj;
	T_DATUM_TEMPLATE_DATA *block_template;
	unsigned char *msg = &temp_data[0]; // global temp var for constructing messages within the datum protocol thread
	
	int i = 0, j;
	
	if (job_index >= 8) {
		// error response to 0x50 0x12
		msg[i] = 0x50; i++;
		msg[i] = 0x92; i++;
		msg[i] = 0xFF; i++;
		msg[i] = 0xF3; i++;
		
		// pad with some randomness
		j = 1 + (rand() % 100);
		memset(&msg[i], rand(), j);
		i+=j;
		
		datum_protocol_mining_cmd(msg, i);
		return 1;
	}
	
	pthread_rwlock_rdlock(&datum_jobs_rwlock);
	
	dj = &datum_jobs[job_index];
	
	sj = dj->sjob;
	if (!sj) {
		pthread_rwlock_unlock(&datum_jobs_rwlock);
		// error response to 0x50 0x12
		msg[i] = 0x50; i++;
		msg[i] = 0x92; i++;
		msg[i] = job_index; i++;
		msg[i] = 0xF0; i++;
		
		// pad with some randomness
		j = 1 + (rand() % 100);
		memset(&msg[i], rand(), j);
		i+=j;
		
		datum_protocol_mining_cmd(msg, i);
		
		return 1;
	}
	
	block_template = sj->block_template;
	if (!block_template) {
		pthread_rwlock_unlock(&datum_jobs_rwlock);
		// error response to 0x50 0x12
		msg[i] = 0x50; i++;
		msg[i] = 0x92; i++;
		msg[i] = job_index; i++;
		msg[i] = 0xF1; i++;
		
		// pad with some randomness
		j = 1 + (rand() % 100);
		memset(&msg[i], rand(), j);
		i+=j;
		
		datum_protocol_mining_cmd(msg, i);
		return 1;
	}
	
	msg[i] = 0x50; i++;
	msg[i] = 0x92; i++;
	msg[i] = job_index; i++;
	msg[i] = 0x01; i++;
	pk_u16le(msg, i, block_template->txn_count); i += 2;
	
	for(j=0;j<block_template->txn_count;j++) {
		// size is stored as 3 bytes for consistency.
		// this is technically redundant, as the server can derive this by decoding the transaction
		// however, we're future-proofing just a little here for a tiny bit of overhead.
		// since the block data must be < 4MB, max 16384 txns, this adds at most 50KB, which fits in our 2^22 byte send max
		pk_u16le(msg, i, ((uint32_t)(block_template->txns[j].size) & 0xFFFF)); i += 2;
		msg[i] = (uint16_t)((block_template->txns[j].size >> 16) & 0xFF); i++;
		
		// dump the raw txn in
		memcpy(&msg[i], block_template->txns[j].txn_data_binary, block_template->txns[j].size);
		i += block_template->txns[j].size;
	}
	
	pthread_rwlock_unlock(&datum_jobs_rwlock);
	msg[i] = 0xFE; i++;
	// no random data here for size safety. this is also already expensive, potentially taking seconds to transmit.
	datum_protocol_mining_cmd(msg, i); // let 'er rip
	DLOG_DEBUG("sent full block of txns to server for job %d (%d bytes)",job_index,i);
	return 1;
}

int datum_protocol_job_validation_cmd(int len, unsigned char *data) {
	unsigned char cmd = data[0];
	unsigned char *p = data;
	
	if (len < 2) return 0;
	
	p++;
	
	// sub sub cmd
	switch (cmd) {
		case 0x10: {
			// send short txn list
			return datum_protocol_job_validation_stxlist(p);
			break;
		}
		
		case 0x11: {
			// send the requested txns
			// 16-bit indexes
			return datum_protocol_job_validation_stxlist_byid(p);
			break;
		}
		
		case 0x12: {
			// send the entire block, except the coinbase txn
			return datum_protocol_job_validation_sblock(p);
			break;
		}
		// TODO: Implement a job differences mechanism to save bandwidth on new work vs stxids
		
		default: break;
	}
	
	return 1;
}

// TODO: Ensure all shares are responded to!  Currently this has no bearing on anything, just logging
int datum_protocol_share_response(int len, unsigned char *data) {
	if (len < 9) {
		DLOG_DEBUG("Invalid share response received!");
		return 0;
	}
	if (data[0] == DATUM_POW_SHARE_RESPONSE_REJECTED) {
		DLOG_DEBUG("DATUM server rejected our share!  Reason code: %d / TargetPOT: %2.2x / Job ID: %d / Nonce: %8.8x",
		           (int)upk_u16le(data, 1),
		           data[7], (int)data[8], upk_u32le(data, 3));
		
		datum_rejected_share_count++;
		if (data[7] != 0xFF) {
			datum_rejected_share_diff += 1<<data[7];
		} else {
			datum_rejected_share_diff += datum_config.override_vardiff_min;
		}
		
		return 1;
	}
	
	if ((data[0] != DATUM_POW_SHARE_RESPONSE_ACCEPTED) && (data[0] != DATUM_POW_SHARE_RESPONSE_ACCEPTED_TENTATIVELY)) {
		DLOG_DEBUG("Unknown share response %2.2x.  Your client may need to be upgraded!", data[0]);
		return 1;
	}
	
	// share accepted
	DLOG_DEBUG("Share accepted: NONCE: %8.8lx / TargetPOT: %2.2x / Job ID: %d", (unsigned long)upk_u32le(data, 3),
	           data[7], (int)data[8]);
	
	datum_accepted_share_count++;
	datum_accepted_share_diff += 1<<data[7];
	datum_last_accepted_share_tsms = datum_protocol_mainloop_tsms;
	
	return 1;
}

// Main mining related command.  Has sub commands
int datum_protocol_mining_cmd5(T_DATUM_PROTOCOL_HEADER *h, unsigned char *data) {
	if (!h->cmd_len) return 0;
	
	switch(*data) {
		case 0x99: {
			if (!h->is_signed) {
				DLOG_ERROR("Received unsigned client configuration from DATUM server!");
				return 0;
			}
			return datum_protocol_client_configure(h->cmd_len-1, &data[1]);
			break;
		}
		case 0x11: {
			// Coinbaser response!
			return datum_protocol_coinbaser_fetch_response(h->cmd_len-1, &data[1]);
			break;
		}
		
		case 0x50: {
			// Job validation commands
			return datum_protocol_job_validation_cmd(h->cmd_len-1, &data[1]);
			break;
		}
		
		case 0x8F: {
			// share response
			return datum_protocol_share_response(h->cmd_len-1, &data[1]);
			break;
		}
		
		case 0xF9: {
			// Server says we should check for a new block template immediately
			DLOG_DEBUG("DATUM server blocknotify");
			datum_blocktemplates_notifynew(NULL, 0);
			return 1;
			break;
		}
		
		default: {
			DLOG_WARN("Received unknown mining command %2.2X from DATUM Server.  Perhaps you need to upgrade this DATUM Gateway?", *data);
			return 0;
		}
	}
	
	return 0;
}

int datum_protocol_send_hello(int sockfd) {
	T_DATUM_PROTOCOL_HEADER h;
	unsigned char hello_msg[1024];
	unsigned char enc_hello_msg[1024];
	int i = 0;
	int j;
	uint32_t nk;
	
	memset(&h, 0, sizeof(T_DATUM_PROTOCOL_HEADER));
	
	h.is_signed = true;
	h.is_encrypted_pubkey = true;
	h.proto_cmd = 1; // handshake init
	
	if (datum_encrypt_generate_keys(&session_datum_keys) != 0) {
		DLOG_FATAL("Could not generate our session keys!");
		return -1;
	}
	
	// send over a message that gives the server our encryption public key, our signing public key, our session encryption public key, and our session signing key.
	// we should sign this message with our signing public key, then seal it in a message to the server.
	// we should pad it with some random number of bytes also, not that the purpose is lost at the packet level here
	
	i = 0;
	memcpy(&hello_msg[i], local_datum_keys.pk_ed25519, crypto_sign_PUBLICKEYBYTES); i+=crypto_sign_PUBLICKEYBYTES;
	memcpy(&hello_msg[i], local_datum_keys.pk_x25519, crypto_box_PUBLICKEYBYTES); i+=crypto_box_PUBLICKEYBYTES;
	memcpy(&hello_msg[i], session_datum_keys.pk_ed25519, crypto_sign_PUBLICKEYBYTES); i+=crypto_sign_PUBLICKEYBYTES;
	memcpy(&hello_msg[i], session_datum_keys.pk_x25519, crypto_box_PUBLICKEYBYTES); i+=crypto_box_PUBLICKEYBYTES;
	
	strncpy((char *)&hello_msg[i], DATUM_PROTOCOL_VERSION, 127);
	hello_msg[i+127] = 0;
	i += strlen((char *)&hello_msg[i]);
	hello_msg[i] = '/'; i++;
	strncpy((char *)&hello_msg[i], GIT_COMMIT_HASH, 127);
	hello_msg[i+127] = 0;
	i += strlen((char *)&hello_msg[i]);
#ifdef BUILD_GIT_TAG
	hello_msg[i] = '('; i++;
	strncpy((char *)&hello_msg[i], BUILD_GIT_TAG, 127);
	hello_msg[i+127] = 0;
	i += strlen((char *)&hello_msg[i]);
	hello_msg[i] = ')'; i++;
#endif
	hello_msg[i] = 0; i++;
	
	hello_msg[i] = 0xFE; i++;
	
	// pick our initial sending_header_key
	hello_msg[i] = rand(); i++;
	hello_msg[i] = rand(); i++;
	hello_msg[i] = rand(); i++;
	hello_msg[i] = rand(); i++;
	
	nk = upk_u32le(hello_msg, i - 4);
	
	// TODO: maybe tack on other useful data here at some point
	// ...
	
	// pad with some randomness
	j = 1 + (rand() % 200);
	memset(&hello_msg[i], rand(), j);
	i+=j;
	
	// tack the signature on to the message
	DLOG_DEBUG("Signing handshake %d bytes",i);
	crypto_sign_detached(&hello_msg[i], NULL, hello_msg, i, local_datum_keys.sk_ed25519);
	i+=crypto_sign_BYTES;
	
	// seal it up
	crypto_box_seal(&enc_hello_msg[sizeof(T_DATUM_PROTOCOL_HEADER)], hello_msg, i, pool_keys.pk_x25519);
	i+=crypto_box_SEALBYTES;
	
	h.cmd_len = i;
	
	memcpy(enc_hello_msg, &h, sizeof(T_DATUM_PROTOCOL_HEADER));
	
	// apply our initial xor key to the header, just to obfuscate it a tiny bit
	// kinda pointless, but ok
	datum_xor_header_key(&enc_hello_msg[0], sending_header_key);
	
	DLOG_DEBUG("Sending handshake init (%d bytes)", h.cmd_len);
	
	// from here on out, we're going to send our headers to the server XOR'd with the header feedback mechanism for each header to protect that data
	// generally, packet alignment will help with some analysis, but overall can't be certain about values.
	sending_header_key = datum_header_xor_feedback(nk);
	receiving_header_key = datum_header_xor_feedback(~nk);
	
	// setup a somewhat deterministic nonce
	memset(session_nonce_receiver, 0, crypto_box_NONCEBYTES);
	nk -= 42;
	nk = nk ^ upk_u32le(session_datum_keys.pk_ed25519, 7);
	for(j=0;j<crypto_box_NONCEBYTES;j+=4) {
		pk_u32le(session_nonce_receiver, j, datum_header_xor_feedback(nk - 42));
		pk_u32le(session_nonce_sender, j, upk_u32le(session_nonce_receiver, j) ^ 0x57575757);
		nk = upk_u32le(session_nonce_receiver, j);
		nk = ~nk;
	}
	
	// FIXME: why is this mixed-endian?
	//DLOG_DEBUG("Session Nonce: %8.8X%8.8X%8.8X%8.8X%8.8X%8.8X", upk_u32le(session_nonce_receiver, 0), upk_u32le(session_nonce_receiver, 4), upk_u32le(session_nonce_receiver, 8), upk_u32le(session_nonce_receiver, 12), upk_u32le(session_nonce_receiver, 16), upk_u32le(session_nonce_receiver, 20));
	
	return datum_protocol_chars_to_server(enc_hello_msg, i+sizeof(T_DATUM_PROTOCOL_HEADER));
}

int datum_protocol_decrypt_sealed(T_DATUM_PROTOCOL_HEADER *h, unsigned char *data) {
	if (h->cmd_len < crypto_box_SEALBYTES) {
		DLOG_ERROR("Couldn't decrypt too-small DATUM command from server! (%d bytes)", h->cmd_len);
		return -1;
	}
	int i;
	memcpy(temp_data, data, h->cmd_len);
	// attempt to decode with our session key
	i = crypto_box_seal_open(data, temp_data, h->cmd_len, session_datum_keys.pk_x25519, session_datum_keys.sk_x25519);
	if (i!=0) {
		DLOG_ERROR("Couldn't decrypt DATUM command from server with our session key! (%d bytes)", h->cmd_len);
		return -1;
	}
	h->cmd_len -= crypto_box_SEALBYTES;
	return 1;
}

void datum_increment_session_nonce(void *s) {
	uint32_t *x = s;
	int i;
	
	for(i=0;i<crypto_box_NONCEBYTES;i+=4) {
		(*x)++;
		if (!(*x)) {
			x++;
		} else {
			return;
		}
	}
	return;
}

int datum_protocol_decrypt_standard(T_DATUM_PROTOCOL_HEADER *h, unsigned char *data) {
	if (h->cmd_len < crypto_box_MACBYTES) {
		DLOG_ERROR("Couldn't decrypt too-small DATUM command from server! (%d bytes)", h->cmd_len);
		return -1;
	}
	int i;
	// supposedly this can be done in place, according to docs!
	
	i = crypto_box_open_easy_afternm(data, data, h->cmd_len, session_nonce_receiver, session_precomp.precomp_remote);
	if (i!=0) {
		DLOG_ERROR("Couldn't decrypt DATUM command from server with our session key! (%d bytes)", h->cmd_len);
		return -1;
	}
	h->cmd_len -= crypto_box_MACBYTES;
	datum_increment_session_nonce(session_nonce_receiver);
	return 0;
}

int datum_protocol_compare_data(unsigned char *a, unsigned char *b, int len) {
	int i;
	for (i=0;i<len;i++) {
		if (a[i] != b[i]) return -1;
	}
	return 0;
}

int datum_protocol_handshake_response(T_DATUM_PROTOCOL_HEADER *h, unsigned char *data) {
	// already decrypted, and signature checked
	int i;
	char motd[512];
	
	if (!h->is_signed) {
		// handshake must have passed a sig check
		return -1;
	}
	
	i = 0;
	if (datum_protocol_compare_data(&data[i], local_datum_keys.pk_ed25519, crypto_sign_PUBLICKEYBYTES) != 0) {
		DLOG_WARN("Our public signing key echoed by the DATUM server did NOT match.");
		return -1;
	}
	i+=crypto_sign_PUBLICKEYBYTES;
	
	if (datum_protocol_compare_data(&data[i], local_datum_keys.pk_x25519, crypto_box_PUBLICKEYBYTES) != 0) {
		DLOG_WARN("Our public encryption key echoed by the DATUM server did NOT match.");
		return -1;
	}
	i+=crypto_box_PUBLICKEYBYTES;
	
	if (datum_protocol_compare_data(&data[i], session_datum_keys.pk_ed25519, crypto_sign_PUBLICKEYBYTES) != 0) {
		DLOG_WARN("Our session public signing key echoed by the DATUM server did NOT match.");
		return -1;
	}
	i+=crypto_sign_PUBLICKEYBYTES;
	
	if (datum_protocol_compare_data(&data[i], session_datum_keys.pk_x25519, crypto_box_PUBLICKEYBYTES) != 0) {
		DLOG_WARN("Our session public encryption key echoed by the DATUM server did NOT match.");
		return -1;
	}
	i+=crypto_box_PUBLICKEYBYTES;
	
	// ok, let's save the pool's session keys
	memcpy(session_remote_datum_keys.pk_ed25519, &data[i], crypto_sign_PUBLICKEYBYTES); i+=crypto_sign_PUBLICKEYBYTES;
	memcpy(session_remote_datum_keys.pk_x25519, &data[i], crypto_box_PUBLICKEYBYTES); i+=crypto_box_PUBLICKEYBYTES;
	
	// Server MOTD
	strncpy(motd, (char *)&data[i], 511);
	motd[511] = 0;
	
	session_remote_datum_keys.is_remote = true;
	
	datum_encrypt_prep_precomp(&session_remote_datum_keys, &session_datum_keys, &session_precomp);
	datum_state = 2; //we're handshaked with encryption setup!
	
	DLOG_DEBUG("Handshake response received.");
	DLOG_INFO("DATUM Server MOTD: %s", motd);
	
	return 1;
}

int datum_protocol_server_msg(T_DATUM_PROTOCOL_HEADER *h, unsigned char *data) {
	int i;
	//DLOG_DEBUG("Server msg: %d bytes cmd %d", h->cmd_len, h->proto_cmd);
	
	if ((h->is_encrypted_pubkey) && (!h->is_encrypted_channel)) {
		// this is a sealed message to our session pubkey
		// decrypt the message
		i = datum_protocol_decrypt_sealed(h, data);
		if (i < 0) {
			DLOG_ERROR("Could not decrypt sealed message from DATUM server!");
			return -1;
		}
	}
	
	if ((!h->is_encrypted_pubkey) && (h->is_encrypted_channel)) {
		// this is a message encrypted for our session
		i = datum_protocol_decrypt_standard(h, data);
		if (i < 0) {
			DLOG_ERROR("Could not decrypt standard message from DATUM server!");
			return -1;
		}
	}
	
	// message is decrypted by now
	if (h->is_signed) {
		if (h->cmd_len < crypto_sign_BYTES) {
			DLOG_ERROR("Could not validate too-small signature of message from server! (%d bytes)", h->cmd_len);
			return -1;
		}
		
		// validate the signature
		// if we're already handshaked, signatures are with the pool-side session key.  if not, they're with the pool's key
		if (datum_state >= 2) {
			i = crypto_sign_verify_detached(&data[h->cmd_len-crypto_sign_BYTES], data, h->cmd_len-crypto_sign_BYTES, session_remote_datum_keys.pk_ed25519);
		} else {
			i = crypto_sign_verify_detached(&data[h->cmd_len-crypto_sign_BYTES], data, h->cmd_len-crypto_sign_BYTES, pool_keys.pk_ed25519);
		}
		if (i!=0) {
			DLOG_ERROR("Could not validate signature of message from server! (%d bytes)", h->cmd_len);
			return -1;
		}
		
		// signature good... strip it!
		h->cmd_len -= crypto_sign_BYTES;
	}
	
	latest_server_msg_tsms = datum_protocol_mainloop_tsms;
	
	// NOTE: Keep in mind protocol command is limited to 5 bits
	switch(h->proto_cmd) {
		case 2: {
			// handshake response
			return datum_protocol_handshake_response(h, data);
		}
		
		case 5: {
			return datum_protocol_mining_cmd5(h, data);
		}
		
		case 7: {
			// display INFO in log
			if (h->cmd_len) {
				DLOG_INFO("DATUM Server message: %s", (char *)data);
			}
			return 1;
		}
		
		case 1: {
			// PING
			return datum_protocol_ping_response(h, data);
		}
		
		default: {
			DLOG_WARN("Unknown protocol command from server 0x%2.2x.  It this client up to date???", h->proto_cmd);
			return 1;
		}
	}
	
	return -1;
}

// Work submission multithreaded queue
DATUM_QUEUE pow_queue;

void datum_protocol_pow_queue_submits(void) {
	datum_queue_process(&pow_queue);
}

int datum_protocol_pow_submit(
	const T_DATUM_CLIENT_DATA *c,
	const T_DATUM_STRATUM_JOB *job,
	const char *username,
	const bool was_block,
	const bool subsidy_only,
	const bool quickdiff,
	const unsigned char *block_header,
	const uint64_t target_diff,
	const unsigned char *full_cb_tx,
	const T_DATUM_STRATUM_COINBASE *cb,
	unsigned char *extranonce,
	unsigned char coinbase_index)
{
	// called by other threads to submit new POW
	T_DATUM_PROTOCOL_POW pow;
	
	pow.datum_job_id = job->datum_job_idx;
	memcpy(pow.extranonce, extranonce, 12);
	strncpy(pow.username, username, 383);
	pow.username[383] = 0;
	pow.coinbase_id = coinbase_index;
	pow.subsidy_only = subsidy_only;
	pow.is_block = was_block;
	pow.quickdiff = quickdiff;
	pow.target_byte_index = job->target_pot_index; // just a sanity check on the server side. server hunts for this in the correct place anyway.
	pow.target_byte = full_cb_tx[job->target_pot_index];
	pow.ntime = upk_u32le(block_header, 68);
	pow.nonce = upk_u32le(block_header, 76);
	pow.version = upk_u32le(block_header, 0);
	
	//DLOG_DEBUG("ADD: DATUM POW: time %d nonce %8.8X", pow.ntime, pow.nonce);
	
	return datum_queue_add_item(&pow_queue, &pow);
}

// {"params": ["mzjP9Hn7aqaCLM5pSgMSQzgs3gnxSFv91B", "662599770700", "f40c000000000000", "66259976", "48220d13", "00d30000"], "id": 182, "method": "mining.submit"}
int datum_protocol_pow(void *arg) {
	T_DATUM_PROTOCOL_POW *pow = arg;
	T_DATUM_STRATUM_JOB *sjob;
	
	unsigned char msg[32768 + crypto_box_MACBYTES];
	int i = 0, j;
	bool w=false;
	// this is called when processing queued shares in our thread
	//DLOG_DEBUG("DATUM POW @ %p: time %d nonce %8.8X", pow, pow->ntime, pow->nonce);
	
	if ((pow->coinbase_id > 7) && (!(pow->coinbase_id == 0xff) && pow->subsidy_only)) {
		DLOG_ERROR("Could not process POW to DATUM server! Bad coinbase ID.");
		return 0;
	}
	
	msg[0] = 0x27; i++; // submit POW
	
	msg[i]=pow->datum_job_id; i++; // job ID 0
	msg[i]=pow->coinbase_id; i++; // which coinbase 1
	msg[i]=((pow->is_block?1:0)|(pow->subsidy_only?2:0)|(pow->quickdiff?4:0)); i++; // other flags that are useful for constructing the block header 2
	msg[i]=pow->target_byte; i++; // target byte we used for this work (PoT target diff) 3
	pk_u32le(msg, i, pow->ntime); i += 4;  // ntime 4
	pk_u32le(msg, i, pow->nonce); i += 4;  // nonce 8
	pk_u32le(msg, i, pow->version); i += 4;  // version 12
	msg[i] = 12; i++; // extranonce size... DO NOT CHANGE. Server support for other sizes is not likely any time soon.  But, planning ahead.  This should be plenty for everyone. :) 16
	memcpy(&msg[i], pow->extranonce, 12); i+=12; // extranonce1+2 17
	
	char * const username = (char *)&msg[i];
	if (((!datum_config.datum_pool_pass_full_users) && (!datum_config.datum_pool_pass_workers)) || pow->username[0] == '\0') {
		i+=snprintf(username, 385, "%s", datum_config.mining_pool_address);
	} else if (datum_config.datum_pool_pass_full_users && pow->username[0] != '.') {
		// TODO: Make sure the usernames are addresses, and if not use one of the configured addresses
		i+=snprintf(username, 385, "%s", pow->username);
	} else if (datum_config.datum_pool_pass_full_users || datum_config.datum_pool_pass_workers) {
		// append the miner's username to the configured address as .workername
		i+=snprintf(username, 385, "%s%s%s", datum_config.mining_pool_address, (pow->username[0] == '.') ? "" : ".", pow->username);
	}
	i++;  // already 0 from snprintf
	
	// reserve 4 bytes for future use
	memset(&msg[i], 0, 4); i+=4;
	
	pthread_rwlock_rdlock(&datum_jobs_rwlock);
	
	sjob = datum_jobs[pow->datum_job_id].sjob;
	if (!sjob) {
		pthread_rwlock_unlock(&datum_jobs_rwlock);
		return 0;
	}
	
	if (!datum_jobs[pow->datum_job_id].server_has_merkle_branches) {
		// we need to send the merkle branches with this job
		// also send the prevblockhash
		msg[i] = 0x01; i++;
		memcpy(&msg[i], sjob->prevhash_bin, 32); i+=32;
		pk_u16le(msg, i, pow->target_byte_index); i += 2; // target byte location in coinb1
		memcpy(&msg[i], &sjob->nbits_bin[0], sizeof(sjob->nbits_bin)); i += sizeof(sjob->nbits_bin); // nbits!
		msg[i] = sjob->datum_coinbaser_id; i++;
		pk_u32le(msg, i, sjob->height); i += 4;
		pk_u64le(msg, i, sjob->coinbase_value); i += 8;
		
		pk_u32le(msg, i, sjob->block_template->txn_count); i += 4;
		pk_u32le(msg, i, sjob->block_template->txn_total_weight); i += 4;
		pk_u32le(msg, i, sjob->block_template->txn_total_size); i += 4;
		pk_u32le(msg, i, sjob->block_template->txn_total_sigops); i += 4;
		
		msg[i] = sjob->merklebranch_count; i++;
		
		memcpy(&msg[i], &sjob->merklebranches_bin[0][0], sjob->merklebranch_count * 32);
		i+=sjob->merklebranch_count * 32;
		
		// switch us to a write lock
		pthread_rwlock_unlock(&datum_jobs_rwlock);
		pthread_rwlock_wrlock(&datum_jobs_rwlock);
		w = true;
		datum_jobs[pow->datum_job_id].server_has_merkle_branches = true;
	}
	
	if (pow->subsidy_only) {
		if (!datum_jobs[pow->datum_job_id].server_has_coinbase_empty) {
			msg[i] = 0x02; i++;
			msg[i] = 0xFF; i++; // subsidy only coinbase! yes, I know we specified above in the flags as well
			pk_u16le(msg, i, sjob->subsidy_only_coinbase.coinb1_len); i += 2;  // len1
			pk_u16le(msg, i, sjob->subsidy_only_coinbase.coinb2_len); i += 2;  // len2
			memcpy(&msg[i], sjob->subsidy_only_coinbase.coinb1_bin, sjob->subsidy_only_coinbase.coinb1_len);
			i+=sjob->subsidy_only_coinbase.coinb1_len;
			memcpy(&msg[i], sjob->subsidy_only_coinbase.coinb2_bin, sjob->subsidy_only_coinbase.coinb2_len);
			i+=sjob->subsidy_only_coinbase.coinb2_len;
			
			if (!w) {
				pthread_rwlock_unlock(&datum_jobs_rwlock);
				pthread_rwlock_wrlock(&datum_jobs_rwlock);
				w = true;
			}
			
			datum_jobs[pow->datum_job_id].server_has_coinbase_empty = true;
		}
	} else {
		if (!datum_jobs[pow->datum_job_id].server_has_coinbase[pow->coinbase_id]) {
			msg[i] = 0x02; i++;
			msg[i] = pow->coinbase_id; i++;
			pk_u16le(msg, i, sjob->coinbase[pow->coinbase_id].coinb1_len); i += 2;  // len1
			pk_u16le(msg, i, sjob->coinbase[pow->coinbase_id].coinb2_len); i += 2;  // len2
			memcpy(&msg[i], sjob->coinbase[pow->coinbase_id].coinb1_bin, sjob->coinbase[pow->coinbase_id].coinb1_len);
			i+=sjob->coinbase[pow->coinbase_id].coinb1_len;
			memcpy(&msg[i], sjob->coinbase[pow->coinbase_id].coinb2_bin, sjob->coinbase[pow->coinbase_id].coinb2_len);
			i+=sjob->coinbase[pow->coinbase_id].coinb2_len;
			
			if (!w) {
				pthread_rwlock_unlock(&datum_jobs_rwlock);
				pthread_rwlock_wrlock(&datum_jobs_rwlock);
				w = true;
			}
			
			datum_jobs[pow->datum_job_id].server_has_coinbase[pow->coinbase_id] = true;
		}
	}
	
	pthread_rwlock_unlock(&datum_jobs_rwlock);
	
	// cap message
	msg[i] = 0xFE; i++;
	
	// pad with some randomness
	// TODO: Make this dependant on the number of shares we have in our queue to submit, since they can share space in a packet further obfuscating the nature of the data
	j = 1 + (rand() % 80);
	memset(&msg[i], rand(), j);
	i+=j;
	
	datum_protocol_mining_cmd(msg, i);
	if ((datum_protocol_mainloop_tsms - datum_last_accepted_share_local_tsms) > 25000) {
		// we don't want to trigger a connection timeout just because we are mining very slowly...
		// so we'll fake this in that case.
		// There's better ways to do this, but we'll worry about those later
		// this is just a network hiccup kludge for now.
		datum_last_accepted_share_tsms = datum_protocol_mainloop_tsms;
	}
	datum_last_accepted_share_local_tsms = datum_protocol_mainloop_tsms;
	return 0;
}

bool datum_protocol_thread_is_active(void) {
	if (datum_protocol_client_active != 0) return true;
	return false;
}

bool datum_protocol_is_active(void) {
	if (datum_protocol_client_active == 3) return true;
	return false;
}

void *datum_protocol_client(void *args) {
	struct addrinfo hints, *res, *p;
	int sockfd = -1;
	int epollfd, nfds;
	int flag = 1;
#ifdef __linux__
	struct epoll_event ev, events[MAX_DATUM_CLIENT_EVENTS];
#elif  defined(__APPLE__) || defined(__BSD__)
	struct kevent ev, events[MAX_DATUM_CLIENT_EVENTS];
#endif

	struct timeval start, now;
	int ret,i,n;
	datum_protocol_client_active = 1;
	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	char port_str[7];  // To hold the port number as a string
	bool break_again = false;
	int sent = 0;
	T_DATUM_PROTOCOL_HEADER s_header;
	
	pthread_rwlock_wrlock(&datum_jobs_rwlock);
	for(i=0;i<MAX_DATUM_PROTOCOL_JOBS;i++) {
		datum_jobs[i].server_has_merkle_branches = false;
		datum_jobs[i].server_has_coinbase_empty = false;
		datum_jobs[i].server_has_short_txnlist = false;
		datum_jobs[i].server_has_validated_block = false;
		for(n=0;n<8;n++) {
			datum_jobs[i].server_has_coinbase[n] = false;
		}
	}
	pthread_rwlock_unlock(&datum_jobs_rwlock);
	pthread_mutex_lock(&datum_protocol_send_buffer_lock);
	sending_header_key = 0xDC871829;
	receiving_header_key = 0;
	protocol_state = 0;
	server_out_buf = 0;
	server_in_buf = 0;
	pthread_mutex_unlock(&datum_protocol_send_buffer_lock);
	datum_state = 0;
	memset(&s_header, 0, sizeof(T_DATUM_PROTOCOL_HEADER));
	
	// Note: The pool can not set a LOWER vardiff minimum than the client has set, so this is safe to use for that calculation.
	if (datum_queue_prep(&pow_queue, (datum_config.stratum_v1_max_clients_per_thread * datum_config.stratum_v1_vardiff_target_shares_min * (datum_config.stratum_v1_share_stale_seconds/60) * 16), sizeof(T_DATUM_PROTOCOL_POW), datum_protocol_pow) != 0) {
		DLOG_FATAL("Could not setup work submission queue!");
		datum_protocol_client_active = 0;
		return 0;
	}
	
	snprintf(port_str, sizeof(port_str)-1, "%d", datum_config.datum_pool_port);
	port_str[6] = 0;
	
	if ((ret = getaddrinfo(datum_config.datum_pool_host, port_str, &hints, &res)) != 0) {
		DLOG_ERROR("getaddrinfo: %s", gai_strerror(ret));
		datum_protocol_client_active = 0;
		return NULL;
	}
	
	for (p = res; p != NULL; p = p->ai_next) {
		if ((sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1) {
			DLOG_ERROR("socket(...) error: %s",strerror(errno));
			continue;
		}
		
		// Set socket to non-blocking
		int flags = fcntl(sockfd, F_GETFL, 0);
		if (flags == -1 || fcntl(sockfd, F_SETFL, flags | O_NONBLOCK) == -1) {
			DLOG_ERROR("fcntl(...) error: %s",strerror(errno));
			close(sockfd);
			sockfd = -1;
			continue;
		}
		
		// TCP_NODELAY!  Probably not needed since we group sends, but can't hurt.
		if (setsockopt(sockfd, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(int)) < 0) {
			DLOG_FATAL("setsockopt(TCP_NODELAY) failed: %s", strerror(errno));
			close(sockfd);
			sockfd = -1;
			continue;
		}
		
		// Start the connection process.
		gettimeofday(&start, NULL);
		while (1) {
			ret = connect(sockfd, p->ai_addr, p->ai_addrlen);
			if (ret == 0 || errno == EINPROGRESS) {
				break;  // Either connected immediately or in progress
			}
			
			if (errno != EINPROGRESS && errno != EALREADY) {
				DLOG_ERROR("connect(...) error: %s",strerror(errno));
				close(sockfd);
				sockfd = -1;
				continue;
			}
			
			// Check for timeout
			gettimeofday(&now, NULL);
			if (now.tv_sec - start.tv_sec >= DATUM_PROTOCOL_CONNECT_TIMEOUT) { // TODO: Make configurable
				DLOG_ERROR("Connection timed out!");
				close(sockfd);
				sockfd = -1;
				continue;
			}
			
			usleep(100000);  // Sleep 100ms before retrying
		}
		
		if (sockfd != -1) {
			break;  // Successfully connected
		}
	}
	
	freeaddrinfo(res);
	
	if (sockfd == -1) {
		DLOG_FATAL("Could not connect to DATUM server!");
		datum_protocol_client_active = 0;
		return NULL;
	}
	
	// Set up epoll
#ifdef __linux__
	if ((epollfd = datum_io_create(0)) == -1) {
#elif defined(__APPLE__) || defined(__BSD__)
	if ((epollfd = datum_io_create()) == -1) {
#endif

		DLOG_FATAL("epoll_create1(...) error: %s",strerror(errno));
		close(sockfd);
		datum_protocol_client_active = 0;
		return NULL;
	}

	if (datum_io_add(epollfd, sockfd, &ev) == -1) {
		DLOG_FATAL("epoll_ctl(...) error: %s",strerror(errno));
		close(sockfd);
		close(epollfd);
		datum_protocol_client_active = 0;
		return NULL;
	}

	i = 0;
	datum_last_accepted_share_tsms = 0;
	datum_last_accepted_share_local_tsms = 0;
	latest_server_msg_tsms = current_time_millis();
	
	while (1) {
		i++;
		
		datum_protocol_mainloop_tsms = current_time_millis();
		
		// Sanity check.  If we haven't received anything at all from the server in the set time, then it's pretty likely there's a connection issue.
		if ((datum_protocol_mainloop_tsms - latest_server_msg_tsms) >= datum_config.datum_protocol_global_timeout_ms) {
			// Pretty safe bet that the connection is dead.
			DLOG_WARN("No data received from server in over %d seconds.  Exiting protocol thread to retry.", datum_config.datum_protocol_global_timeout);
			break;
		}
		
		// Sanity check.  If we've been sending shares but getting no acceptance for > 30 seconds, something is wrong and we should fail and start over
		if ((datum_last_accepted_share_tsms != 0) && (datum_last_accepted_share_local_tsms != 0)) {
			if (datum_last_accepted_share_local_tsms > datum_last_accepted_share_tsms) {
				if ((datum_last_accepted_share_local_tsms - datum_last_accepted_share_tsms) >= 30000) {
					// no response to our latest share for > 30 seconds
					DLOG_WARN("No share acceptance response for > 30 seconds.  Exiting protocol thread to retry.");
					break;
				}
			}
		}
		
		// Queue up sends for PoW submissions
		datum_protocol_pow_queue_submits();
		
		pthread_mutex_lock(&datum_protocol_send_buffer_lock);
		if (server_out_buf) {
			sent = send(sockfd, server_send_buffer, server_out_buf, MSG_DONTWAIT);
			if (sent > 0) {
				if (sent < server_out_buf) {
					// not a full send. shift remaining data to beginning of w_buffer
					memmove(server_send_buffer, server_send_buffer + sent, server_out_buf - sent);
				}
				if (sent <= server_out_buf) {
					server_out_buf -= sent;
				} else {
					// should never happen
					server_out_buf = 0;
				}
			} else {
				if (!(errno == EAGAIN || errno == EWOULDBLOCK || errno == ENOTCONN)) {
					pthread_mutex_unlock(&datum_protocol_send_buffer_lock);
					break;
				}
			}
		}
		pthread_mutex_unlock(&datum_protocol_send_buffer_lock);
		
		break_again = false;
		// Basic state machine for connection setup
		switch(datum_state) {
			case 0: {
				// Hello, server!
				if (datum_protocol_send_hello(sockfd) < 0) {
					DLOG_FATAL("Error sending handshake start message.");
					break_again = true;
					break;
				}
				datum_state = 1;
				break;
			}
			
			case 1: {
				// waiting on server response
				// Global nothing-from-server timeout applies
				break;
			}
			
			case 2: {
				// we're online!
				datum_protocol_client_active = 2;
				break;
			}
			
			case 3: {
				// we're configured!
				datum_protocol_client_active = 3;
				break;
			}
			
			default: break;
		}
		
		if (break_again) break;

#ifdef __linux__
		int wait_ms = 5;
#elif defined(__APPLE__) || defined(__BSD__)
		int wait_ms = 5000;
#endif
		nfds = datum_io_wait(epollfd, events, MAX_DATUM_CLIENT_EVENTS, wait_ms);  // Wait for 5ms

		if (nfds == -1 && errno != EINTR) {
			DLOG_FATAL("epoll_wait(...) error: %s",strerror(errno));
			break;
		}
		
		if (nfds <= 0) {
			continue;  // Timeout, nothing happened
		}
#ifdef __linux__
		if (events[0].events & (EPOLLERR | EPOLLHUP)) {
#elif defined(__APPLE__) || defined(__BSD__)
		if (events[0].flags & EVFILT_EXCEPT) {
#endif

			int err = 0;
			socklen_t errlen = sizeof(err);
#ifdef __linux__
			int fd = events[0].data.fd;
#elif defined(__APPLE__) || defined(__BSD__)
			int fd = events[0].ident;
#endif
			if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &errlen) == 0) {
				if (err != 0) {
					DLOG_ERROR("Socket error: %s", strerror(err));
				} else {
					DLOG_ERROR("Socket hangup with no error.");
				}
			} else {
				DLOG_ERROR("Socket error, but failed to get the specific error: %s", strerror(errno));
			}
			break;
		}

#ifdef __linux__
		if (events[0].events & EPOLLIN) {
#elif defined(__APPLE__) || defined(__BSD__)
		if (events[0].flags & EV_ADD) {
#endif
			// data to receive
			break_again = false;
			// Receive the header, followed by any data specified by the header
			switch(protocol_state) {
				// order matters because of fall throughs
				case 1:
				case 2:
				case 3: {
					n = recv(sockfd, ((unsigned char *)&s_header) + (sizeof(T_DATUM_PROTOCOL_HEADER) - protocol_state), protocol_state, MSG_DONTWAIT);
					if (n <= 0) {
						if ((n < 0) && ((errno == EAGAIN || errno == EWOULDBLOCK))) {
							continue;
						}
						DLOG_DEBUG("recv() issue. protocol_state=%d, n=%d, errno=%d (%s)", protocol_state, n, errno, strerror(errno));
						break_again = true; break;
					}
					
					if ((n+(sizeof(T_DATUM_PROTOCOL_HEADER) - protocol_state)) != sizeof(T_DATUM_PROTOCOL_HEADER)) {
						if ((n+protocol_state) > 4) {
							DLOG_DEBUG("recv() issue. too many header bytes. protocol_state=%d, n=%d, errno=%d (%s)", protocol_state, n, errno, strerror(errno));
							break_again = true; break;
						}
						
						protocol_state = sizeof(T_DATUM_PROTOCOL_HEADER) - n - (sizeof(T_DATUM_PROTOCOL_HEADER) - protocol_state); // should give us a state equal to the number of. consoluted to show the process. (compiler optimizes)
						continue;
					}
					
					protocol_state = 4;
					continue; // cant fall through to 0, so loop around back to this to jump to 4
				}
				case 0: {
					n = recv(sockfd, &s_header, sizeof(T_DATUM_PROTOCOL_HEADER), MSG_DONTWAIT);
					if (n <= 0) {
						if ((n < 0) && ((errno == EAGAIN || errno == EWOULDBLOCK))) {
							continue;
						}
						DLOG_DEBUG("recv() issue. protocol_state=%d, n=%d, errno=%d (%s)", protocol_state, n, errno, strerror(errno));
						break_again = true; break;
					}
					if (n != sizeof(T_DATUM_PROTOCOL_HEADER)) {
						if (n > 4) {
							DLOG_DEBUG("recv() issue. too many header bytes (B). protocol_state=%d, n=%d, errno=%d (%s)", protocol_state, n, errno, strerror(errno));
							break_again = true; break;
						}
						protocol_state = sizeof(T_DATUM_PROTOCOL_HEADER)-n;
						continue;
					}
					
					protocol_state = 4;
					// Fall through to 4 now!
					[[fallthrough]];
				}
				
				case 4: {
					datum_xor_header_key(&s_header, receiving_header_key);
					//DLOG_DEBUG("Server CMD: cmd=%u, len=%u, raw = %8.8x ... rkey = %8.8x", s_header.proto_cmd, s_header.cmd_len, upk_u32le(s_header, 0), receiving_header_key);
					receiving_header_key = datum_header_xor_feedback(receiving_header_key);
					protocol_state = 5;
					server_in_buf = 0;
					if (!s_header.cmd_len) {
						// fall through to 5
						server_in_buf = 0;
					} else {
						n = recv(sockfd, server_recv_buffer, s_header.cmd_len, MSG_DONTWAIT);
						if (n <= 0) {
							if ((n < 0) && ((errno == EAGAIN || errno == EWOULDBLOCK))) {
								continue;
							}
							DLOG_DEBUG("recv() issue. protocol_state=%d, n=%d, errno=%d (%s)", protocol_state, n, errno, strerror(errno));
							break_again = true; break;
						}
						
						if (n > s_header.cmd_len) {
							DLOG_DEBUG("recv() issue. too many header bytes (C). protocol_state=%d, n=%d, errno=%d (%s)", protocol_state, n, errno, strerror(errno));
							break_again = true; break;
						}
						
						protocol_state = 5;
						server_in_buf = n;
						
						if (n < s_header.cmd_len) {
							continue;
						}
						
						// fall through to 5
					}
					[[fallthrough]];
				}
				
				case 5: {
					if (server_in_buf < s_header.cmd_len) {
						n = recv(sockfd, &server_recv_buffer[server_in_buf], s_header.cmd_len-server_in_buf, MSG_DONTWAIT);
						if (n <= 0) {
							if ((n < 0) && ((errno == EAGAIN || errno == EWOULDBLOCK))) {
								continue;
							}
							DLOG_DEBUG("recv() issue. protocol_state=%d, n=%d, errno=%d (%s)", protocol_state, n, errno, strerror(errno));
							break_again = true; break;
						}
						
						if (n+server_in_buf > s_header.cmd_len) {
							DLOG_DEBUG("recv() issue. too many data bytes. cmd_len=%d, server_in_buf=%d, protocol_state=%d, n=%d, errno=%d (%s)", s_header.cmd_len, server_in_buf, protocol_state, n, errno, strerror(errno));
							break_again = true; break;
						}
						
						server_in_buf += n;
						
						if (server_in_buf < s_header.cmd_len) {
							continue;
						}
					}
					
					if (server_in_buf == s_header.cmd_len) {
						n = datum_protocol_server_msg(&s_header, server_recv_buffer);
						if (n < 0) {
							DLOG_DEBUG("datum_protocol_server_msg returned %d",n);
							break_again = true; break;
						}
						protocol_state = 0;
						server_in_buf = 0;
						continue;
					}
					break;
				}
				
				default: {
					// Should never happen!
					DLOG_DEBUG("unknown protocol_state %d!",protocol_state);
					break_again = true;
					break;
				}
			}
			
			if (break_again) break;
		}
	}
	
	// Must clean up this thread, as it can be restarted by the main thread.
	DLOG_DEBUG("DATUM Protocol Thread is exiting.");
	close(sockfd);
	close(epollfd);
	datum_protocol_client_active = 0;
	datum_queue_free(&pow_queue);
	
	// Wait up to 5 seconds for another thread to reconnect
	for (i = 2000; i; --i) {
		if (datum_protocol_client_active >= 3) break;
		usleep(2500);
	}
	// ...then force a new job
	datum_blocktemplates_notify_othercause();
	
	return 0;
}

void datum_encrypt_log_pubkeys(DATUM_ENC_KEYS *keys) {
	char s[512];
	int i;
	
	for(i=0;i<crypto_sign_PUBLICKEYBYTES;i++) {
		uchar_to_hex(&s[i<<1], keys->pk_ed25519[i]);
	}
	s[i<<1] = 0;
	DLOG_INFO("Signing Public Key:     %s", s);
	
	for(i=0;i<crypto_box_PUBLICKEYBYTES;i++) {
		uchar_to_hex(&s[i<<1], keys->pk_x25519[i]);
	}
	s[i<<1] = 0;
	
	DLOG_INFO("Encryption Public Key:  %s", s);
}

void datum_protocol_start_connector(void) {
	pthread_t pthread_datum_protocol_client;
	
	if (!datum_protocol_client_active) {
		datum_protocol_client_active = 1; // no delay!
		DLOG_DEBUG("Starting DATUM " DATUM_PROTOCOL_VERSION " client...");
		if (pthread_create(&pthread_datum_protocol_client, NULL, datum_protocol_client, NULL) != 0) {
			DLOG_ERROR("Could not start thread for DATUM Protocol");
			datum_protocol_client_active = 0;
			return;
		}
		pthread_detach(pthread_datum_protocol_client);
	} else {
		DLOG_DEBUG("DATUM client already running.");
	}
}

int datum_protocol_init(void) {
	if (datum_config.datum_pool_host[0] == 0) {
		DLOG_WARN("****************************************************");
		DLOG_WARN("*** DATUM pool host is blank. NON-POOLED MINING! ***");
		DLOG_WARN("****************************************************");
		return 0;
	}
	
	if (sodium_init() < 0) {
		DLOG_FATAL("libsodium initialization failed");
		return -1;
	}
	
	memset(&local_datum_keys, 0, sizeof(DATUM_ENC_KEYS));
	memset(&pool_keys, 0, sizeof(DATUM_ENC_KEYS));
	memset(&session_datum_keys, 0, sizeof(DATUM_ENC_KEYS));
	
	if (datum_encrypt_generate_keys(&local_datum_keys) != 0) {
		DLOG_FATAL("Could not generate our keys");
		return -1;
	}
	
	DLOG_INFO("Our public keys:");
	datum_encrypt_log_pubkeys(&local_datum_keys);
	
	if (datum_pubkey_to_struct(datum_config.datum_pool_pubkey, &pool_keys) != 0) {
		DLOG_WARN("Pool pubkey not specified or invalid.");
		return -1;
	}
	pool_keys.is_remote = true;
	
	DLOG_INFO("Pool's public keys: (You should periodically verify that these are what you expect!)");
	datum_encrypt_log_pubkeys(&pool_keys);
	datum_protocol_start_connector();
	
	return 0;
}

int datum_encrypt_generate_keys(DATUM_ENC_KEYS *keys) {
	int i;
	
	// generate an Ed25519 key pair
	i = crypto_sign_keypair(keys->pk_ed25519, keys->sk_ed25519);
	if (i != 0) return i;
	
	// generate an X25519 key pair
	i = crypto_box_keypair(keys->pk_x25519, keys->sk_x25519);
	if (i != 0) return i;
	
	keys->is_remote = false;
	
	return 0;
}