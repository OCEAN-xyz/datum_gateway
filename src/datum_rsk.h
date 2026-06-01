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
 * Copyright (c) 2026 Bitcoin Ocean, LLC & Luke Dashjr
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

#ifndef _DATUM_RSK_H_
#define _DATUM_RSK_H_

#include "datum_conf.h"

struct T_DATUM_STRATUM_JOB;  // datum_stratum.h includes us, so it would be recursive

#define RSK_COMMITMENT_SIZE 0x20
#define RSK_TARGET_SIZE 0x20

// NOTE: First byte of RSK_COMMITMENT_OVERHEAD_HEX is the length of both the overhead (excluding that byte) and actual commitment in binary
#define RSK_COMMITMENT_OVERHEAD_HEX "2952534b424c4f434b3a"
#define RSK_COMMITMENT_OVERHEAD_SIZE (sizeof(RSK_COMMITMENT_OVERHEAD_HEX) / 2)

bool datum_rsk_init(const global_config_t *cfg);
void datum_rsk_get_current_work(char *out_rsk_commitment_hex_unterminated, uint8_t *out_target);
int datum_rsk_pow_submit(const struct T_DATUM_STRATUM_JOB *job, const unsigned char *block_header, const unsigned char *full_cb_txn, size_t full_cb_txn_len);

#endif
