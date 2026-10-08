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
 * Copyright (c) 2024 Bitcoin Ocean, LLC & Jason Hughes
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

#ifndef _DATUM_SUBMITBLOCK_H_
#define _DATUM_SUBMITBLOCK_H_

#include <stdbool.h>
#include <jansson.h>

// What a submitblock reply means. The RPC helper returns NULL for the null
// result the node sends on acceptance, so NULL is "accepted" here.
typedef enum {
	DATUM_SUBMITBLOCK_ACCEPTED = 0,	// null result: the node took the block
	DATUM_SUBMITBLOCK_DUPLICATE,	// "duplicate": the node already had it, and it is valid
	DATUM_SUBMITBLOCK_REJECTED,		// anything else, including "duplicate-invalid"
} datum_submitblock_status;

datum_submitblock_status datum_submitblock_reply_status(const json_t *reply);
bool datum_submitblock_log_reply(const json_t *reply, const char *block_hash_hex);
void datum_submitblock_tests(void);

void datum_submitblock_init(void);
void datum_submitblock_trigger(const char *ptr, const char *hash);
void datum_submitblock_waitfree(void);

#endif
