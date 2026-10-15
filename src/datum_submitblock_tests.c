/*
 *
 * DATUM Gateway
 * Decentralized Alternative Templates for Universal Mining
 *
 * This file is part of the DATUM Gateway and is distributed under the
 * same MIT license as the rest of the project. See LICENSE.
 *
 */

#include <jansson.h>

#include "datum_submitblock.h"
#include "datum_utils.h"

static datum_submitblock_status status_of(const char * const json_text) {
	json_t * const reply = json_loads(json_text, 0, NULL);
	datum_test(reply != NULL);
	const datum_submitblock_status st = datum_submitblock_reply_status(reply);
	json_decref(reply);
	return st;
}

void datum_submitblock_tests(void) {
	// The RPC helper hands back NULL for the null result the node sends on acceptance
	datum_test(datum_submitblock_reply_status(NULL) == DATUM_SUBMITBLOCK_ACCEPTED);
	datum_test(status_of("{\"result\":null,\"error\":null,\"id\":1}") == DATUM_SUBMITBLOCK_ACCEPTED);
	
	// Already have it and it is valid: the block is in the chain
	datum_test(status_of("{\"result\":\"duplicate\",\"error\":null,\"id\":1}") == DATUM_SUBMITBLOCK_DUPLICATE);
	
	// Every other string is a rejection, including the other duplicate-* forms
	datum_test(status_of("{\"result\":\"duplicate-invalid\",\"error\":null,\"id\":1}") == DATUM_SUBMITBLOCK_REJECTED);
	datum_test(status_of("{\"result\":\"duplicate-inconclusive\",\"error\":null,\"id\":1}") == DATUM_SUBMITBLOCK_REJECTED);
	datum_test(status_of("{\"result\":\"inconclusive\",\"error\":null,\"id\":1}") == DATUM_SUBMITBLOCK_REJECTED);
	datum_test(status_of("{\"result\":\"bad-txnmrklroot\",\"error\":null,\"id\":1}") == DATUM_SUBMITBLOCK_REJECTED);
	datum_test(status_of("{\"result\":\"prev-blk-not-found\",\"error\":null,\"id\":1}") == DATUM_SUBMITBLOCK_REJECTED);
	
	// A non-string result is not something to call success
	datum_test(status_of("{\"result\":true,\"error\":null,\"id\":1}") == DATUM_SUBMITBLOCK_REJECTED);
	datum_test(status_of("{\"result\":{\"x\":1},\"error\":null,\"id\":1}") == DATUM_SUBMITBLOCK_REJECTED);
}
