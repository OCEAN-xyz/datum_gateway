## General

A DATUM pool tells the Gateway a minimum share difficulty, and by default the Gateway raises every miner to it. That minimum can be far above what suits a small miner, which then finds a share only every few minutes. For a miner rented from a marketplace that matters: the marketplace measures delivered hashrate from accepted shares, so its reading turns choppy, the rig's owner is warned that the pool's difficulty is too high, and some marketplace proxies reconnect a pool that has gone a couple of minutes without accepting a share.

`stratum.vardiff_below_pool_min` lets each miner keep a difficulty that suits it, without changing what the pool receives:

```json
"stratum": {
	"vardiff_below_pool_min": true
}
```

It is off by default, and with it off miners are raised to the pool's minimum as before. It can also be switched on the Config page or through the JSON API, and applies from each connection's next job without a restart.

## What changes

For pooled work, every job now has two difficulties:

| | Set from | Used for |
| --- | --- | --- |
| Served | the miner's own vardiff | `mining.set_difficulty`, and the Gateway's local acceptance of the miner's shares |
| Committed | the served difficulty, but never below the pool's minimum | the coinbase target byte the pool checks a share against |

Without the option the two are always equal. With it, the served difficulty may be lower.

Every share that meets the served target is accepted, so the miner's delivered hashrate is measured accurately, and vardiff and the idle timeouts see its real share rate. Only shares that also meet the committed target are sent to the pool.

## Why the pool's credit is unchanged

Whether a hash meets the committed target does not depend on which difficulty the miner was asked for. The shares forwarded are exactly the ones a miner working at the committed difficulty would have found, with the same expected credit and the same variance. Blocks are among them, since a block meets any share target. The easier shares in between are kept by the Gateway, and each forwarded share carries the committed target, as before.

## Details

- A quickdiff job is still new work, made unique by the marker at the end of coinb1, and keeps the committed target. After a quickdiff committed at the pool minimum, a second one for the same job and coinbase with the same target byte (still below the minimum, or served exactly at it) would be the same work as the first, so the Gateway sends only the new difficulty and leaves the miner on its current work.
- Work that is not pooled has no pool minimum, so the two difficulties are equal.

## Changes that apply with the option off

These came with the same work and apply either way:

- Vardiff measures the rate at the difficulty it now serves. It starts measuring afresh whenever it sends a new difficulty, and a share that misses the difficulty now served is accepted but not counted toward the rate.
- A share for an older job, once a harder difficulty is served, is credited at the served difficulty if it meets it and at nothing otherwise.
- A share labelled as quickdiff is accepted only for the job its quickdiff notify was sent for.

## datum.capabilities

Tools that point miners at a Gateway can ask what it supports. This is not a Stratum standard method, and it needs no subscribe or authorize:

```
{"id":1,"method":"datum.capabilities","params":[]}
```

```json
{"error":null,"id":1,"result":{
	"gateway":"v0.5.1-beta",
	"features":{"vardiff_below_pool_min":true,"reject_tls_probe":true},
	"pooled":true,"pool_min_diff":1048576}}
```

A feature listed with `false` is supported but switched off. A Gateway without the method answers `Method not found`. There is no algorithm field: a DATUM Gateway works SHA256 only. `pool_min_diff` is the pool's current minimum, in `mining.set_difficulty` units, or `0` when not mining pooled. Send `"params":[]`: like any request without it, one that leaves it out makes the Gateway close the connection.

## TLS probes

The Gateway closes a connection when a read starts with the TLS handshake byte (`0x16`) and no partial line is pending, so a client probing for encrypted stratum fails fast instead of timing out.
