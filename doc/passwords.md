# Minimum difficulty requests

A miner can ask the Gateway to keep its share difficulty at or above a minimum. There
are two ways to ask:

- The `minimum-difficulty` extension of `mining.configure`, for miners whose firmware
  supports it. This is always honoured.
- `d=N` in the Stratum password, for miners that cannot send that extension. This is
  off unless you enable it.

Either way, a request can only **raise** a miner's difficulty. Nothing a miner sends
can take it below `stratum.vardiff_min`, so a miner cannot cost the Gateway more shares
than you already allow every miner.

## Why the password

The Stratum password is often the only field you can set. Rental marketplaces and some
firmware let you configure a pool host, port, worker name and password, and nothing
else, so there is no way to make the miner send `mining.configure`'s
`minimum-difficulty`. A rental marketplace typically judges a rental by the hashrate it
measures from accepted shares, so a renter may want each rig at a difficulty suited to
its size from the first job, rather than waiting for vardiff to get there.

DATUM Gateway historically ignored the password entirely, and still does by default.
Reading it is opt-in:

```json
"stratum": {
	"password_difficulty": true
}
```

With it left at the default of `false`, every password is discarded exactly as before,
including one that happens to look like a request, so upgrading does not move any
existing miner's difficulty.

**Always test your full mining stack configuration.**
Misconfiguration of either the DATUM Gateway or your miners *can* result in lost work
that is impossible to recover!

## Password syntax

The password is read as a list of `key=value` pairs separated by commas or semicolons.
`d=N` is the only key. Anything else is skipped rather than treated as an error, so the
near-universal filler `x`, and any other password already in use, means nothing.

```
d=65536
d=131072,someotherkey=ignored
```

The value must be a plain decimal number. The password is read once per connection, at
the first `mining.authorize`.

## What a request does

- **It rounds up** to a power of two, matching how vardiff steps, so a miner never gets
  less than it asked for. A request for 40000 becomes 65536.
- **Below `stratum.vardiff_min`, it becomes `stratum.vardiff_min`.**
- **It is a floor as well as a starting point.** The miner starts at the requested
  difficulty, vardiff may raise it from there, but vardiff will not take it back below
  the request.
- **The pool's minimum still applies.** When mining for a pool, the Gateway never sends
  a difficulty below the pool's own minimum, whatever was requested.
- **A miner fingerprinted as needing a high difficulty keeps it.** See
  `stratum.fingerprint_miners`.
- **Requests above 2^44 are ignored**, and the miner keeps ordinary vardiff. Because a
  request is also a floor, a mistyped huge value would otherwise leave the miner where
  it could never find a share. A miner at an exahash wants about 1.4e10 for a share a
  minute, far below this bound.

A miner that sends `mining.configure` with `minimum-difficulty` gets
`"minimum-difficulty": true` in the reply when the request was taken, and `false` when
the value was unusable.
