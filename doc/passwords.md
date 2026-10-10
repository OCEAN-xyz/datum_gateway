## General

DATUM Gateway historically ignored the Stratum password entirely. It still does by
default. Reading it is opt-in:

```json
"stratum": {
	"password_difficulty": true
}
```

With `stratum`.`password_difficulty` left at its default of `false`, every password is
discarded exactly as before, including one that happens to look like a request, so
upgrading does not move any existing miner's difficulty. With it on, a password the
Gateway does not recognise is still discarded, so the near-universal filler `x`
continues to mean nothing.

What the password can now carry is a difficulty request. This exists because the
Stratum password is often the only field an operator can set. Rental marketplaces and
some firmware let you configure a pool host, port, worker name and password, and
nothing else; in particular they give you no way to make the miner negotiate the
`minimum-difficulty` extension of `mining.configure`, which is the mechanism a miner
would otherwise use to ask for this.

**Always test your full mining stack configuration.**
Misconfiguration of either the DATUM Gateway or your miners *can* result in lost work
that is impossible to recover!

## Syntax

The password is read as a list of `key=value` pairs separated by commas or semicolons.
Unrecognised keys are skipped rather than treated as an error, so a miner configured
for a newer Gateway still works against an older one, and vice versa.

| Key | Meaning |
| --- | --- |
| `d=N` | Start at difficulty `N`, and do not let vardiff drop below it. Vardiff may still raise it. |
| `fd=N` | Hold difficulty at exactly `N`. Vardiff is disabled for this connection. |

Examples:

```
d=4096
fd=1024
d=8192,someotherkey=ignored
```

The password applies to the connection it arrived on, and is read at
`mining.authorize`. Because `mining.subscribe` has already sent a difficulty by that
point, a miner that asks for one will see two `mining.set_difficulty` messages at the
start of the connection: the default, then the requested value.

## Why `d=` sets a floor and not just a starting point

Vardiff adjusts difficulty downward by halving, and clamps each step to a minimum. If
`d=` set only the starting difficulty, the first downward adjustment would clamp back
to `stratum`.`vardiff_min` and the request would quietly evaporate, which would make
the feature useless for precisely the small miners it exists to serve. So `d=` sets a
floor for that connection, replacing `stratum`.`vardiff_min` for it.

## Limits

Requested values are rounded down to a power of two, matching how vardiff steps. A
request of `d=5000` becomes 4096.

Three limits still apply, in the sense that a password cannot lower difficulty past
them:

- `stratum`.`vardiff_client_min` (default 1024) is the lowest difficulty any client
  may request. It exists so that a miner you do not control, pointed at your Gateway,
  cannot ask for difficulty 1 and bury you in shares. Lower it if you are testing with
  very small hashrate, such as on regtest.

  If `stratum`.`vardiff_min` is lower than this, that lower value applies instead. A
  Gateway configured to hand out difficulty 64 unasked has already accepted that load
  from every client, so there would be no sense in refusing to let one request it.
  Setting `vardiff_client_min` therefore only ever restricts requests below what the
  Gateway does by default, never above it.
- A miner fingerprinted as needing high difficulty keeps that requirement. This is a
  compatibility workaround for firmware known to misbehave lower, not a preference;
  set `stratum`.`fingerprint_miners` to false if you need to override it.
- In pooled mining, the pool's own declared minimum share difficulty applies. Shares
  below it would simply be rejected upstream, so the Gateway does not send work below
  it regardless of what the password asked for. This limit does not apply to non-pooled
  mining, where there is no upstream pool to reject anything.

Note that the password is *not* forwarded to the pool. It is consumed by the Gateway.
