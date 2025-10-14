## General

DATUM Gateway is designed with the assumption that pool usernames are generally Bitcoin addresses.
While it is *possible* to specify non-addresses in your miner, and pass those through to the pool, the default username in the Gateway itself (the `mining`.`pool_address` configuration option) must always be a valid Bitcoin address, and the Gateway will not fully start until it is set to one.

The rest of this document deals with Stratum usernames specifically, and how they are interpreted.

**Always test your full mining stack configuration.**
Misconfiguration of either the DATUM Gateway or your miners *can* result in lost work that is impossible to recover!

## Limitations

DATUM Gateway has a limit of 191 characters for Stratum usernames, including all special features specified by them.

Your miner likely has a lower limit.
For example,
Avalons truncate usernames at 63 characters;
Whatsminer has a buffer overflow (which may damage your miner) if you exceed 127;
and so on.

Some miners replace special characters (anything except alphanumeric, underscores, periods, and tildes) with hex codes (for example, `%` becomes `%25`), which can contribute toward reaching these limits and/or potentially confuse anything looking for them.

Note that Stratum usernames are *only* used for pooled mining.
When in non-pooled mode, they have no effect whatsoever, and only `mining`.`pool_address` is used to create blocks.

## Bitcoin address requirements (non-pooled mode)

This version of DATUM Gateway supports Base58 (aka Legacy), Bech32 (aka Segwit), and Bech32m (aka Taproot) addresses, for Bitcoin and Bitcoin testnet only.

It will not detect if you are using an address for the wrong network.

## Worker names

Immediately following the Bitcoin address, you may append a period (`.`) and an arbitrary worker name.
For compatibility, pools might also support an underscore (`_`) separator, but the DATUM Gateway codebase itself does not, and the period must be used to make use of Gateway features.

If the Stratum username *begins* with a period, it is interpreted as a worker name only, and appended to the Gateway's default username (`mining`.`pool_address`) before being sent to the pool.

## Passing usernames to the pool

There are three different ways to pass usernames to your pool.

By default, the Stratum username is always passed in full, as-is.
You can make this explicit by setting `datum`.`pool_pass_full_users` to `true` in the config file, or "Send Miner Usernames To Pool: Override Bitcoin Address" in the web configurator.

If you change `datum`.`pool_pass_full_users` to `false`, you can then set `datum`.`pool_pass_workers` instead (or "Send Miner Usernames To Pool: Send as worker names" in the web configurator).
With this setting, the entire Stratum username will be appended after the default username (`mining`.`pool_address`) as a worker.

Finally, if you set both options to `false`, the Stratum username will be ignored entirely.
Instead, only the configured default username (`mining`.`pool_address`) will be used, without any worker names.

## Username modifiers (advanced)

Some miners are in revenue sharing arrangements, and may wish to distribute a portion of their shares to different addresses.
While ideally this should be implemented in miner firmware, many miners today do not support it, so the DATUM Gateway provides it as an optional feature.
This is accomplished using "username modifiers".

In the `stratum` section of your configuration, add `username_modifiers` as a JSON object.
Example:

    "username_modifiers": {
        "modifier name 1": {
	        "bitcoin address A": 0.2,
	        "": 0.8
        },
        "modifier name 2": {
	        "bitcoin address B": 0.5,
	        "": 0.5
        },
        "modifier name 3": {
	        "bitcoin address C": 0.01,
	        "bitcoin address D": 0.99
        }
    }

This example defines three username modifiers, each named "modifier name 1" and so on, with differnent proportions.
The first redirects approximately 20% (`0.2`) of shares to "bitcoin address A", and 80% (`0.8`) to the address specified in the Stratum username (which is specified as simply `""`).
Similarly, the second defines a 50/50 split.
The third redirects 1% to "bitcoin address C", and 99% to "bitcoin address D"; note that the Stratum username's address does not receive *any* shares in that scenario.

To make use of a modifier, you must append a tilde (`~`) and the modifier name to your Stratum username.
For example, you might use "bitcoin address E.workername~modifier name 2".
This would send 20% of shares to the pool as username "bitcoin address A.workername" and 80% as "bitcoin address E.workername".
Regardless of what Bitcoin address is being used by a modifier, the worker name (if any) specified by the Stratum username is copied over as-is.

Be aware that this feature reassigns share submissions based on the proof-of-work hash.
If you specify 80%/20%, shares beginning with 0000-cccc will be directed toward the first address, and shares beginning with cccd-ffff will be sent as the second.
Since the hash is random, this may not be an exact split (though it should approach it over the long term).

Modifiers should always add up to 100%, and behaviour when they do not is undefined.
*Currently*, if you assign *less* than a full 100%, any shares which fall outside of the defined ranges will be submitted as the default username in `mining`.`pool_address` *without* the workername copied;
if you assign *more* than 100%, that portion above will not have any shares submitted
(the order of addresses may or may not be random).
Do not rely on these behaviours.
Always specify the full 100% range explicitly.

NOTE: This feature is handled when shares are received by the Gateway's Stratum server, and will therefore only work if you have `datum`.`pool_pass_full_users` enabled.
