# Documentation for the DATUM Gateway JSON API

## Access and authentication

The JSON API uses the dashboard's `api.listen_addr` and `api.listen_port`. It requires a build with API support, a nonzero listen port, and `api.json_api: true`. Examples below use port `7152`; replace the address and port to match your Gateway.

The statistics endpoints are readable without authentication, except `/v1/stratum_client_list`. That endpoint and `/v1/configuration` require a configured `api.admin_password` and HTTP Digest authentication. Use username `admin` and the configured password:

```bash
curl --fail --silent --show-error --digest --user admin \
  http://YOUR_GATEWAY_LAN_IP:7152/v1/stratum_client_list
```

`curl` prompts for the password, so it need not appear in the command or shell history. The same authentication options work for a `GET` of `/v1/configuration`. HTTP Digest authentication does not encrypt request or response bodies; fields such as `rpcpassword` sent in a JSON body remain visible over plain HTTP. Keep the API on a trusted network or access it through a private VPN. See [RFC 7616, section 5.3](https://www.rfc-editor.org/rfc/rfc7616.html#section-5.3).

Check response bodies for an `error` field as well as checking HTTP status. Some errors, including a missing current job or an unset admin password, are returned as JSON with HTTP status `200`.

## Decentralized client stats:

Endpoint: `/v1/decentralized_client_stats`

These counters describe responses from the DATUM pool, not local Stratum acceptance or wallet payouts. They accumulate for the lifetime of the Gateway process and reset on restart; a pool reconnect alone does not reset them. Treat a counter decrease or a process restart as a new measurement interval when calculating rates.

| Field | Meaning / unit |
| --- | --- |
| `acceptedShares`, `rejectedShares` | Counts of shares accepted or rejected by the pool. |
| `acceptedSharesDiff`, `rejectedSharesDiff` | Cumulative share difficulty accounted for by those responses, not share counts. |
| `poolMinDiff` | The pool's minimum share difficulty. |
| `poolHost` | Configured host and port, or `N/A` when no pool is configured. |
| `uptime` | Seconds since Gateway process startup. |

`ready` is `Ready` for active pooled mining, `Non-Pooled Mode and Ready` for ready non-pooled operation, or a status such as `Not Ready`, `Waiting for block template to be initialized`, or `Block template error`.

Result:

```json
{
  "acceptedShares": 0,
  "acceptedSharesDiff": 0,
  "rejectedShares": 0,
  "rejectedSharesDiff": 0,
  "ready": "Ready",
  "poolHost": "datum-beta1.mine.ocean.xyz:28915",
  "poolTag": "DATUM Gateway",
  "minerTag": "DATUM User",
  "poolMinDiff": 0,
  "poolPubKey": "f21f2f0ef0aa1970468f22bad9bb7f4535146f8e4a8f646bebc93da3d89b1406f40d032f09a417d94dc068055df654937922d2c89522e3e8f6f0e649de473003",
  "uptime": 0
}
```

## Stratum server info:

Endpoint: `/v1/stratum_server_info`

`activeThread` is the number of active Stratum threads. `totalConnections` and `totalWorkSubscriptions` are current counts, not cumulative totals. `estimatedHashrate` is the aggregate share-based estimate in **TH/s** (`1 TH/s = 10^12 hashes/second`); estimates older than 180 seconds are excluded.

```json
{
  "activeThread": 0,
  "totalConnections": 0,
  "totalWorkSubscriptions": 0,
  "estimatedHashrate": 0.0
}
```

## Current stratum job:

Endpoint: `/v1/current_stratum_job`

| Field | Meaning / unit |
| --- | --- |
| `block_height` | Height of the candidate block (normally the node's tip height plus one). |
| `block_value` | Available coinbase reward, in satoshis. |
| `time.current`, `time.minimum` | Unix timestamps in seconds, from the node's template. |
| `size`, `limits.size` | Bytes. |
| `weight`, `limits.weight` | Bitcoin weight units. |
| `sigops`, `limits.sigops` | Signature-operation cost units as reported by the template. |
| `tx_count` | Number of ordinary transactions in the template. |

The `size`, `weight`, `sigops`, and `tx_count` totals describe the template's ordinary transactions, excluding the Gateway's coinbase transaction. They are not final assembled-block totals. The `limits` object contains the node's template limits. If no job is available, the response contains an `error` instead of these fields.

```json
{
  "block_height": 939444,
  "block_value": 313097029,
  "previous_block": "000000000000000000008163708303bde1cb4d2971b64288a7203d82c6df5a87",
  "block_target": "00000000000000000001f3030000000000000000000000000000000000000000",
  "witness_commitment": "6a24aa21a9ed6b35c1269d98ac6b04bc8499b85710838ec2d5b8a54fb730363fc86a2f3d4c26",
  "block_difficulty": 144398401518101.0,
  "block_version": {
    "int": 536870912,
    "hex": "20000000"
  },
  "bits": "1701f303",
  "time": {
    "current": 1772727309,
    "minimum": 1772724401
  },
  "limits": {
    "size": 4000000,
    "weight": 4000000,
    "sigops": 80000
  },
  "size": 298988,
  "weight": 728012,
  "sigops": 2511,
  "tx_count": 622
}
```

## Coinbaser:

Endpoint: `/v1/coinbaser`

Output values are in **satoshis**. This is a view of outputs available for the current job, not a wallet balance or a history of payments.

```json
{
  "OP_RETURN": 0,
  "bc1qztuue9qkmj48zhwxww6rzqm3caz7xtg7kudnv2": 75716361,
  "bc1q7fkekg66yly2ynaew7t9gdvt8cut0p0drzf2q4": 27890098,
  "bc1q7ur9nh720up3syvhnmgtl7s885lnvffn8nkjry": 24959664,
  "1DwTRcse75MMiYxfyYGvErKAy2cUgpwhWc": 24477895,
  "bc1qpthfpk8aj45363s4gm4j4d5g67c7gsfaljuyshyj8f5cr0kww6wsqaf7qg": 15305970,
  "bc1q6f3ged3f74sga3z2cgeyehv5f9lu9r6p5arqvf44yzsy4gtjxtlsmnhn8j": 14055283,
  "bc1qauy6m9mgjtwqjrwllwszgzc4xzp3p9mnd75p5y": 10778836,
  "bc1q0a52shtqy27fmk4k6deauhz6qsu6q7x6n72jgp": 10766849,
  "bc1qh9rhekcgdmulrvxvhwfjpr9qejz4nahn8lf49v": 9442694,
  "bc1qpfu9c8qtxepx4g3rwcrzd3phexqkvqc2a0kyw3": 6626621,
  "bc1qjena63hace2unvhsj6g599w6eh0ns2anl760ef": 4803135,
  "bc1qfnlf63932nhxquz8d0swajdh8lmlnhdag5vldx": 3130752,
  "bc1qcc9255wz90tez5hx9c6uqva9va9nctse3gcv6lhszp990xvqsfjsdx2xn8": 2414045
}
```

## Thread stats:

Endpoint: `/v1/thread_stats`

Object keys identify Stratum threads. `connection_count` and `subscription_count` are current client counts. `approx_hashrate` is a share-based estimate in **TH/s**, excluding estimates older than 180 seconds.

```json
{
  "0": {
    "connection_count": 1,
    "subscription_count": 1,
    "approx_hashrate": 0.0
  },
  "1": {
    "connection_count": 1,
    "subscription_count": 1,
    "approx_hashrate": 0.0
  }
}
```

## Stratum client list:

Endpoint: `/v1/stratum_client_list`

HTTP Digest authentication is required; see the [request example](#access-and-authentication).

The outer object is keyed by thread ID, then client slot. Slots may be reused after disconnects. Share counters belong to the current client connection and reset when that client reconnects; they record local Gateway acceptance, independently of the pool counters above. An unsubscribed client has only its connection details and `subscribed: false`.

| Field | Meaning / unit |
| --- | --- |
| `sid_time` | Seconds since the client subscribed. |
| `last_share` | Seconds since its last accepted share, or `-1` if none. |
| `vdiff` | Current client share difficulty. |
| `accepted_count`, `rejected_count` | Share counts for this connection. |
| `accepted_diff`, `rejected_diff` | Cumulative accepted or rejected share difficulty for this connection. |
| `rejected_percentage` | Rejected difficulty as a percentage of total submitted difficulty; currently `0` until some work has been accepted. |
| `hash_rate` | Share-based estimate in **TH/s**, encoded as a string, or `N/A` before any accepted work. |
| `hash_rate_age` | Seconds since the sample used for the estimate, or `-1` before any accepted work. |

```json
{
  "0": {
    "0": {
      "remote_host": "::ffff:192.168.1.1",
      "auth_username": "S21",
      "subscribed": true,
      "sid": "b10cf00d",
      "sid_time": 73.42,
      "last_share": -1.0,
      "vdiff": 131072,
      "accepted_diff": 0,
      "accepted_count": 0,
      "rejected_diff": 0,
      "rejected_count": 0,
      "rejected_percentage": 0.0,
      "hash_rate": "N/A",
      "hash_rate_age": -1.0,
      "coinbase": "Respect",
      "useragent": ""
    }
  },
  "1": {
    "0": {
      "remote_host": "::ffff:192.168.1.2",
      "auth_username": "bitaxe",
      "subscribed": true,
      "sid": "b14cf00d",
      "sid_time": 67.77,
      "last_share": 2.5,
      "vdiff": 131072,
      "accepted_diff": 1310720,
      "accepted_count": 10,
      "rejected_diff": 0,
      "rejected_count": 0,
      "rejected_percentage": 0.0,
      "hash_rate": "313.37",
      "hash_rate_age": 2.5,
      "coinbase": "Respect",
      "useragent": "bitaxe/BM1366/v2.13.0"
    }
  }
}
```

## Configuration

Endpoint: `/v1/configuration`

HTTP Digest authentication is required for both `GET` and `POST` requests. Configuration changes also require `api.modify_conf: true`.

`work_update_seconds` is in seconds. `reward_sharing` is `require` for pooled-only mining, `prefer` for pooled mining with solo fallback, or `never` for explicit full solo mining.

The `GET` response reports whether an RPC password is set through `rpcpassword_set` and omits the password itself. A successful `POST` response echoes the submitted JSON fields, including `rpcpassword` if supplied. Do not log or share unredacted configuration request or response bodies; remove passwords and other sensitive fields first.

A `POST` request must additionally send the anti-CSRF token in an `X-DATUM-CSRF` header and use a `Content-Type` of `application/json`.
The token is returned by the `GET` method below (as `csrf_token`). It is generated randomly at Gateway startup, independently of `api.admin_password` and `api.listen_port`, and changes on each restart. After a restart, fetch the new token with `GET /v1/configuration` before sending further `POST` requests.

`GET` method

```json
{
  "pool_address": "bc1...",
  "miner_username_behavior": {
    "pool_pass_workers": true,
    "pool_pass_full_users": true
  },
  "coinbase_tag_secondary": "DATUM User",
  "coinbase_unique_id": 4242,
  "reward_sharing": "require",
  "pool": {
    "host": "datum-beta1.mine.ocean.xyz",
    "port": 28915,
    "pubkey": "f21f2f0ef0aa1970468f22bad9bb7f4535146f8e4a8f646bebc93da3d89b1406f40d032f09a417d94dc068055df654937922d2c89522e3e8f6f0e649de473003"
  },
  "fingerprint_miners": true,
  "vardiff_below_pool_min": false,
  "always_pay_self": true,
  "work_update_seconds": 40,
  "rpcurl": "http://localhost:8332",
  "rpcuser": "test",
  "rpcpassword_set": true,
  "csrf_token": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
}
```

`POST` method

```json
{
  "pool_address": "bc1...",
  "miner_username_behavior": {
    "pool_pass_workers": true,
    "pool_pass_full_users": true
  },
  "coinbase_tag_secondary": "DATUM User",
  "coinbase_unique_id": 4242,
  "reward_sharing": "require",
  "pool": {
    "host": "datum-beta1.mine.ocean.xyz",
    "port": 28915,
    "pubkey": "f21f2f0ef0aa1970468f22bad9bb7f4535146f8e4a8f646bebc93da3d89b1406f40d032f09a417d94dc068055df654937922d2c89522e3e8f6f0e649de473003"
  },
  "fingerprint_miners": true,
  "vardiff_below_pool_min": false,
  "always_pay_self": true,
  "work_update_seconds": 40,
  "rpcurl": "http://localhost:8332",
  "rpcuser": "test",
  "rpcpassword": "test"
}
```
