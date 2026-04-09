# Documentation for the DATUM Gateway JSON API

## Decentralized client stats:

Endpoint: `/v1/decentralized_client_stats`

Result:

```
{
  "acceptedShares": 0,
  "acceptedSharesDiff": 0,
  "rejectedShares": 0,
  "rejectedSharesDiff": 0,
  "ready": true,
  "poolHost": "datum-beta1.mine.ocean.xyz",
  "poolTag": "DATUM Gateway",
  "minerTag": "DATUM User",
  "poolMinDiff": 0,
  "poolPubKey": "f21f2f0ef0aa1970468f22bad9bb7f4535146f8e4a8f646bebc93da3d89b1406f40d032f09a417d94dc068055df654937922d2c89522e3e8f6f0e649de473003",
  "uptime": 0
}
```

## Stratum server info:

Endpoint: `/v1/stratum_server_info`

```
{
  "activeThread": 0,
  "totalConnections": 0,
  "totalWorkSubscriptions": 0,
  "estimatedHashrate": 0.0
}
```

## Current stratum job:

Endpoint: `/v1/current_stratum_job`

```
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

```
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

```
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

HTTP auth is required.

```
{
  "0": {
    "0": {
      "remote_host": "::ffff:192.168.1.1",
      "auth_username": "S21",
      "subscribed": true,
      "sid": "b10cf00d",
      "sid_time": 73.42,
      "last_share": -1.0, // return -1 if no share has ever been sent
      "vdiff": 131072,
      "accepted_diff": 0,
      "accepted_count": 0,
      "rejected_diff": 0,
      "rejected_count": 0,
      "rejected_percentage": 0.0,
      "hash_rate": "313.37", // return N/A if no share has ever been sent
      "hash_rate_age": 2.5, // return -1 if no share has ever been sent
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
      "last_share": 2.5, // return -1 if no share has ever been sent
      "vdiff": 131072,
      "accepted_diff": 0,
      "accepted_count": 0,
      "rejected_diff": 0,
      "rejected_count": 0,
      "rejected_percentage": 0.0,
      "hash_rate": "313.37", // return "N/A" if no share has ever been sent
      "hash_rate_age": 2.5, // return -1 if no share has ever been sent
      "coinbase": "Respect",
      "useragent": "bitaxe/BM1366/v2.13.0"
    }
  }
}
```

## Configuration

Endpoint: `/v1/configuration`

HTTP auth is required for both `GET` and `POST` request.

`GET` method

```
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
  "always_pay_self": true,
  "work_update_seconds": 40,
  "rpcurl": "http://localhost:8332",
  "rpcuser": "test",
  "rpcpassword_set": true
}
```

`POST` method

```
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
  "always_pay_self": true,
  "work_update_seconds": 40,
  "rpcurl": "http://localhost:8332",
  "rpcuser": "test",
  "rpcpassword": "test"
}
```