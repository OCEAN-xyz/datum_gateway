# Installing and configuring DATUM Gateway

For the project overview, official upstream notice, and explanation of mining modes, see the [README](../README.md).

Choose an installation method, configure your Bitcoin Core node, then configure the Gateway and connect your miners. Pooled solo mining with shared rewards is recommended; full solo mining with no pool is also supported.

- [Requirements](#requirements)
- [OCEAN's Debian packages](#oceans-debian-packages)
- [Debian's official package](#debians-official-package)
- [DATUM box installer image](#datum-box-installer-image)
- [Building from source](#building-from-source)
- [Systemd service for source builds](#systemd-service-for-source-builds)
- [Node configuration](#node-configuration)
- [Gateway usage](#usage)
- [Pooled solo mining setup (recommended)](#pooled-solo-mining-setup-recommended)
- [Solo mining setup (no pool)](#solo-mining-setup-no-pool)
- [Verify it is working](#verify-it-is-working)
- [Optimization guide](OPTIMIZATIONS.md): share difficulty, bandwidth, and node peers
- [Docker](#docker)

## Requirements

 - Linux on a 64-bit AMD or Intel system (x86-64/amd64) is the recommended starting point.
 - Bitcoin full node ([Bitcoin Core](https://bitcoincore.org/en/download/) recommended) fully synced with the Bitcoin network.
 - Fast storage recommended for the Bitcoin node.
 - Stable internet connection for the Bitcoin node and, when pooling rewards, the Gateway's connection to the pool.
 - CPU powerful enough to run the Bitcoin node without validation delays.
 - Approximately 1 GB of RAM, plus 1 GB per 1,000 Stratum clients, plus Bitcoin node RAM requirements.
 - Bitcoin mining hardware able to reach the system running the DATUM Gateway.

The build and test CI also covers FreeBSD, including aarch64 (64-bit ARM) configurations. These are additional tested configurations; CI coverage does not establish production performance for every platform or device. OCEAN's Debian package instructions below specifically target Debian Trixie on amd64. Validate other configurations with your node and mining hardware before deploying them to a farm.

Use a stable system that can validate new blocks and deliver templates to the Gateway promptly. For maximum benefit, run Bitcoin Core, DATUM Gateway, and your miners on the same LAN.

No modifications to the Bitcoin node source code are required for the Gateway, as it uses the standard GBT mechanism for template fetch.

The following external libraries are required (installed automatically with OCEAN's Debian packages):

 - libcurl
 - libjansson
 - libmicrohttpd
 - libsodium

## Installation
Install DATUM Gateway using [OCEAN's Debian packages](#oceans-debian-packages), [Debian's official package](#debians-official-package), [build it from source](#building-from-source), or use [Docker](#docker). For a dedicated machine, the [DATUM box installer image](#datum-box-installer-image) installs Debian, Bitcoin Core, and DATUM Gateway together. You also need [Bitcoin Core](https://bitcoincore.org/en/download/), fully synced with the Bitcoin network. OCEAN's repository provides both packages. Full node setup and synchronization instructions are beyond the scope of this document.

After installation, complete [Node Configuration](#node-configuration) to enable RPC, reserve coinbase space, and arrange new-block notifications, then continue to [Usage](#usage).

### OCEAN's Debian packages

The following commands configure OCEAN's APT repository for **Debian Trixie on amd64** and install `datum-gateway` and `bitcoin-core`.

Install the tools needed to add the repository and import its signing key:

```bash
sudo apt update
sudo apt install ca-certificates curl gnupg
sudo install -d -m 0755 /etc/apt/keyrings
curl -fsSL https://apt.ocean.xyz/bootstrap/ocean.asc | sudo gpg --dearmor -o /etc/apt/keyrings/ocean.gpg
sudo chmod 0644 /etc/apt/keyrings/ocean.gpg
```

Create `/etc/apt/sources.list.d/ocean.sources`:

```bash
sudo tee /etc/apt/sources.list.d/ocean.sources > /dev/null <<'EOF'
Types: deb
URIs: https://apt.ocean.xyz/public/bitcoin
Suites: trixie
Components: main
Architectures: amd64
Signed-By: /etc/apt/keyrings/ocean.gpg
EOF
```

Refresh the package index and install both packages:

```bash
sudo apt update
sudo apt install datum-gateway bitcoin-core
```

Complete the package configuration prompts, including your Bitcoin reward address. Debian's default `debconf` priority is `high`, so installation may skip less urgent settings. To review all configuration prompts, use `dpkg-reconfigure`, which defaults to `low` priority:

```bash
sudo dpkg-reconfigure bitcoin-core datum-gateway
```

This lets you configure both packages interactively and restarts the affected services. The packaged Gateway uses `/etc/datum-gateway/datum_gateway_config.json` and the `datum-gateway` service; Bitcoin Core's configuration is `/etc/bitcoin/bitcoin.conf`. Review [Node Configuration](#node-configuration) and [Usage](#usage), and allow Bitcoin Core to fully sync before mining. You can also edit the configuration files directly; after editing the Gateway configuration, restart it with:

```bash
sudo systemctl restart datum-gateway
```

Package installation includes the runtime dependencies; you can skip the source-build instructions below.

### Debian's official package

DATUM Gateway is also available in Debian's own repositories. Check the [Debian package tracker](https://tracker.debian.org/pkg/datum-gateway) for current versions and supported suites and architectures. These packages follow Debian's release and update schedule, so their version may differ from OCEAN's repository or the latest upstream release.

On Debian Trixie, after [enabling trixie-backports](https://backports.debian.org/Instructions/), install the Gateway with:

```bash
sudo apt update
sudo apt install -t trixie-backports datum-gateway
```

On a Debian suite that includes the package directly, use `sudo apt install datum-gateway`. The Debian package installs runtime dependencies and a `datum-gateway` service, with configuration at `/etc/datum-gateway/datum_gateway_config.json`. Review its prompts with `sudo dpkg-reconfigure datum-gateway`.

Install and configure Bitcoin Core separately, then complete [Node Configuration](#node-configuration) and [Usage](#usage). The Gateway needs your node's RPC URL and either a readable RPC cookie or matching RPC credentials. The two-package `dpkg-reconfigure bitcoin-core datum-gateway` command above applies when both packages are installed from OCEAN's repository.

### DATUM box installer image

The [DATUM box installer project](https://github.com/OCEAN-xyz/preseed-debian) provides an automated Debian Trixie installer that installs Bitcoin Core and DATUM Gateway from OCEAN's APT repository. Download an image for your machine's architecture from its [releases](https://github.com/OCEAN-xyz/preseed-debian/releases), or follow the project's instructions to build an image with your reward address and SSH public key configured.

**The installer automatically selects the largest disk and repartitions it, erasing existing data.** Use it on a dedicated machine with that disk intended for installation, and back up any data you need before booting the image.

The default username is `box` and the password is `datumbox`. You will be prompted to change the password on first login; follow the installer project's first-login instructions.

After installation, review the [package configuration](#oceans-debian-packages), [Node Configuration](#node-configuration), and [Usage](#usage), allow Bitcoin Core to fully sync, and complete the [verification checklist](#verify-it-is-working) before connecting the rest of your miners.

### Building from source

Install Git, a C compiler and build tools, and the required development packages: cmake, pkgconf, libcurl, jansson, libsodium, and libmicrohttpd. You may also need psmisc for your node to send blocknotify signals to the DATUM Gateway.

For Debian/Ubuntu:

    sudo apt install git build-essential cmake pkgconf libcurl4-openssl-dev libjansson-dev libsodium-dev libmicrohttpd-dev psmisc

For Fedora/Amazon Linux:

    sudo dnf install git gcc make cmake pkgconf libcurl-devel jansson-devel libsodium-devel libmicrohttpd-devel psmisc

For Alma Linux:

    sudo dnf install epel-release dnf-plugins-core
    sudo dnf config-manager --set-enabled crb
    sudo dnf install git gcc make cmake pkgconf libcurl-devel jansson-devel libsodium-devel libmicrohttpd-devel psmisc

For Oracle Linux:

    sudo dnf install epel-release dnf-plugins-core
    sudo dnf config-manager --set-enabled ol9_codeready_builder
    sudo dnf install git gcc make cmake pkgconf libcurl-devel jansson-devel libsodium-devel libmicrohttpd-devel psmisc

For Alpine (also needs a standalone argp library):

    sudo apk add git build-base cmake pkgconf argp-standalone curl-dev jansson-dev libsodium-dev libmicrohttpd-dev psmisc

For Arch:

    sudo pacman -Syu git base-devel cmake pkgconf curl jansson libsodium libmicrohttpd psmisc

For FreeBSD:

    sudo pkg install git cmake pkgconf curl jansson libsodium libmicrohttpd argp-standalone libepoll-shim

Clone the official upstream repository, enter its directory, and compile DATUM:

```bash
git clone https://github.com/OCEAN-xyz/datum_gateway.git
cd datum_gateway
cmake .
cmake --build .
```

The executable is `./datum_gateway`. Continue with [Node Configuration](#node-configuration) and [Usage](#usage); the source-build examples below assume you are in this repository directory.

#### Separate build directory and installation prefix

Alternatively, keep build files in a separate directory and install the executable and documentation under a chosen prefix. From the cloned repository root, with CMake 3.15 or later:

```bash
cmake -S . -B build -DCMAKE_INSTALL_PREFIX=/opt/datum_gateway
cmake --build build
sudo cmake --install build
```

The executable is then `/opt/datum_gateway/bin/datum_gateway`. Replace `/opt/datum_gateway` with your preferred installation prefix; `sudo` is needed only when installing to a directory your user cannot write. Installation does not create a configuration file or service. For a foreground run, copy and edit the example as described under [Usage](#usage), then run from the repository root:

```bash
/opt/datum_gateway/bin/datum_gateway -c datum_gateway_config.json
```

For automatic startup, use the service example below.

### Systemd service for source builds

On a Linux system using systemd, this example runs a source build installed under `/opt/datum_gateway`. It assumes your Bitcoin Core node already runs as user and group `bitcoin`; replace both with your node's actual user and group. Running as the node's user permits local RPC cookie access and the `killall -USR1 datum_gateway` block notification described under [Node Configuration](#node-configuration).

From the repository root, create a private configuration directory and copy the example for a new installation. If you already have a configuration file, use that file instead of overwriting it with the example:

```bash
sudo install -d -o bitcoin -g bitcoin -m 0750 /etc/datum-gateway
sudo install -o bitcoin -g bitcoin -m 0600 doc/example_datum_gateway_config.json /etc/datum-gateway/datum_gateway_config.json
sudoedit /etc/datum-gateway/datum_gateway_config.json
```

Complete [Node Configuration](#node-configuration) and your chosen mining setup under [Usage](#usage) before starting the service. Set your reward address, RPC authentication, coinbase tags, and a secure admin password. Use an absolute path for `bitcoind.rpccookiefile` when using cookie authentication, and ensure the service user can read it. Keep `logger.log_to_console` enabled to send logs to the journal.

Create `/etc/systemd/system/datum_gateway.service` with the following contents, adjusting `User`, `Group`, and the executable path to match your installation:

```ini
[Unit]
Description=DATUM Gateway
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=bitcoin
Group=bitcoin
ExecStart=/opt/datum_gateway/bin/datum_gateway -c /etc/datum-gateway/datum_gateway_config.json
WorkingDirectory=/var/lib/datum-gateway
StateDirectory=datum-gateway
StateDirectoryMode=0750
UMask=0077
Restart=on-failure
RestartSec=30
TimeoutSec=600
LimitNOFILE=65535
NoNewPrivileges=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths=/etc/datum-gateway

[Install]
WantedBy=multi-user.target
```

Systemd creates `/var/lib/datum-gateway` for the service user. The configuration directory remains writable so dashboard changes can be saved when `api.modify_conf` is enabled; its ownership and permissions above allow the Gateway to create and rename the replacement configuration file. Home directories remain readable for a node's RPC cookie. If you enable file logging, use an absolute path under `/var/lib/datum-gateway`, or explicitly allow another log directory in the unit and make it writable by the service user.

Enable the service and check its status and logs:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now datum_gateway
sudo systemctl status datum_gateway --no-pager
sudo journalctl -u datum_gateway -n 100 --no-pager
```

After editing the configuration or installing a new build, apply the change with `sudo systemctl restart datum_gateway`, then complete the [verification checklist](#verify-it-is-working). This source-build service uses the name `datum_gateway`; Debian packages use `datum-gateway`. Use the service name that matches your installation in the status, restart, and journal commands elsewhere in this guide. Run only one Gateway instance on a given set of listening ports.

## Node Configuration

Configure Bitcoin Core to provide block templates to the Gateway through RPC (`getblocktemplate`). The settings below require **Bitcoin Core 29.0 or later**, which supports `blockreservedweight`. Add them to your `bitcoin.conf` and restart the node after making changes.

Enable the RPC server and reserve room for the pool's generation (coinbase) transaction:

    server=1
    blockmaxweight=4000000
    blockreservedweight=66000

The `blockmaxweight` setting allows the final block to approach Bitcoin's 4,000,000-weight-unit limit. Bitcoin Core subtracts `blockreservedweight` from this budget before selecting ordinary transactions. Setting it to 66,000 replaces Core's default 8,000-weight-unit reservation and accommodates DATUM's largest coinbase size budget of **16,000 bytes** (64,000 weight units before witness data), with room for witness data, the block header, transaction count, and a small safety margin. DATUM uses this reserved space when assembling the final block and reward split; there is no need to also lower `blockmaxweight` for this reservation.

To avoid mining stale work, you will need to ensure the DATUM Gateway receives new block notifications from your node. It is suggested you run the DATUM Gateway as the same user as your full node and utilize the following configuration line in your bitcoin.conf:

    blocknotify=killall -USR1 datum_gateway

Ensure you have "killall" installed on your system (*psmisc* package on many OSs).

If the node and Gateway are on different systems, use the [HTTP notification setup](#block-notifications-between-separate-machines) below.

The Gateway must have authenticated RPC access to your node. Configure `bitcoind.rpccookiefile` for a local RPC cookie, or `bitcoind.rpcuser` and `bitcoind.rpcpassword` to match your node's RPC credentials. OCEAN's Debian package configures local cookie authentication. If the node is on another machine, restrict RPC access to the Gateway.

If your system has sufficient RAM, you can optionally increase the mempool size:

    maxmempool=1000

This lets your node retain more transactions that meet its policies for inclusion in block templates. Leave `blockreconstructionextratxn` at Bitcoin Core's default; DATUM does not require an enlarged compact-block reconstruction cache.

### Block notifications between separate machines

When Bitcoin Core and the Gateway run on separate machines, have the node call the Gateway's `/NOTIFY` endpoint on each new block. The Gateway then fetches the current template through its configured RPC connection. Keep both machines on the mining LAN where possible.

On the Gateway, enable the dashboard listener and bind it to its LAN address. Merge this excerpt into the existing `api` section, replacing `YOUR_GATEWAY_LAN_IP` with the Gateway's actual local IP address and preserving your secure `api.admin_password`:

```json
{
  "api": {
    "listen_addr": "YOUR_GATEWAY_LAN_IP",
    "listen_port": 7152
  }
}
```

Restart the Gateway after applying the settings. Source builds need API support (`ENABLE_API=ON`, the build default). `/NOTIFY` does not depend on `api.json_api` being enabled.

Install `curl` on the Bitcoin node machine. In that node's `bitcoin.conf`, replace the local `killall` notification command with:

```ini
blocknotify=/usr/bin/curl -fsS --connect-timeout 2 --max-time 5 --output /dev/null http://YOUR_GATEWAY_LAN_IP:7152/NOTIFY
```

Replace the host and port to match the Gateway, and use the path returned by `command -v curl` if it differs from `/usr/bin/curl`. Restart Bitcoin Core after changing `bitcoin.conf`. The command runs as the node's service user, which must be able to execute `curl` and reach the Gateway.

**`/NOTIFY` does not require authentication.** Restrict the dashboard port to the Bitcoin node and trusted administration hosts using your firewall. The admin password protects administrative actions; it does not protect this notification endpoint.

From the Bitcoin node machine, check reachability with:

```bash
curl -fsS --connect-timeout 2 --max-time 5 http://YOUR_GATEWAY_LAN_IP:7152/NOTIFY
```

Expect an `OK` response. This verifies that the notification reached the Gateway; it does not prove RPC access or template freshness. Next, watch an actual new block and complete the [verification checklist](#verify-it-is-working). You can leave `bitcoind.notify_fallback` at its default `true` as a backup poller; prompt HTTP notifications should be the normal path.

## Usage

Run the `datum_gateway` executable with the `-?` flag for detailed configuration information, descriptions, and required options. Then construct a configuration file (defaults to `datum_gateway_config.json` in the current working directory). Be sure to also set your coinbase tags. The primary tag setting is unused in pooled mining; however, the secondary tag is intended to show on things like block explorers when you mine a block.

There is an [example configuration file included in the doc/ directory](example_datum_gateway_config.json) you may wish to use as a template.
Set a secure `api.admin_password` to protect administrative actions, or disable the API/web interface entirely.

You should review the [documentation on usernames](usernames.md) next.
If your miners need to run above the difficulty vardiff picks for them, see the [documentation on minimum difficulty requests](passwords.md).
Once you have everything running, you can point miners at the Gateway.

### Pooled solo mining setup (recommended)

Complete [Node Configuration](#node-configuration) first. This walkthrough connects to OCEAN using the default username behavior: enter your Bitcoin reward address in each ASIC's username, optionally followed by a worker name. Rewards follow the pool's reward system and payout rules; your miners do not need to find a block themselves to qualify for shared rewards.

For OCEAN's Debian package, edit `/etc/datum-gateway/datum_gateway_config.json`, preserving the RPC authentication and admin password configured by the package. For a source build, copy the example from the repository root and edit it:

```bash
cp doc/example_datum_gateway_config.json datum_gateway_config.json
```

Set the `bitcoind` RPC connection and credentials for your node, and set a secure `api.admin_password` if using the dashboard. Apply this excerpt to the existing `mining` and `datum` sections, keeping your other settings:

```json
{
  "mining": {
    "pool_address": "REPLACE_WITH_YOUR_BITCOIN_MAINNET_ADDRESS",
    "coinbase_tag_secondary": "My Mining Farm"
  },
  "datum": {
    "pool_host": "datum-beta1.mine.ocean.xyz",
    "pool_port": 28915,
    "pool_pass_full_users": true,
    "pool_pass_workers": true,
    "pooled_mining_only": true
  }
}
```

Use a Bitcoin mainnet address you control for `mining.pool_address`. The host and port above are this release's built-in OCEAN defaults. Leave `datum.pool_pubkey` unset to use the bundled OCEAN public key; if switching from another pool, remove its key override. For another DATUM-compatible pool, configure that pool's DATUM host, port, and public key. A pool's ordinary Stratum endpoint cannot be used as a DATUM endpoint.

The `datum` settings above match the defaults. The Gateway forwards full ASIC usernames to the pool, so `YOUR_BITCOIN_ADDRESS.miner1` credits work to that address and worker. You can use the same address across your ASICs or a different address on each one. A valid `mining.pool_address` is still required by the Gateway, but setting it does not override an address supplied in the ASIC username. To use that configured address with simple worker names instead, see [Using the configured reward address](#using-the-configured-reward-address).

Start or restart the Gateway using the command for your installation method.

For OCEAN's Debian package:

```bash
sudo systemctl restart datum-gateway
```

For a source build, run from the repository/build directory containing your executable and configuration:

```bash
./datum_gateway -c datum_gateway_config.json
```

Configure each ASIC with:

| ASIC setting | Value |
| --- | --- |
| Pool URL | `stratum+tcp://YOUR_GATEWAY_LAN_IP:23334` |
| Username / worker | `YOUR_BITCOIN_ADDRESS.miner1` (replace the address; use a distinct worker name for each ASIC) |
| Password | `x` |

Replace the host with your Gateway's LAN address, and the port if you changed `stratum.listen_port`. The ASIC connects to your Gateway; the Gateway connects to OCEAN. Configure ASIC failover destinations as appropriate. With `pooled_mining_only: true`, a prolonged pool outage disconnects miners so they can fail over. Solo fallback requires explicitly setting this option to `false`; during solo fallback, you earn nothing unless you find a block.

Before moving the rest of your miners over, [verify the setup](#verify-it-is-working) with one ASIC, including checking that the pool credits work to your intended Bitcoin address and worker. For larger installations, [size the share difficulty](OPTIMIZATIONS.md#sizing-share-difficulty) before connecting the full fleet.

#### Using the configured reward address

If you prefer to manage one reward address in the Gateway configuration, set `mining.pool_address` to your Bitcoin mainnet address and apply these settings to the existing `datum` section, keeping the pool connection settings:

```json
{
  "datum": {
    "pool_pass_full_users": false,
    "pool_pass_workers": true
  }
}
```

Restart the Gateway and use simple ASIC usernames such as `miner1` and `miner2`. The Gateway sends them to the pool as `YOUR_CONFIGURED_BITCOIN_ADDRESS.miner1` and `YOUR_CONFIGURED_BITCOIN_ADDRESS.miner2`. In this mode, the entire ASIC username is treated as a worker name, so omit the Bitcoin address from it. Verify the resulting address and workers in the pool's statistics.

Alternatively, you can keep the default username settings and enter `.miner1` on an ASIC. The leading dot tells the Gateway to use `mining.pool_address` for that worker, while other ASICs can still specify full addresses. See [username and payout-address configuration](usernames.md) for details.

### Solo mining setup (no pool)

First complete [Node Configuration](#node-configuration) and [Installation](#installation), including syncing Bitcoin Core and configuring the Gateway's RPC access and new-block notifications.

In your Gateway configuration file (`/etc/datum-gateway/datum_gateway_config.json` for OCEAN's Debian package, or `datum_gateway_config.json` by default when run manually), apply the following settings to the existing `mining` and `datum` sections. This is a configuration excerpt; keep your other settings, including the `bitcoind` section:

```json
{
  "mining": {
    "pool_address": "REPLACE_WITH_YOUR_BITCOIN_MAINNET_ADDRESS"
  },
  "datum": {
    "pool_host": "",
    "pooled_mining_only": false
  }
}
```

- Set `mining.pool_address` to a Bitcoin mainnet address you control. Despite its name, this is **your solo block reward address**. All solo rewards from miners connected to this Gateway go to this address; ASIC usernames do not change the payout destination.
- Set `datum.pool_host` explicitly to `""` to disable the pool connection. Omitting this setting uses the default pool host (OCEAN).
- Set `datum.pooled_mining_only` to `false` so mining can run without a pool. Both settings are required for this setup: setting only `pooled_mining_only` to `false` leaves pooled mining enabled and allows solo fallback when the pool is unavailable.

For OCEAN's Debian package, apply the changes with `sudo systemctl restart datum-gateway`. For a source build, start the Gateway with your edited configuration, or restart your existing Gateway service:

```bash
./datum_gateway -c datum_gateway_config.json
```

Point your ASIC miners at `stratum+tcp://YOUR_GATEWAY_LAN_IP:23334`, replacing the host with your Gateway's LAN address (and the port if you changed `stratum.listen_port`). You can use a worker name such as `miner1` and a password such as `x`; these do not determine solo payouts. Confirm that the Gateway receives templates from your node and your miners are submitting accepted shares.

**Accepted shares in solo mode are not paid shares. You receive no rewards unless your miners find a block accepted by the Bitcoin network.** Any failover destinations configured on your ASICs operate independently of this Gateway; choose them to match your intended mining mode.

### Verify it is working

Start with one ASIC before connecting the rest of the farm. Work through this checklist after initial setup and repeat the relevant checks after changing node, pool, reward-address, or network settings.

If enabled, open the Gateway dashboard at `http://YOUR_GATEWAY_LAN_IP:7152/` (or your configured `api.listen_port`). Set a secure `api.admin_password`; the admin username is `admin`. Setting `api.listen_port` to `0` disables the dashboard and API. Keep access to the dashboard and node RPC restricted to your trusted network.

- [ ] **The Gateway stays running.** For OCEAN's Debian package, `systemctl status datum-gateway` shows `active (running)` without repeated restarts. For a foreground source build, the process stays running without fatal configuration errors. Check recent logs using the commands below.
- [ ] **Bitcoin Core is synced on the intended network.** Run `bitcoin-cli getblockchaininfo` using your node's configuration, data directory, and RPC credentials. For Bitcoin mainnet, expect `chain: "main"`, `initialblockdownload: false`, and `blocks` caught up with `headers`. Confirm the node continues receiving new blocks.
- [ ] **The Gateway has a current template.** Its job height is the node's current height plus one, and its previous-block hash matches the node's `bestblockhash`. There are no persistent template-fetch errors. You can read the job through the JSON API below; compare again if a new block arrives between checks.
- [ ] **New blocks trigger prompt work changes.** Watch at least one new Bitcoin block arrive. The Gateway promptly advances its job height and previous-block hash, and the ASIC continues submitting work. Logs include `NEW NETWORK BLOCK` and job updates. The Gateway should not wait for the normal 40–60-second work-update period to react to a new block.
- [ ] **The intended mining mode is active.** Pooled mining shows `Connected and Ready` and the intended pool host. Explicit full solo mining shows `Non-Pooled Mode`. If you intended pooled mining, investigate `Non-Pooled Mode` before proceeding.
- [ ] **The ASIC is mining through this Gateway.** Its active destination is your Gateway's address and Stratum port. The Gateway shows the client connected and subscribed, with accepted shares increasing and a plausible hashrate once enough shares arrive. Check that the ASIC has not switched to a failover destination. Slow miners or a high difficulty floor can take longer to submit shares; use the [difficulty guide](OPTIMIZATIONS.md#sizing-share-difficulty) to estimate the expected rate.
- [ ] **The pool is accepting work (pooled mode).** The dashboard's DATUM accepted-share counter increases. Watch rejected shares too, and investigate persistent rejects. An ASIC's locally accepted shares alone do not prove pool acceptance.
- [ ] **Work is credited to the right address (pooled mode).** Check the pool's miner statistics for your exact Bitcoin address and worker, allowing time for statistics to update. With default settings, the ASIC username should be `YOUR_BITCOIN_ADDRESS.worker`; if using the [configured reward address](#using-the-configured-reward-address), check that address instead. Confirm credited work before connecting more miners. Credit and payouts follow the pool's reward system; a wallet payment is not an immediate setup check.

**For full solo mining, skip the two pool checks.** Verify that `mining.pool_address` is a Bitcoin mainnet address you control. ASIC usernames do not set solo payouts, and accepted shares earn nothing unless your miners find a block accepted by the Bitcoin network.

Once the checks pass, connect the remaining ASICs and confirm the expected client count, aggregate hashrate, and [share submission rate](OPTIMIZATIONS.md#sizing-share-difficulty). Watch another new-block transition under the full farm's load.

#### Status and diagnostic commands

For OCEAN's Debian package, inspect service status and recent logs with:

```bash
sudo systemctl status datum-gateway --no-pager
sudo journalctl -u datum-gateway -n 100 --no-pager
# Follow new messages while checking a miner or waiting for a new block:
sudo journalctl -u datum-gateway -f
```

For a foreground source build, watch the console output (`logger.log_to_console` is enabled by default).

The [JSON API](json_api.md) also provides these checks when the dashboard and `api.json_api` are enabled. Replace the example host and port as needed:

```bash
curl -fsS http://YOUR_GATEWAY_LAN_IP:7152/v1/decentralized_client_stats
curl -fsS http://YOUR_GATEWAY_LAN_IP:7152/v1/current_stratum_job
curl -fsS http://YOUR_GATEWAY_LAN_IP:7152/v1/stratum_server_info
```

These expose pool readiness and accepted/rejected shares, the current job's `block_height` and `previous_block`, and client/subscription counts and estimated hashrate, respectively. The pooled API readiness value is `Ready`; the dashboard displays `Connected and Ready`.

#### If a check fails

| Symptom | Check first |
| --- | --- |
| Gateway exits or repeatedly restarts | Configuration syntax, required reward address, and the first error in its logs. |
| Missing or outdated template | Node sync, RPC URL and authentication, cookie-file permissions, and new-block notifications. |
| Pool stays `Not Ready` | DATUM pool host, port, public key, DNS, and outbound connectivity. |
| ASIC does not appear | Its active destination, Gateway LAN address, Stratum port, and network reachability. |
| Local accepts but no pool credit | DATUM accepted/rejected counters, forwarded username, intended reward address, and the pool's statistics update delay. |
| Excessive stale shares | Node peer performance, block notifications, and congestion along the node-to-Gateway-to-ASIC path; see the [optimization guide](OPTIMIZATIONS.md). |

If the problem persists, [report it through the official repository's GitHub Issues](../README.md#reporting-problems) with the relevant details and logs. Report suspected security vulnerabilities privately using [SECURITY.md](../SECURITY.md).

## Docker

Build the DATUM Gateway Docker image from this repository, then supply your own configuration.

### Building the Docker Image

To build the DATUM Gateway Docker image:

```bash
# From the root of the repository
docker build -t datum_gateway .
```

### Running the Container

The container expects a configuration file at `/app/config/config.json`. Copy the [example configuration](example_datum_gateway_config.json) to `/path/to/your/config/directory/config.json`, fill in your node connection and reward address as described under [Usage](#usage), and make it readable by the container user. Mount that directory when starting the container. Choose a node connection recipe below before starting; the basic command is:

```bash
docker run --name datum-gateway -v /path/to/your/config/directory:/app/config -p 23334:23334 -p 7152:7152 datum_gateway
```

For the HTTP notification recipes below, set `bitcoind.notify_fallback` to `false` and keep `api.listen_port` enabled at `7152`. In bridge-network mode, leave `api.listen_addr` empty (the default, listening on all container interfaces); a host LAN address or container loopback binding will not work for these connections. Restrict access to the published dashboard/API port to your trusted network.

The `blocknotify` command runs in the Bitcoin node's environment, so install `wget` there and use a Gateway address reachable from that environment, as shown below. Restart Bitcoin Core after changing `bitcoin.conf`.

### Connecting to a Bitcoin Node

When running the DATUM Gateway in Docker, you need to configure it to connect to your Bitcoin node. The connection method depends on where your Bitcoin node is running. The JSON snippets below show the `bitcoind` section only; keep your other Gateway settings:

#### 1. Bitcoin Node Running in Docker (Same Network)

Attach both containers to the same **user-defined bridge network** to use their container names as hostnames. Docker's default `bridge` network does not provide automatic container-name DNS; see [Docker's bridge network documentation](https://docs.docker.com/engine/network/drivers/bridge/#differences-between-user-defined-bridges-and-the-default-bridge).

For an existing node container named `bitcoin-node`, create a network and attach the node, then start the Gateway on it using this command in place of the basic command above:

```bash
docker network create datum-net
docker network connect datum-net bitcoin-node
docker run --name datum-gateway --network datum-net \
  -v /path/to/your/config/directory:/app/config \
  -p 23334:23334 -p 7152:7152 datum_gateway
```

If starting a new node container, give it `--name bitcoin-node --network datum-net`. If it already uses a user-defined network, reuse that network for the Gateway instead. Configure the Gateway to use the node's name:

```json
{
  "bitcoind": {
    "rpcurl": "http://bitcoin-node:8332",
    "rpcuser": "your_rpc_user",
    "rpcpassword": "your_rpc_password",
    "notify_fallback": false
  }
}
```

Configure Bitcoin Core's `rpcbind` to listen on its container interface and `rpcallowip` to permit the Gateway's address or the trusted Docker subnet. The node's RPC port does not need to be published to the host for communication on this shared network.

In the node container's `bitcoin.conf`, set `blocknotify` to use the DATUM Gateway container name and its container-side API port:

```ini
blocknotify=wget -q -O /dev/null http://datum-gateway:7152/NOTIFY
```

#### 2. Bitcoin Node Running on Host System

If your Bitcoin node is running directly on the Docker host, or its container publishes an RPC port on that host, you have two options:

**Option A: Using host.docker.internal in bridge mode**

Docker Desktop resolves `host.docker.internal` automatically. With Docker Engine on Linux, add `--add-host=host.docker.internal:host-gateway` when starting the Gateway; see [Docker's host-gateway documentation](https://docs.docker.com/reference/cli/docker/container/run/#add-entries-to-container-hosts-file---add-host). Use this Linux command in place of the basic command above:

```bash
docker run --name datum-gateway \
  --add-host=host.docker.internal:host-gateway \
  -v /path/to/your/config/directory:/app/config \
  -p 23334:23334 -p 7152:7152 datum_gateway
```

Configure the RPC URL as follows (use the published host port if it differs from `8332`):

```json
{
  "bitcoind": {
    "rpcurl": "http://host.docker.internal:8332",
    "rpcuser": "your_rpc_user",
    "rpcpassword": "your_rpc_password",
    "notify_fallback": false
  }
}
```

On Linux, Bitcoin Core's RPC listener must bind to a host address reachable from the Gateway container, with `rpcallowip` permitting the Gateway's source address. Adding the hostname mapping does not make a host service bound only to `127.0.0.1` reachable from a bridge-network container. For a node in another container, its RPC listener must also accept connections through the published port.

For a node running directly on the Docker host, use the Gateway's **published host port** in `bitcoin.conf`. Here `127.0.0.1` refers to the host where Bitcoin Core runs:

```ini
blocknotify=wget -q -O /dev/null http://127.0.0.1:7152/NOTIFY
```

If the node itself runs in another bridge-network container and reaches the Gateway through a published host port, use `http://host.docker.internal:7152/NOTIFY` instead. On Linux, add the same `--add-host=host.docker.internal:host-gateway` mapping to the **node container** too. Container-name DNS such as `datum-gateway` applies to the shared-network recipe above.

**Option B: Using host networking mode**

[Host networking](https://docs.docker.com/engine/network/drivers/host/) is supported by Docker Engine on Linux and as an opt-in feature in Docker Desktop 4.34 or later. Run the DATUM Gateway container with `--network host`; port publishing (`-p`) is unnecessary in this mode:

```bash
docker run --name datum-gateway --network host \
  -v /path/to/your/config/directory:/app/config datum_gateway
```

Then configure using localhost:
```json
{
  "bitcoind": {
    "rpcurl": "http://localhost:8332",
    "rpcuser": "your_rpc_user",
    "rpcpassword": "your_rpc_password",
    "notify_fallback": false
  }
}
```

For a node running directly on the host, use this `blocknotify` in `bitcoin.conf` when the Gateway uses host networking:

```ini
blocknotify=wget -q -O /dev/null http://localhost:7152/NOTIFY
```

For a node in a separate bridge-network container, `localhost` refers to that node container. Use `host.docker.internal` and the Linux mapping described in Option A to reach the Gateway on the host.

#### 3. Bitcoin Node on Remote System

If your Bitcoin node is running on a different machine, use the hostname or IP address:

```json
{
  "bitcoind": {
    "rpcurl": "http://192.168.1.100:8332",
    "rpcuser": "your_rpc_user",
    "rpcpassword": "your_rpc_password",
    "notify_fallback": false
  }
}
```

In your remote Bitcoin node's `bitcoin.conf`, use the Docker host's LAN address and the Gateway's published host port. Replace `YOUR_GATEWAY_LAN_IP` with an address reachable from that node:

```ini
blocknotify=wget -q -O /dev/null http://YOUR_GATEWAY_LAN_IP:7152/NOTIFY
```

**Important Notes:**

- Ensure your Bitcoin node's RPC is configured to accept connections from the DATUM Gateway
- For bridge-network or remote RPC connections, set `rpcbind` in `bitcoin.conf` to a local address on the Bitcoin node that the Gateway can reach. Set `rpcallowip` to permit the Gateway's source address as seen by the node. For a remote node, Docker's default NAT normally makes this the Docker host's address, rather than the Gateway container's address. Do not expose RPC to untrusted networks.
- Always use strong RPC credentials and consider network security when exposing RPC endpoints
- Verify that new blocks trigger prompt work changes using the [verification checks](#verify-it-is-working)
