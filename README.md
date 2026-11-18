# DATUM Gateway
**Decentralized Alternative Templates for Universal Mining**
(c) 2024-2026 Bitcoin Ocean, LLC, Jason Hughes, and individual contributors

> **Know what you’re mining—and who you’re trusting**
>
> **The original and only official DATUM Gateway repository is [OCEAN-xyz/datum_gateway](https://github.com/OCEAN-xyz/datum_gateway).** Official DATUM supports Bitcoin only, using Bitcoin’s consensus rules and SHA-256d proof of work.
>
> DATUM is open source, and anyone can create a fork. Those forks are independently maintained and are not endorsed or supported by this project. They may retain DATUM’s name, logo, and documentation—or advertise equal or higher version numbers—while changing the mining algorithm, consensus rules, or reward destinations.
>
> **Before directing hashpower to a fork, verify what network it mines and how your work is rewarded.** Branding and version numbers alone do not establish Bitcoin compatibility or trustworthiness. DATUM never needs your wallet’s seed phrase or private keys.
>
> If you are reading this under another repository owner or URL, you are viewing a fork or copy of the official project.

**An upstream declaration with a Bitcoin receipt:** The SHA-256 hash of our original upstream declaration is recorded in Bitcoin block **970877**. Read [the story and verify the commitment](doc/original.md).

## Overview

DATUM Gateway enables sovereign Bitcoin mining with block templates created by your own Bitcoin node. It supports two modes:

- **Pooled solo mining with shared rewards (recommended).** Connect to a DATUM-compatible pool and receive rewards according to that pool's reward system and payout rules. Your miners do not need to personally find a block to qualify for shared rewards; eligibility and amounts depend on the pool's rules for contributed work. This is DATUM's intended pooled mining setup: you retain local block template creation and block submission, while the pool coordinates reward splits to reduce payout variance.
- **Solo mining — fully sovereign, with no pool involved.** Run DATUM Gateway with your own Bitcoin node and mining hardware. No pool connection is required, and you receive the full block reward when your miners find a block accepted by the Bitcoin network. **If your miners do not find a block, you receive no rewards**, regardless of how much work they contribute. See [solo mining setup](doc/INSTALL.md#solo-mining-setup-no-pool).

In both modes, the Gateway gets block templates from your local Bitcoin node, generates and distributes work to your mining hardware, and submits solved blocks directly through your node. In pooled solo mining, the pool shares rewards but does not create your block templates or mining work.

The pool supplies reward-split information and requirements for pooled work. Transaction selection and block template creation remain with your own Bitcoin node; the DATUM protocol does not let the pool supply a replacement block template.

Currently the DATUM Gateway supports communication with mining hardware using the Stratum v1 protocol with version rolling extensions (aka "ASICBoost").  Communication with the Bitcoin node is via RPC and must support GBT ("getblocktemplate").  When pooled solo mining is used, communication with the pool is via the DATUM protocol.

**[Bitcoin Core](https://bitcoincore.org/en/download/) is the recommended Bitcoin node for DATUM.** The [installation and configuration guide](doc/INSTALL.md) covers Bitcoin Core.

The DATUM Gateway only supports mining Bitcoin. Many optimizations and design decisions are tightly tied to Bitcoin-specific constraints and consensus rules for efficiency, so modifying the code to support other chains is not straightforward. Adapting this code to another chain does not make that chain Bitcoin or that fork an official DATUM release.

![DATUM recommended setup: on-site ASIC miners and optional remote ASICs through routers connect to DATUM Gateway, which gets templates from your Bitcoin Core node and optionally coordinates rewards with OCEAN via DATUM Prime. Your node connects directly to the Bitcoin network. The footer includes the official repository URL, https://github.com/OCEAN-xyz/datum_gateway, and a QR code linking to it.](doc/DATUM_recommended_setup-network_diagram.svg)

## Important compatibility notes

You MUST run and utilize a valid Bitcoin node to use the DATUM Gateway.  Currently, the only known supported node software is [Bitcoin Core](https://bitcoincore.org/en/download/).

While Bitcoin Knots was previously recommended, versions beyond `29.3.knots20260507` **are no longer compatible** with DATUM Gateway. The Bitcoin Knots project no longer supports the Bitcoin blockchain or Bitcoin mining, despite claims to the contrary. It now only supports a hard-forked altcoin chain with a completely different set of rules and a proof-of-work algorithm that is not compatible with Bitcoin or the official DATUM Gateway.

Use of an incompatible Bitcoin node with DATUM will result in no mining rewards in either pooled or non-pooled mining modes.

Continuing to use older Bitcoin Knots versions which are still technically compatible is NOT recommended, as those versions now lack up-to-date security fixes and could expose you to unpatched vulnerabilities. Bitcoin Core is recommended.

## Benefits over direct-to-pool mining

With a direct miner-to-pool connection (such as Stratum v1), your miners work on templates supplied by the pool. DATUM moves template creation and work distribution to your own node and Gateway, while retaining the option to share rewards:

- **Control your block templates.** Your Bitcoin node selects transactions according to your policies and validates the chain you mine. This distributes template creation among miners, increases censorship resistance, and reduces dependence on pool operators for transaction selection. Pooled work must still meet Bitcoin consensus rules and the pool's reward requirements.
- **Reduce stale work.** With your node, Gateway, and ASICs on the same LAN, new work reaches miners locally as your node learns of a block, without waiting for a remote pool to send replacement jobs. This can reduce stale shares, especially when the pool connection has high latency.
- **Brand the blocks you find.** Set `mining.coinbase_tag_secondary` to include your own short name or identifier in the coinbase transaction, including when pooling rewards. Full solo mining also lets you set the primary tag.
- **Submit blocks through your own node.** The Gateway submits solved blocks directly to your Bitcoin node for validation and relay, so block submission does not have to wait for the pool to receive and relay your solution.
- **Encrypted pool communication.** The DATUM connection between your Gateway and the pool is encrypted, protecting that traffic from passive observers.
- **Keep using existing hardware and firmware.** ASICs connect to the Gateway using Stratum v1, while the Gateway handles DATUM communication with the pool.

Stale-share improvements depend on node connectivity, notification speed, hardware, and network layout. Shares still travel to the pool for reward accounting, and a share accepted locally is not a guarantee of pool acceptance. See the [recommended setup](doc/INSTALL.md#requirements) for the greatest benefit.

## Getting started

See [INSTALL.md](doc/INSTALL.md) for requirements, installation, and configuration:

- [Install OCEAN's Debian packages](doc/INSTALL.md#oceans-debian-packages) for Debian Trixie on amd64, including Bitcoin Core.
- [Install Debian's official package](doc/INSTALL.md#debians-official-package), or use the [DATUM box installer image](doc/INSTALL.md#datum-box-installer-image) for a dedicated machine.
- [Build from source](doc/INSTALL.md#building-from-source), optionally [install under a custom prefix](doc/INSTALL.md#separate-build-directory-and-installation-prefix) and [run as a systemd service](doc/INSTALL.md#systemd-service-for-source-builds), or [run with Docker](doc/INSTALL.md#docker).
- [Configure Bitcoin Core](doc/INSTALL.md#node-configuration) and [DATUM Gateway](doc/INSTALL.md#usage).
- [Set up pooled solo mining with shared rewards](doc/INSTALL.md#pooled-solo-mining-setup-recommended).
- [Set up full solo mining without a pool](doc/INSTALL.md#solo-mining-setup-no-pool).
- [Work through the verification checklist](doc/INSTALL.md#verify-it-is-working).
- [Optimize share difficulty, LAN bandwidth, remote sites, and node peers](doc/OPTIMIZATIONS.md).

For pooled mining, also review the [username and payout-address documentation](doc/usernames.md).
To let miners ask for a minimum difficulty, including through the Stratum password where nothing else can be set, see [minimum difficulty requests](doc/passwords.md).

## External information

Learn more about DATUM from its creator, Jason Hughes:

- **[DATUM Deep Dive — BTC++ Mempool Edition (2025)](https://www.youtube.com/watch?v=FJ0Hye52Ib8)** — A technical talk covering DATUM's origins, protocol design, implementation choices, and how miners create their own block templates while pooling rewards. Published by bitcoin++.
- **[DATUM: The Mining Upgrade that Pays for Itself — Bitcoin 2026](https://www.youtube.com/watch?v=qpJ4KDXNPZI)** — A shorter introduction focused on DATUM's practical benefits for miners. Published by Bitcoin Magazine.

These talks describe DATUM at the time they were recorded. Use this repository's current documentation for supported node software, installation, and configuration.

## DATUM Protocol
The DATUM Gateway's communication with the mining pool is via the DATUM Protocol.  This is an encrypted communication link between the DATUM Gateway (client) and DATUM Prime (pool side).

The protocol itself was made from the ground up as a custom protocol.  Its specification is evolving, subject to change, and will be published elsewhere.

The core concepts of the protocol:

 - Encrypt communications between the Gateway and pool
 - Obfuscate the communications somewhat so a MITM is unable to glean useful or accurate insight into the miner's operation via analysis of the still-ciphered communications.
 - Retrieve proper generation transaction payout splits from the pool for locally constructed templates
 - Submit work to the pool with sufficient data to efficiently validate and accept the work for proper rewards
 - Communicate minimal guardrails and requirements for a valid template to earn pooled rewards

With the current version of the protocol, the pool does block validation after coordinating with the miner. This is strictly to ensure miners are not accidentally creating invalid blocks while DATUM is still in development. In a future version of the protocol, the pool will not be in charge of this function and will be almost completely blinded to the contents of the miner's block template.

The protocol is not specific to a pooled reward system, as the Gateway coordinates the appropriate generation transaction with the pool.  However, in the spirit of maximum decentralization, the pool should implement rewarding miners directly from generated payouts, such as with OCEAN's TIDES reward system.

## Template/Share Requirements for Pooled Mining

 - Must be a valid block and conform to current Bitcoin consensus rules
 - Submitted work must be for the current latest block height, valid time, etc
 - Must include generation transaction outputs provided by the pool in the order provided
 - Must include the primary coinbase tag as provided by the pool
 - Must include the unique identifier provided by the pool
 - Work must include the work target and meet/exceed that target
 - Any additional requirements by pool documentation

## Notes/Known Issues/Limitations

- By default, if the connection with the pool is lost and fails to reconnect, the Gateway will disconnect all stratum clients. This way miners can use their built-in failover and switch to non-DATUM mining, or an alternate/backup Gateway.
- Accepted/rejected share counts on mining hardware may not perfectly match with the pool. The delta may vary depending on the Gateway's configuration. This is because shares are first accepted or rejected as valid for your local template based on your local node, and then again accepted or rejected based on the pool's requirements, latency to the pool (stale work), latency between your node and the network (stale work), etc.  Stratum v1 has no mechanism to report back to the miner that previously accepted work is now rejected, and it doesn't make sense to wait for the pool before responding, either.

DATUM Gateway remains in public beta. While we work to make it stable and reliable, you may still encounter bugs or other issues. Rapid or short-notice protocol upgrades are no longer expected. However, to get the latest features and benefits, you should generally update your DATUM Gateway to the latest release on your regular maintenance schedule, or otherwise as soon as practicable. Follow releases from the [official upstream repository](https://github.com/OCEAN-xyz/datum_gateway/releases) for fixes and improvements, and review release notes when planning upgrades.

Be sure you have failover settings on your miners. As a best practice, when mining on a DATUM pool, set your miner's failover to use that pool's Stratum endpoint.

## Contributing

Contributions that improve Bitcoin mining, documentation, testing, and reliability are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) for project scope, pull request guidance, and validation expectations.

## Reporting problems

Miners using OCEAN can request mining and DATUM setup support directly from OCEAN using the contact information on [ocean.xyz](https://ocean.xyz). OCEAN does not provide support for non-pooled solo mining or pooled mining on other pools.

**For suspected security vulnerabilities, follow [SECURITY.md](SECURITY.md) and report privately through GitHub or directly to Jason Hughes. Do not post vulnerability details in public issues.**

Report ordinary bugs and other non-security problems through [GitHub Issues in the official DATUM repository](https://github.com/OCEAN-xyz/datum_gateway/issues). Check existing issues first, then include your DATUM version or commit, operating system and installation method, Bitcoin Core version, relevant ASIC models and firmware, what you expected to happen, and what actually happened. Include steps to reproduce the problem and relevant log excerpts where possible. Remove passwords, RPC credentials, and other private information before posting logs or configuration.

## License

The DATUM Gateway (including the DATUM Protocol) is free open source software and released under the terms of the MIT license.  See LICENSE.
