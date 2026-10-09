# Reproducible builds with GNU Guix

`guix/build.scm` builds DATUM Gateway from this checkout inside an isolated Guix build environment. `guix/channels.scm` pins the exact Guix revision, which fixes every input: compiler, C library, curl, jansson, libmicrohttpd, libsodium and so on. Anyone who builds the same datum_gateway commit with the same `channels.scm` gets a bit-identical `datum_gateway` binary.

You need GNU Guix, either as the operating system or installed on top of another distribution, with a running `guix-daemon`.

## Build

From the root of the repository:

```sh
guix time-machine -C guix/channels.scm -- build -f guix/build.scm
```

The last line of output is the result's store path. It contains only the stripped binary, `bin/datum_gateway`.

It links only to the system's glibc and has every other library built in.

## Release archives for amd64 and arm64

Dependency:

```sh
sudo apt install guix qemu-user-static binfmt-support
```

Build:

```sh
./guix/release.sh
```

This builds DATUM Gateway for amd64 (`x86_64-linux`) and arm64
(`aarch64-linux`) with the pinned Guix revision and writes to `dist/`:

- `datum_gateway-<version>-amd64.tar.gz`
- `datum_gateway-<version>-arm64.tar.gz`
- `SHA256SUMS`

Each archive contains only the `datum_gateway` binary.

## Verify that a build is reproducible

Rebuild locally and compare with the existing result. The command fails if
any file differs:

```sh
guix time-machine -C guix/channels.scm -- build -f guix/build.scm --check
```
