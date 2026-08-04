<!-- SPDX-License-Identifier: MIT -->

# Releasing Callweave

Callweave releases are built from annotated semantic-version tags. The release
workflow accepts stable tags such as `v1.1.1` and prerelease tags such as
`v1.2.0-rc.1`.

## Prepare the release

Make sure `main` is current, clean, and passing CI:

```sh
git switch main
git pull --ff-only
git status --short
make clean
make
```

Review the commits and release notes since the previous tag before choosing the
next version. Do not move or reuse a tag that has already been published.

## Publish a tag

Create and push an annotated tag:

```sh
git tag -a v1.1.1 -m "Callweave v1.1.1"
git push origin v1.1.1
```

Pushing a matching tag starts `.github/workflows/release.yml`. The workflow:

1. builds and tests on native Ubuntu 24.04 amd64 and arm64 runners;
2. packages the stripped executable, documentation, examples, and licenses;
3. generates a shared `SHA256SUMS` file;
4. creates the GitHub Release with generated release notes.

A tag containing a prerelease suffix, such as `v1.2.0-rc.1`, creates a GitHub
prerelease.

## Release assets

Successful releases contain:

```text
callweave-v1.1.1-linux-amd64.tar.gz
callweave-v1.1.1-linux-arm64.tar.gz
SHA256SUMS
```

The archives are built on Ubuntu 24.04 and dynamically link against the system
glibc, libbpf, libelf, zlib, and zstd libraries. Users on incompatible
distributions can build from the automatically generated source archives.

Verify a downloaded archive with:

```sh
sha256sum --check SHA256SUMS
```

Run this command in a directory containing `SHA256SUMS` and both release
archives. To verify only one downloaded archive, compare its `sha256sum` output
with the corresponding line in `SHA256SUMS`.
