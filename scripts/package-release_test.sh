#!/usr/bin/env bash
# Offline integration test for scripts/package-release.sh.
set -Eeuo pipefail
IFS=$'\n\t'

readonly SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly REPO_DIR="$(cd -- "$SCRIPT_DIR/.." && pwd)"
readonly PACKAGER="$SCRIPT_DIR/package-release.sh"
readonly VERIFIER="$SCRIPT_DIR/verify-template-bundle.py"
TMP_DIR=''

cleanup() {
  [[ -z "$TMP_DIR" || ! -d "$TMP_DIR" ]] || rm -rf -- "$TMP_DIR"
}
trap cleanup EXIT

fail() { printf 'test failure: %s\n' "$*" >&2; exit 1; }

TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/ppflight-package-test.XXXXXX")"
binary="$TMP_DIR/ppflight-agent"
output="$TMP_DIR/output"
repro_output="$TMP_DIR/repro-output"
extract="$TMP_DIR/extract"
printf 'offline test binary\n' > "$binary"
chmod 0755 "$binary"

"$PACKAGER" --binary "$binary" --version 0.1.0 --arch amd64 --output-dir "$output"
archive="$output/ppflight-agent-0.1.0-linux-amd64.tar.gz"
[[ -f "$archive" && -f "$output/SHA256SUMS" ]] || fail 'packager did not create archive and checksums'
(cd -- "$output" && sha256sum --check SHA256SUMS >/dev/null) || fail 'checksum file does not verify'

# POSIX tar may otherwise persist fresh atime/ctime PAX metadata.  Generate a
# second archive from the exact same binary, version, and architecture and
# require the compressed bytes themselves to be stable.
"$PACKAGER" --binary "$binary" --version 0.1.0 --arch amd64 --output-dir "$repro_output"
repro_archive="$repro_output/ppflight-agent-0.1.0-linux-amd64.tar.gz"
cmp -s "$archive" "$repro_archive" || fail 'same release input produced different archive bytes'

mkdir -p -- "$extract"
tar -xzf "$archive" -C "$extract"
root="$extract/ppflight-agent"
[[ -d "$root" && ! -L "$root" ]] || fail 'archive root is missing or unsafe'
case "$(uname -s)" in
  MINGW*|MSYS*)
    # Windows filesystems do not retain POSIX execute bits for an extensionless
    # temporary test binary. Linux CI validates the archive's required 0755.
    ;;
  *) [[ "$(stat -c '%a' "$root/ppflight-agent")" == '755' ]] || fail 'agent binary mode is not 0755' ;;
esac
[[ "$(stat -c '%a' "$root/scripts/install.sh")" == '755' ]] || fail 'installer mode is not 0755'
[[ "$(stat -c '%a' "$root/config/agent.example.yaml")" == '644' ]] || fail 'config mode is not 0644'
[[ "$(<"$root/VERSION")" == '0.1.0' ]] || fail 'package VERSION is incorrect'
(tar -tvzf "$archive" | awk '$2 == "0/0" && $NF == "ppflight-agent/VERSION" { found=1 } END { exit !found }') || fail 'package VERSION is not root-owned in archive metadata'
(cd -- "$root" && sha256sum --check ppflight-agent.sha256 >/dev/null) || fail 'packaged binary checksum does not verify'
find "$root" -type l -print -quit | grep -q . && fail 'archive contains a symlink'
find "$root" -type f \( -path '*/secrets/*' -o -path '*/queue/*' -o -path '*/queues/*' -o -name '*.pem' -o -name '*.key' -o -name '*.token' \) -print -quit | grep -q . && fail 'archive contains forbidden material'

expected=(
  ppflight-agent ppflight-agent.sha256 VERSION README.md
  config/README.md config/agent.env.example config/agent.example.yaml config/assignments.example.yaml
  docs/AGENT-API-V1.md docs/API.md docs/CONTRACT-REVIEW.md docs/INSTALL.md docs/SELF-UPGRADE-V1.md
  packaging/systemd/ppflight-agent.service packaging/systemd/ppflight-agent-upgrade.path packaging/systemd/ppflight-agent-upgrade.service packaging/systemd/ppflight-node-exporter.service packaging/systemd/ppflight-smartctl-exporter.service
  packaging/tmpfiles.d/ppflight-agent.conf
  scripts/install.sh scripts/uninstall.sh scripts/create-pve-tokens.sh scripts/verify-template-bundle.py
  bundles/ppflight-cloudinit/agent-vendor-manifest.v1.json
)
while IFS= read -r bundle_file; do
  bundle_file=${bundle_file%$'\r'}
  expected+=("bundles/ppflight-cloudinit/$bundle_file")
done < <(python3 -I "$VERIFIER" list "$REPO_DIR/bundles/ppflight-cloudinit")

actual_files="$TMP_DIR/actual-files"
expected_files="$TMP_DIR/expected-files"
(cd -- "$root" && find . -type f -printf '%P\n' | LC_ALL=C sort) > "$actual_files"
printf '%s\n' "${expected[@]}" | LC_ALL=C sort > "$expected_files"
cmp -s "$expected_files" "$actual_files" || {
  diff -u "$expected_files" "$actual_files" >&2 || true
  fail 'archive file set differs from the reviewed allowlist'
}

python3 -I "$root/scripts/verify-template-bundle.py" verify "$root/bundles/ppflight-cloudinit" >/dev/null || fail 'packaged bundle did not verify'
printf 'tampered\n' >> "$root/bundles/ppflight-cloudinit/catalog/template-catalog.v1.json"
if python3 -I "$root/scripts/verify-template-bundle.py" verify "$root/bundles/ppflight-cloudinit" >/dev/null 2>&1; then
  fail 'bundle verifier accepted tampered content'
fi

if "$PACKAGER" --binary "$TMP_DIR/missing" --version 0.1.0 --arch amd64 --output-dir "$output" >/dev/null 2>&1; then
  fail 'packager accepted a missing binary'
fi
if "$PACKAGER" --binary "$binary" --version 0.1.0 --arch amd64 --output-dir "$output" >/dev/null 2>&1; then
  fail 'packager overwrote an existing archive or checksum file'
fi
rc_output="$TMP_DIR/rc-output"
"$PACKAGER" --binary "$binary" --version 0.1.0-rc.9 --arch amd64 --output-dir "$rc_output"
[[ -f "$rc_output/ppflight-agent-0.1.0-rc.9-linux-amd64.tar.gz" ]] || fail 'packager did not preserve the prerelease identity'
printf '%s\n' 'package-release test passed'
