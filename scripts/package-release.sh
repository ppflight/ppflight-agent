#!/usr/bin/env bash
# Build a self-contained, reproducible PPFlight release archive from one
# already-built Linux binary.  This script never downloads code or packages.
set -Eeuo pipefail
IFS=$'\n\t'
umask 077

readonly APP='ppflight-agent'
readonly ROOT_NAME='ppflight-agent'
readonly SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly REPO_DIR="$(cd -- "$SCRIPT_DIR/.." && pwd)"
readonly BUNDLE_DIR='bundles/ppflight-cloudinit'
readonly BUNDLE_VERIFIER='scripts/verify-template-bundle.py'

BINARY=''
VERSION=''
ARCH=''
OUTPUT_DIR=''
STAGING_DIR=''

usage() {
  cat <<'EOF'
Usage: scripts/package-release.sh --binary FILE --version X.Y.Z --arch amd64|arm64 --output-dir DIR

Creates DIR/ppflight-agent-X.Y.Z-linux-ARCH.tar.gz and DIR/SHA256SUMS.
The input binary must be an existing regular file, never a symlink.  The
archive has the fixed top-level directory ppflight-agent and contains only the
reviewed installer, examples, unit files, documentation, and verified template
bundle.  It does not fetch anything from the network.
EOF
}

die() { printf 'error: %s\n' "$*" >&2; exit 1; }

need_value() {
  [[ $# -ge 2 && -n "$2" ]] || die "missing value for $1"
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --binary) need_value "$@"; BINARY=$2; shift 2 ;;
    --version) need_value "$@"; VERSION=$2; shift 2 ;;
    --arch) need_value "$@"; ARCH=$2; shift 2 ;;
    --output-dir) need_value "$@"; OUTPUT_DIR=$2; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) die "unknown option: $1" ;;
  esac
done

[[ -n "$BINARY" && -n "$VERSION" && -n "$ARCH" && -n "$OUTPUT_DIR" ]] || {
  usage >&2
  exit 2
}
[[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || die 'version must be a numeric semantic version (X.Y.Z)'
[[ "$ARCH" == 'amd64' || "$ARCH" == 'arm64' ]] || die 'arch must be amd64 or arm64'
[[ -f "$BINARY" && ! -L "$BINARY" ]] || die 'binary must be an existing regular file, not a symlink'
[[ -s "$BINARY" ]] || die 'binary must not be empty'
command -v python3 >/dev/null || die 'python3 is required to verify the template bundle'
command -v tar >/dev/null || die 'tar is required'
command -v gzip >/dev/null || die 'gzip is required'
command -v sha256sum >/dev/null || die 'sha256sum is required'

mkdir -p -- "$OUTPUT_DIR"
[[ -d "$OUTPUT_DIR" && ! -L "$OUTPUT_DIR" ]] || die 'output directory is unsafe'
OUTPUT_DIR="$(cd -- "$OUTPUT_DIR" && pwd)"

cleanup() {
  if [[ -n "$STAGING_DIR" && -d "$STAGING_DIR" ]]; then
    rm -rf -- "$STAGING_DIR"
  fi
}
trap cleanup EXIT

require_regular_source() {
  local relative=$1
  [[ -f "$REPO_DIR/$relative" && ! -L "$REPO_DIR/$relative" ]] || die "required release file is missing or unsafe: $relative"
}

copy_file() {
  local source=$1 destination=$2 mode=$3
  require_regular_source "$source"
  install -D -m "$mode" -- "$REPO_DIR/$source" "$STAGING_DIR/$ROOT_NAME/$destination"
  # install(1) may apply the process umask; archive permissions are part of
  # the release contract, so set the requested mode explicitly afterwards.
  chmod "$mode" -- "$STAGING_DIR/$ROOT_NAME/$destination"
}

# Keep this allowlist deliberately explicit.  New release content must be
# reviewed here instead of being silently swept in by a recursive copy.
readonly -a RELEASE_FILES=(
  'README.md'
  'config/README.md'
  'config/agent.env.example'
  'config/agent.example.yaml'
  'config/assignments.example.yaml'
  'docs/AGENT-API-V1.md'
  'docs/API.md'
  'docs/CONTRACT-REVIEW.md'
  'docs/INSTALL.md'
  'packaging/systemd/ppflight-agent.service'
  'packaging/systemd/ppflight-node-exporter.service'
  'packaging/systemd/ppflight-smartctl-exporter.service'
  'packaging/tmpfiles.d/ppflight-agent.conf'
  'scripts/install.sh'
  'scripts/uninstall.sh'
  'scripts/create-pve-tokens.sh'
  'scripts/verify-template-bundle.py'
)

require_regular_source "$BUNDLE_VERIFIER"
[[ -d "$REPO_DIR/$BUNDLE_DIR" && ! -L "$REPO_DIR/$BUNDLE_DIR" ]] || die 'template bundle directory is missing or unsafe'
python3 -I "$REPO_DIR/$BUNDLE_VERIFIER" verify "$REPO_DIR/$BUNDLE_DIR" >/dev/null || die 'source template bundle verification failed'

mapfile -t BUNDLE_FILES < <(python3 -I "$REPO_DIR/$BUNDLE_VERIFIER" list "$REPO_DIR/$BUNDLE_DIR")
(( ${#BUNDLE_FILES[@]} > 0 )) || die 'template bundle manifest has no files'

# The manifest is a required part of the exact bundle.  Require every listed
# file and reject any unlisted leaf in the source bundle, including symlinks.
declare -A BUNDLE_ALLOWED=([agent-vendor-manifest.v1.json]=1)
for index in "${!BUNDLE_FILES[@]}"; do
  relative=${BUNDLE_FILES[$index]}
  # Some Windows Python launchers translate stdout to CRLF.  Normal Linux/PVE
  # output has no CR; stripping it here keeps the manifest path contract exact.
  relative=${relative%$'\r'}
  BUNDLE_FILES[$index]=$relative
  [[ "$relative" != /* && "$relative" != *'..'* && "$relative" != *'\\'* ]] || die 'template manifest listed an unsafe path'
  BUNDLE_ALLOWED["$relative"]=1
done
while IFS= read -r -d '' source_path; do
  relative=${source_path#"$REPO_DIR/$BUNDLE_DIR/"}
  [[ -n "${BUNDLE_ALLOWED[$relative]+x}" ]] || die "template bundle contains an unlisted file: $relative"
  [[ ! -L "$source_path" && -f "$source_path" ]] || die "template bundle contains a non-regular file: $relative"
done < <(find "$REPO_DIR/$BUNDLE_DIR" -mindepth 1 \( -type f -o -type l \) -print0)
for relative in "${!BUNDLE_ALLOWED[@]}"; do
  require_regular_source "$BUNDLE_DIR/$relative"
done

STAGING_DIR="$(mktemp -d "${TMPDIR:-/tmp}/ppflight-release.XXXXXX")"
install -d -m 0755 "$STAGING_DIR/$ROOT_NAME"
chmod 0755 -- "$STAGING_DIR/$ROOT_NAME"
install -m 0755 -- "$BINARY" "$STAGING_DIR/$ROOT_NAME/$APP"
chmod 0755 -- "$STAGING_DIR/$ROOT_NAME/$APP"
for source in "${RELEASE_FILES[@]}"; do
  mode=0644
  case "$source" in
    scripts/*.sh|scripts/*.py) mode=0755 ;;
  esac
  copy_file "$source" "$source" "$mode"
done
for relative in agent-vendor-manifest.v1.json "${BUNDLE_FILES[@]}"; do
  mode=0644
  case "$relative" in *.sh|*.py) mode=0755 ;; esac
  copy_file "$BUNDLE_DIR/$relative" "$BUNDLE_DIR/$relative" "$mode"
done
find "$STAGING_DIR/$ROOT_NAME" -type d -exec chmod 0755 {} +

python3 -I "$STAGING_DIR/$ROOT_NAME/$BUNDLE_VERIFIER" verify "$STAGING_DIR/$ROOT_NAME/$BUNDLE_DIR" >/dev/null || die 'staged template bundle verification failed'

# The staging tree is the archive policy boundary: directories and regular
# files only, no state, queues, credential material, or accidental extras.
if find "$STAGING_DIR/$ROOT_NAME" -type l -print -quit | grep -q .; then
  die 'release staging tree contains a symbolic link'
fi
if find "$STAGING_DIR/$ROOT_NAME" \( -type b -o -type c -o -type p -o -type s \) -print -quit | grep -q .; then
  die 'release staging tree contains a special file'
fi
if find "$STAGING_DIR/$ROOT_NAME" -type f \( -path '*/secrets/*' -o -path '*/queue/*' -o -path '*/queues/*' -o -name '*.pem' -o -name '*.key' -o -name '*.token' \) -print -quit | grep -q .; then
  die 'release staging tree contains forbidden secret or queue material'
fi

archive_name="$APP-$VERSION-linux-$ARCH.tar.gz"
archive_path="$OUTPUT_DIR/$archive_name"
checksum_path="$OUTPUT_DIR/SHA256SUMS"
tmp_archive="$OUTPUT_DIR/.${archive_name}.tmp.$$"
[[ ! -e "$archive_path" && ! -L "$archive_path" ]] || die "refusing to overwrite existing archive: $archive_path"
[[ ! -e "$checksum_path" && ! -L "$checksum_path" ]] || die "refusing to overwrite existing checksum file: $checksum_path"
[[ ! -e "$tmp_archive" && ! -L "$tmp_archive" ]] || die "temporary archive name is unexpectedly occupied: $tmp_archive"

# These two root-owned archive members make an extracted package independently
# usable with install.sh's required --binary-sha256 argument.  The release
# SHA256SUMS still protects the complete tarball before extraction.
printf '%s\n' "$VERSION" > "$STAGING_DIR/$ROOT_NAME/VERSION"
chmod 0644 "$STAGING_DIR/$ROOT_NAME/VERSION"
(
  cd -- "$STAGING_DIR/$ROOT_NAME"
  sha256sum -- "$APP" > "$APP.sha256"
)
chmod 0644 "$STAGING_DIR/$ROOT_NAME/$APP.sha256"

# GNU tar's sorting, numeric ownership and epoch mtime make output independent
# of the checkout user, timestamp, and filesystem enumeration order.  gzip -n
# removes the gzip header timestamp and original filename.
(
  cd -- "$STAGING_DIR"
  LC_ALL=C tar --format=posix --sort=name --mtime='@0' --owner=0 --group=0 --numeric-owner -cf - "$ROOT_NAME"
) | gzip -n > "$tmp_archive"
mv -f -- "$tmp_archive" "$archive_path"

# Verify the final archive names match the deterministic staged tree exactly.
mapfile -t expected_entries < <((cd -- "$STAGING_DIR" && LC_ALL=C find "$ROOT_NAME" -print | LC_ALL=C sort))
mapfile -t archive_entries < <(LC_ALL=C tar -tzf "$archive_path" | sed 's:/$::' | LC_ALL=C sort -u)
for index in "${!expected_entries[@]}"; do
  expected_entries[$index]="${expected_entries[$index]%/}"
done
[[ "$(printf '%s\n' "${expected_entries[@]}")" == "$(printf '%s\n' "${archive_entries[@]}")" ]] || die 'final archive file set does not match the release allowlist'

(cd -- "$OUTPUT_DIR" && sha256sum -- "$archive_name" > "$(basename -- "$checksum_path")")
printf 'created %s\ncreated %s\n' "$archive_path" "$checksum_path"
