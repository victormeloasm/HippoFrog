#!/usr/bin/env bash
set -euo pipefail

echo "[*] Building HippoFrog v2.2"

# Normalize timestamps to avoid 'clock skew detected'
find . -type f -exec touch {} + || true

# Prefer lld if available
if command -v ld.lld >/dev/null 2>&1; then
  export LDFLAGS="${LDFLAGS:-} -fuse-ld=lld"
  echo "[*] Using lld"
fi

# Extra aggressive flags
export CXXFLAGS="${CXXFLAGS:-} -fno-semantic-interposition -fomit-frame-pointer"
make clean
make -j"$(nproc)"
strip -s bin/HippoFrog || true
echo "[*] Done -> bin/HippoFrog"
