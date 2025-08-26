#!/usr/bin/env bash
set -euo pipefail

# HippoFrog build.sh — compile to ./bin/HippoFrog, fix mtimes, prefer clang++ + lld
# Usage:
#   ./build.sh          # portable build
#   ./build.sh release  # -march=native -flto
#   ./build.sh strict   # -Werror -pedantic
#   ./build.sh asan     # dev: Address/UB sanitizers

MODE="${1:-portable}"

echo "[1/6] Fixing file modification times..."
now_ts="$(date +%s)"
if touch -d "@${now_ts}" . 2>/dev/null; then
  find . -type f -exec touch -d "@${now_ts}" {} +
else
  find . -type f -exec touch {} +
fi

echo "[2/6] Selecting compiler and linker..."
if command -v clang++ >/dev/null 2>&1; then
  export CXX=clang++
elif command -v g++ >/dev/null 2>&1; then
  export CXX=g++
else
  echo "No C++ compiler found (need clang++ or g++)." >&2; exit 1
fi
echo "  CXX=${CXX}"

USE_LLD=0
if command -v ld.lld >/dev/null 2>&1 || command -v lld >/dev/null 2>&1; then
  USE_LLD=1
fi

EXTRA_LDFLAGS=""
if [ "${USE_LLD}" -eq 1 ]; then
  EXTRA_LDFLAGS+=" -fuse-ld=lld -Wl,-O2"
  echo "  Using lld"
else
  echo "  lld not found; using system linker"
fi

echo "[3/6] Detecting OpenSSL..."
OPENSSL_CFLAGS=""
OPENSSL_LIBS="-lssl -lcrypto"
if command -v pkg-config >/dev/null 2>&1 && pkg-config --exists openssl; then
  OPENSSL_CFLAGS="$(pkg-config --cflags openssl)"
  OPENSSL_LIBS="$(pkg-config --libs openssl)"
fi
echo "  OPENSSL_CFLAGS=${OPENSSL_CFLAGS}"
echo "  OPENSSL_LIBS=${OPENSSL_LIBS}"

echo "[4/6] Configuring flags..."
BASE_CXXFLAGS="${OPENSSL_CFLAGS}"
if [ "${MODE}" = "release" ]; then
  BASE_CXXFLAGS+=" -march=native -mtune=native -flto"
elif [ "${MODE}" = "strict" ]; then
  BASE_CXXFLAGS+=" -Werror -pedantic"
fi

if [ "${MODE}" = "asan" ]; then
  BASE_CXXFLAGS+=" -O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer"
fi
export CXXFLAGS="${CXXFLAGS:-} ${BASE_CXXFLAGS}"
export LDFLAGS="${EXTRA_LDFLAGS} ${LDFLAGS:-}"
export LDLIBS="${OPENSSL_LIBS}"

echo "[5/6] Building HippoFrog into ./bin/HippoFrog ..."
make clean >/dev/null 2>&1 || true
make -j"$(nproc || echo 1)"

echo "[6/6] Smoke tests..."
./bin/HippoFrog --generate-keys >/dev/null && echo "Keygen OK" || echo "Keygen FAILED"
./bin/HippoFrog --validate-keys >/dev/null && echo "Validate OK" || echo "Validate FAILED"

echo "Done. Binary at ./bin/HippoFrog"
