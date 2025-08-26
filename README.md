# HippoFrog

**HippoFrog v2.2** — ECDH + AES-256-GCM on a custom ~521‑bit curve (prime field, a = −9, cofactor = 1) using OpenSSL 3.x.

> ⚠️ **Security note**: This is a research/experimental implementation using a non‑standard curve. Do not use for production without an independent cryptographic review.

## Build

Ubuntu/Debian:
```bash
sudo apt-get update
sudo apt-get install -y build-essential lld pkg-config libssl-dev
make clean && make -j$(nproc)
```
Binary: `bin/HippoFrog`

## Quick start

```bash
# 1) Generate a fresh keypair
./bin/HippoFrog --generate-keys   # writes priv.pem and pub.pem

# 2) Validate keys (on-curve + subgroup, twist-safe)
./bin/HippoFrog --validate-keys

# 3) Encrypt / decrypt with ECDH + HKDF(SHA-256) + AES-256-GCM
echo "hippos love gimonada" > note.txt
./bin/HippoFrog --encrypt note.txt      # produces note.txt.hf
./bin/HippoFrog --decrypt note.txt.hf   # recovers note.txt.dec
diff -q note.txt note.txt.dec && echo OK
```

### Implementation highlights
- **Provider**: OpenSSL 3.x (legacy EC APIs are used with deprecation warnings silenced at compile time).
- **Public-key hygiene** (twist/invalid-curve resistant):
  - On-curve check.
  - Prime‑order subgroup check: verify `n·Q = O` (cofactor = 1).
  - Reject identity.
- **Key derivation**: ECDH → HKDF(SHA‑256) → 32‑byte key → AES‑256‑GCM.

## CI (GitHub Actions)
- Ubuntu latest, installs OpenSSL 3.x.
- Builds the project and runs a smoke test: keygen, key validation, encrypt+decrypt round‑trip.

## License
MIT © Víctor Duarte Melo
