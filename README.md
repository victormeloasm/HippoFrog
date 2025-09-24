# HippoFrog (ECCFROG522PP) — Twist-Safe ECDH + AES-256-GCM

![ECCFROG522PP Logo](img/hpp.png)

**Download:** [HippoFrog.zip](https://github.com/victormeloasm/HippoFrog/releases/download/Hippo/HippoFrog.zip)

[![Reproducibility](https://img.shields.io/badge/reproducible-YES-brightgreen)](https://github.com/victormeloasm/HippoFrog/blob/main/SAGE%20Math%20Scripts/Reproducing_ECCFROG522PP_home.py)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://github.com/victormeloasm/HippoFrog/blob/main/LICENSE)


## Table of Contents

* [1. Overview](#1-overview)
* [2. Cryptographic Design](#2-cryptographic-design)
  * [2.1. Curve: ECCFROG522PP](#21-curve-eccfrog522pp)
  * [2.2. ECDH, HKDF, AES-GCM](#22-ecdh-hkdf-aes-gcm)
  * [2.3. Public-Key Validation](#23-public-key-validation)
* [3. File Format](#3-file-format)
  * [3.1. Header Layout (86 bytes)](#31-header-layout-86-bytes)
  * [3.2. Complete Blob Layout](#32-complete-blob-layout)
  * [3.3. AAD Binding](#33-aad-binding)
* [4. Build](#4-build)
* [5. Quick Start](#5-quick-start)
* [6. Commands](#6-commands)
* [7. Key Management](#7-key-management)
* [8. Internals / Code Map](#8-internals--code-map)
* [9. Full Specification: ECCFROG522PP](#9-full-specification-eccfrog522pp-presunto-power)
* [10. License](#10-license)

---

## 1. Overview

**HippoFrog** is a professional‑grade file encryption tool based on the custom 522‑bit prime‑field curve **ECCFROG522PP** (cofactor 1, `a = -9`). It uses ephemeral **ECDH → HKDF‑SHA‑256 → AES‑256‑GCM**, authenticating metadata via AAD. The CLI is minimal and stable; the on‑disk format is deterministic and self‑describing.

## 2. Cryptographic Design

### 2.1. Curve: ECCFROG522PP

- **Field:** 522‑bit prime; parameters in `include/hf/params.hpp`.
- **Equation:** `y² = x³ + a·x + b (mod p)` with `a = −9`.
- **Base point:** `G=(GX,GY)` with prime order **N** and **cofactor 1**.
- **Parameter hash** binds active parameters into each ciphertext:
  ```
  param_hash = SHA-256(P_DEC | "|" | A_INT | "|" | B_DEC | "|" | N_DEC | "|" | GX_DEC | "|" | GY_DEC)
  ```

### 2.2. ECDH, HKDF, AES-GCM

- **ECDH:** sender uses an ephemeral key; shared secret from recipient’s public key.
- **HKDF‑SHA‑256:** `salt = 32B` random; `info = param_hash || "HippoFrog v2.2 AES-256-GCM"`; output key = 32B.
- **AES‑256‑GCM:** `IV = 12B` random; `tag = 16B` appended.

### 2.3. Public-Key Validation

Every external public key `Q` is checked:
1. **Canonical compressed format:** 67 bytes, prefix `0x02/0x03`.
2. **On‑curve on ECCFROG522PP**.
3. **Non‑infinity** (`Q ≠ O`).
4. **Subgroup confinement:** `[N]Q = O` (cofactor 1).

![ECCFROG522PP Security](img/security.png)

## 3. File Format

### 3.1. Header Layout (86 bytes)

**Deterministic byte‑wise encoding (endianness‑safe; no struct/memcpy)**

| Offset | Size | Field        | Notes                                        |
|:------:|:----:|--------------|----------------------------------------------|
| 0      | 4    | `magic`      | ASCII `"HFv1"`                               |
| 4      | 1    | `version`    | `1`                                          |
| 5      | 3    | `reserved`   | zero                                         |
| 8      | 32   | `param_hash` | SHA‑256 of curve parameters                   |
| 40     | 32   | `salt`       | HKDF salt                                    |
| 72     | 12   | `iv`         | AES‑GCM IV                                   |
| 84     | 2    | `eph_len`    | **uint16, little‑endian (fixed)** = `67`     |

### 3.2. Complete Blob Layout

```
[ Header (86B) ]
[ EphemeralPublicCompressed (eph_len) ]
[ Ciphertext (...) ]
[ GCM Tag (16B) ]
[ CiphertextLength (8B, big-endian) ]
```

### 3.3. AAD Binding

**AAD = `Header || EphemeralPublicCompressed`** — changes in header or ephemeral public invalidate the tag.

![ECCFROG522PP Benchmark](img/bh.png)

## 4. Build

Dependencies: **C++20**, **OpenSSL 3.x**. The script prefers **clang++** and **lld** when available.

```bash
# Portable build
./build.sh

# Optimized
./build.sh release      # adds -march=native -flto

# Strict (CI)
./build.sh strict       # -Werror -pedantic

# Dev sanitizers
./build.sh asan         # -fsanitize=address,undefined
```

Binary output: `./bin/HippoFrog`

## 5. Quick Start

```bash
./bin/HippoFrog --generate-keys       # writes keys/priv.pem, keys/pub.pem, keys/pub.comp
./bin/HippoFrog --validate-keys       # on-curve + subgroup checks
echo "hello" > note.txt
./bin/HippoFrog --encrypt note.txt    # produces note.txt.hf
./bin/HippoFrog --decrypt note.txt.hf # recovers plaintext
```

## 6. Commands

```
HippoFrog CLI
Usage:
  HippoFrog --generate-keys
  HippoFrog --validate-keys
  HippoFrog --b
  HippoFrog --encrypt <file>
  HippoFrog --decrypt <file.hf>
```

## 7. Key Management

- Public distribution: `keys/pub.pem` (and `keys/pub.comp` if desired).
- Private key on POSIX is stored as `keys/priv.pem` with permission `0600`.
- Rotate keys with `--generate-keys` and redistribute the public key.

## 8. Internals / Code Map

```
include/hf/
  params.hpp        # curve params + param_hash()
  backend.hpp       # backend interface
  crypto.hpp        # HKDF + AES-256-GCM (EVP)
  cmds.hpp          # CLI entrypoints

src/
  backend_openssl.cpp  # group init, point checks, ECDH, compression, header pack/unpack
  cmds.cpp             # AAD glue, file IO, CLI dispatcher
  main.cpp             # CLI front-end
```

![ECCFROG522PP Comparison](img/comparison.png)

## 9. Full Specification: ECCFROG522PP (Presunto Power)

# Full Specification of ECCFrog522PP (Presunto Power)

## 1. Introduction
* Curve name: ECCFrog522PP (Presunto Power)
* Generated: 2025-08-25 UTC
* Seed: ECCFrog522PP|v1
* Method: Deterministic generation via BLAKE3, parallelized search on Ryzen 9 5950X (32 cores, 128 GB RAM).

## 2. Field parameters
* Prime p (decimal):
6864797660130609714981900799081393217269435300143305409394463459185543183397656052122559640661454554977296311391480858037121987999716643812574028291115058039
* Prime p (hex):
0x20000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000377
* Bits: 522

## 3. Curve parameters
* Equation: y² = x³ - 9x + b mod p
* a: -9
* b (decimal):
6611391361841958508604524699377447911389994900129754213077683112250964195093882510934154923371011820554254572559896136823993565633006955666197428760619911
* b (hex):
0x7e3bceccfd45483334adf221158d1db7ff8456d746fe5f8844ce317ed31514d9c323c6adb78c10d36df0fb1111936e1be21d55444c49ace1168053242e5a2b87
* b index i: 1,294,798
* j-invariant (hex):
0x18439cdd3687bd3f0ad0125a314b06742c759b642c0483cb1aa6370947bd4b8aee06d20e466d306ab5ed2b3a9ca59703d27f09c8cc76c6b61fb3fd5af4f5d1688e5

## 4. Security checks
* Order N (decimal):
6864797660130609714981900799081393217269435300143305409394463459185543183397654707839930998069072437178898634323218419738245117910726080434907495541251156283
* Bits: 521
* Cofactor: 1 (N is prime)
* Trace t:
1344282628642592382117798397677068262438298876870088990563377666532749863901757
* Anti-MOV: No k ≤ 200 with p^k ≡ 1 mod N
* CM discriminant:
D = t² - 4p = -25652094854852200923182489755562709400813783410907538423881259128294063827498368666061775444493529979367517268977200639940503231230605133844631506932712545107
* CM small-squarefree check: PASS up to 100k

## 5. Twist security
* Twist order (decimal):
6864797660130609714981900799081393217269435300143305409394463459185543183397657396405188283253836672775693988459743296335998858088707207190240561040978959797
* Largest proven prime factor of twist:
85873302312087786179581201124346620848743889870570863629357444355031125247340631170553136478826092653027782845595417824845809510622924496694319073328817
* Large prime bits: 505

## 6. Embedding degree
* Lower bound LB: 14
* LB bits: ~3.81

## 7. Basepoint generation
* Basepoint G (deterministic from seed):
Gx = 11483659870055913964623536371313631260976767098619949198405802655079012131788815900015100098140592301158799072401266653548293144687306675149107389798128134
* Gy = 3038694457428442024388132117370677943127343938512113463034318638709600451136325747025138610802391491914091276481105699353919202494902810686593030172286395020
* Basepoint index j: 0 (astonishing luck)
* Order(G) = N

## 8. Reproducibility instructions
* b = BLAKE3(seed|b|i) mod p; choose the first b that is prime and non-singular.
* G = BLAKE3(seed|G|j) mod p; choose the first point of order N.
* Final proofs: ECPP for b, N, and the large prime factor of #twist.
* Software: SageMath + BLAKE3.

## 9. System and timing info
* Platform: Linux-6.14.0-28-generic-x86_64
* CPU: AMD Ryzen 9 5950X (32 logical cores)
* RAM: 130.4 GB
* Runtime: ~216,000 seconds (~60h)
* Parallelism: processes=32, batch=2048, chunksize=32, ctx=spawn

## 10. Appendix
* SHA256(report):
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
* BLAKE3(report):
af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262

Security summary:
* ~260-bit classical security (same ballpark as NIST P-521)
* Cofactor = 1
* Twist security > 500 bits
* Embedding degree safe
* Fully reproducible generation, no hidden parameters
* Rare: ~1 in millions of candidates yields a curve this "clean"

## 10. License

MIT © Víctor Duarte Melo
