# eccfrog522PP_reproduce_full.sage
# Complete, self-contained reproduction & verification of ECCFrog522PP
# Correct b-derivation: b = (BLAKE3(seed|b|i) mod (p-3)) + 2

import os, sys, math, time, platform, hashlib
from datetime import datetime, timezone
from sage.all import ZZ, GF, EllipticCurve, is_prime, Integer

try:
    import blake3
except Exception:
    print("[!] Missing 'blake3'. Install with:\n    ./sage -python -m pip install --user blake3")
    sys.exit(1)

# ---------------- Config ----------------
REPORT_TXT = "eccfrog522PP_reproduce_report.txt"
REPORT_MD  = "eccfrog522PP_reproduce_report.md"
FACTS_CSV  = "eccfrog522PP_reproduce_facts.csv"

DO_PARICARD = True   # Prove group order via PARI/ECPP (E.cardinality(algorithm="pari"))
K_MOV       = 200
CM_SQF_LIM  = 100000

# ---------------- Published constants ----------------
SEED = "ECCFrog522PP|v1"

p = ZZ("6864797660130609714981900799081393217269435300143305409394463459185543183397656052122559640661454554977296311391480858037121987999716643812574028291115058039")
a = ZZ(-9)

b_index = 1294798
G_index = 0

b_pub = ZZ("6611391361841958508604524699377447911389994900129754213077683112250964195093882510934154923371011820554254572559896136823993565633006955666197428760619911")

N_pub = ZZ("6864797660130609714981900799081393217269435300143305409394463459185543183397654707839930998069072437178898634323218419738245117910726080434907495541251156283")
t_pub = ZZ("1344282628642592382117798397677068262438298876870088990563377666532749863901757")

Gx_pub = ZZ("11483659870055913964623536371313631260976767098619949198405802655079012131788815900015100098140592301158799072401266653548293144687306675149107389798128134")
Gy_pub = ZZ("3038694457428442024388132117370677943127343938512113463034318638709600451136325747025138610802391491914091276481105699353919202494902810686593030172286395020")

j_hex_pub = "0x18439cdd3687bd3f0ad0125a314b06742c759b642c0483cb1aa6370947bd4b8aee06d20e466d306ab5ed2b3a9ca59703d27f09c8cc76c6b61fb3fd5af4f5d1688e5"

twist_large_prime_pub = ZZ("85873302312087786179581201124346620848743889870570863629357444355031125247340631170553136478826092653027782845595417824845809510622924496694319073328817")

# ---------------- Utils ----------------
def now_iso_utc():
    return datetime.now(timezone.utc).isoformat()

def b_from_seed(seed, i, p_int):
    # b = (BLAKE3(seed|b|i) mod (p-3)) + 2  ∈ [2, p-2]
    h = blake3.blake3(f"{seed}|b|{i}".encode()).digest(length=64)
    return (int.from_bytes(h, "big") % (p_int - 3)) + 2

def gx_from_seed(seed, j, p_int):
    # For basepoint candidate x we just need an element in F_p
    h = blake3.blake3(f"{seed}|G|{j}".encode()).digest(length=64)
    return int.from_bytes(h, "big") % p_int

def hasse_bounds(p_):
    two_sqrt_p = 2 * math.isqrt(int(p_))
    return p_ + 1 - two_sqrt_p, p_ + 1 + two_sqrt_p

def nonsingular(a_, b_, p_):
    # Δ (scaled) = 4 a^3 + 27 b^2 mod p != 0
    return ((4 * pow(int(a_), 3, int(p_)) + 27 * pow(int(b_), 2, int(p_))) % int(p_)) != 0

def anti_mov_ok(p_, N_, kmax):
    for k in range(1, kmax + 1):
        if pow(int(p_), k, int(N_)) == 1:
            return False, k
    return True, None

def squarefree_sanity(n, limit):
    n = abs(int(n))
    for q in range(2, limit + 1):
        q2 = q * q
        if q2 > n:
            break
        if n % q2 == 0:
            return False, q
    return True, None

# ---------------- Main ----------------
def main():
    wall_start = time.time()
    info = {
        "utc": now_iso_utc(),
        "platform": platform.platform(),
        "python": sys.version.splitlines()[0],
        "sage_threads": os.environ.get("SAGE_NUM_THREADS", ""),
        "omp_threads": os.environ.get("OMP_NUM_THREADS", ""),
        "openblas_threads": os.environ.get("OPENBLAS_NUM_THREADS", ""),
        "do_paricard": DO_PARICARD,
        "k_mov": K_MOV,
        "cm_sqf_lim": CM_SQF_LIM,
    }

    p_int = int(p)

    # 1) Deterministic re-derivation of b and Gx
    t0 = time.time()
    b_derived = b_from_seed(SEED, b_index, p_int)
    gx_derived = gx_from_seed(SEED, G_index, p_int)
    t1 = time.time()

    # 2) Build the curve using the **published** b (exact canonical parameters)
    F = GF(p)
    E = EllipticCurve(F, [a, F(b_pub)])

    # 3) Invariants & checks
    t2 = time.time()

    # j-invariant
    j_val = ZZ(E.j_invariant())
    j_match = (hex(int(j_val)).lower() == j_hex_pub.lower())

    # Non-singularity and b primality
    nonsing = nonsingular(a, b_pub, p)
    b_is_prime = is_prime(ZZ(b_pub))

    # Hasse via published trace
    L, U = hasse_bounds(p)
    N_from_t = p + 1 - t_pub
    hasse_ok = (N_from_t >= L and N_from_t <= U)
    N_eq_pub_via_t = (N_from_t == N_pub)

    # Optional PARI/ECPP group order
    if DO_PARICARD:
        N_pari = E.cardinality(algorithm="pari")
        N_pari_ok = (N_pari == N_pub)
        N_final = N_pari
    else:
        N_pari = None
        N_pari_ok = None
        N_final = N_from_t

    # N primality ⇒ cofactor=1
    N_is_prime = is_prime(ZZ(N_pub))
    cofactor = Integer(1) if N_is_prime else None

    # Twist order and factor
    N_twist = 2 * p + 2 - N_pub
    twist_q = twist_large_prime_pub
    twist_q_is_prime = is_prime(twist_q)
    twist_q_divides = (N_twist % twist_q == 0)

    # Anti-MOV
    mov_ok, mov_bad_k = anti_mov_ok(p, N_pub, K_MOV)

    # CM discriminant
    D = t_pub * t_pub - 4 * p
    D_sign = "negative" if D < 0 else ("zero" if D == 0 else "positive")
    D_abs_bits = ZZ(abs(D)).nbits()
    D_sf_ok, D_sf_bad = squarefree_sanity(D, CM_SQF_LIM)

    # Basepoint check
    P = E(Gx_pub, Gy_pub)
    basepoint_ok = ((N_pub * P).is_zero())

    t3 = time.time()

    timings = {
        "derive_hashes_s": t1 - t0,
        "invariants_and_checks_s": t3 - t2,
        "wall_total_s": time.time() - wall_start,
    }

    # ---------------- Write .txt ----------------
    lines = []
    lines.append("ECCFrog522PP Reproduction Report")
    lines.append("================================")
    lines.append("")
    lines.append("Run Info")
    lines.append("--------")
    lines.append(f"UTC: {info['utc']}")
    lines.append(f"Platform: {info['platform']}")
    lines.append(f"Python:   {info['python']}")
    lines.append(f"SAGE_NUM_THREADS={info['sage_threads']}  OMP_NUM_THREADS={info['omp_threads']}  OPENBLAS_NUM_THREADS={info['openblas_threads']}")
    lines.append(f"PARI/ECPP cardinality: {'ON' if info['do_paricard'] else 'OFF'}")
    lines.append("")
    lines.append("Parameters (published)")
    lines.append("----------------------")
    lines.append(f"Field prime p (bits): {p.nbits()}  (p dec)")
    lines.append(f"{p}")
    lines.append(f"a = {a}")
    lines.append(f"b index i = {b_index}")
    lines.append(f"b (published) = {b_pub}")
    lines.append(f"Seed = {SEED}")
    lines.append(f"G index j = {G_index}")
    lines.append(f"Gx = {Gx_pub}")
    lines.append(f"Gy = {Gy_pub}")
    lines.append(f"N (published) = {N_pub}")
    lines.append(f"t (published) = {t_pub}")
    lines.append(f"j-invariant (published hex) = {j_hex_pub}")
    lines.append(f"Twist large prime factor (published) = {twist_q}")
    lines.append("")
    lines.append("Deterministic Regeneration")
    lines.append("--------------------------")
    lines.append("b rule: b = (BLAKE3(seed|b|i) mod (p-3)) + 2")
    lines.append(f"b derived = {b_derived}")
    lines.append(f"b_derived == b_published: {'YES' if ZZ(b_derived) == b_pub else 'NO'}")
    lines.append(f"Gx derived (BLAKE3(seed|G|j) mod p) = {gx_derived}")
    lines.append(f"gx_derived == Gx_published: {'YES' if ZZ(gx_derived) == Gx_pub else 'NO'}")
    lines.append("")
    lines.append("Core Checks")
    lines.append("-----------")
    lines.append(f"Non-singular (Δ != 0 mod p): {'YES' if nonsing else 'NO'}")
    lines.append(f"b is prime (ECPP): {'YES' if b_is_prime else 'NO'}")
    lines.append(f"j-invariant (hex): {hex(int(j_val))}")
    lines.append(f"j matches published: {'YES' if j_match else 'NO'}")
    lines.append(f"Hasse bounds: [{hasse_bounds(p)[0]}, {hasse_bounds(p)[1]}]")
    lines.append(f"N_from_t = {N_from_t}  (via t)")
    lines.append(f"N_from_t within Hasse: {'YES' if hasse_ok else 'NO'}")
    lines.append(f"N_from_t == N_published: {'YES' if N_eq_pub_via_t else 'NO'}")
    if DO_PARICARD:
        lines.append(f"N_pari = {N_pari}  (PARI/ECPP)")
        lines.append(f"N_pari == N_published: {'YES' if N_pari_ok else 'NO'}")
    lines.append(f"N is prime (ECPP): {'YES' if N_is_prime else 'NO'}")
    lines.append(f"Cofactor: {cofactor}")
    lines.append("")
    lines.append("Twist Security")
    lines.append("--------------")
    lines.append(f"N_twist = 2p + 2 - N = {N_twist}")
    lines.append(f"Twist large prime q is prime: {'YES' if twist_q_is_prime else 'NO'}")
    lines.append(f"q | N_twist: {'YES' if twist_q_divides else 'NO'}")
    lines.append("")
    lines.append("Anti-MOV")
    lines.append("--------")
    if mov_ok:
        lines.append(f"p^k != 1 (mod N) for all 1 ≤ k ≤ {K_MOV} : PASS")
    else:
        lines.append(f"Found k ≤ {K_MOV} with p^k ≡ 1 (mod N): k={mov_bad_k} : FAIL")
    lines.append("")
    lines.append("CM Discriminant (sanity)")
    lines.append("------------------------")
    lines.append(f"D = t^2 - 4p = {D}")
    lines.append(f"D sign: {'negative' if D < 0 else ('zero' if D == 0 else 'positive')}   |D| bits: {ZZ(abs(D)).nbits()}")
    if D_sf_ok:
        lines.append(f"No small square factor up to {CM_SQF_LIM}: PASS")
    else:
        lines.append(f"Has small square factor q^2 (q={D_sf_bad}) ≤ {CM_SQF_LIM}: ATTENTION")
    lines.append("")
    lines.append("Basepoint")
    lines.append("---------")
    lines.append(f"G = (Gx, Gy) on E: {'YES' if P in E else 'NO'}")
    lines.append(f"Order(G) = N: {'YES' if basepoint_ok else 'NO'}")
    lines.append("")
    lines.append("Timings")
    lines.append("-------")
    lines.append(f"Hash derivations: {timings['derive_hashes_s']:.3f} s")
    lines.append(f"Invariants & checks: {timings['invariants_and_checks_s']:.3f} s")
    lines.append(f"Wall total: {timings['wall_total_s']:.3f} s")
    lines.append("")
    # Fingerprints (for this .txt content)
    txt_blob = ("\n".join(lines)).encode()
    sha256 = hashlib.sha256(txt_blob).hexdigest()
    b3 = blake3.blake3(txt_blob).hexdigest()
    lines.append("Fingerprints (this .txt section)")
    lines.append("--------------------------------")
    lines.append(f"SHA256: {sha256}")
    lines.append(f"BLAKE3: {b3}")
    lines.append("")
    with open(REPORT_TXT, "w") as f:
        f.write("\n".join(lines))

    # ---------------- Write .md ----------------
    md = []
    md.append("# ECCFrog522PP — Full Reproducibility & Security Verification")
    md.append("")
    md.append(f"- **UTC**: {info['utc']}")
    md.append(f"- **Platform**: {info['platform']}")
    md.append(f"- **Python/Sage**: {info['python']}")
    md.append(f"- **Threads**: SAGE={info['sage_threads']} OMP={info['omp_threads']} OPENBLAS={info['openblas_threads']}")
    md.append(f"- **Cardinality proof**: {'PARI/ECPP enabled' if info['do_paricard'] else 'via t only'}")
    md.append("")
    md.append("## Parameters (published)")
    md.append(f"- Field prime bits: **{p.nbits()}**")
    md.append(f"- `p` (dec): `{p}`")
    md.append(f"- `a = {a}`")
    md.append(f"- `b` index `i = {b_index}` → `b (dec) = {b_pub}`")
    md.append(f"- `Seed = {SEED}`")
    md.append(f"- Basepoint index `j = {G_index}`")
    md.append(f"- `Gx = {Gx_pub}`")
    md.append(f"- `Gy = {Gy_pub}`")
    md.append(f"- Order `N` (dec): `{N_pub}`")
    md.append(f"- Trace `t` (dec): `{t_pub}`")
    md.append(f"- j-invariant (hex): `{j_hex_pub}`")
    md.append(f"- Twist large prime factor (dec): `{twist_q}`")
    md.append("")
    md.append("## Deterministic Regeneration")
    md.append("`b = (BLAKE3(seed|b|i) mod (p-3)) + 2`, `Gx = BLAKE3(seed|G|j) mod p`")
    md.append(f"- `b_derived == b_published`: **{'YES' if ZZ(b_derived) == b_pub else 'NO'}**")
    md.append(f"- `gx_derived == Gx_published`: **{'YES' if ZZ(gx_derived) == Gx_pub else 'NO'}**")
    md.append("")
    md.append("## Core Checks")
    md.append(f"- Non-singularity: **{'PASS' if nonsing else 'FAIL'}**")
    md.append(f"- `b` is prime (ECPP): **{'PASS' if b_is_prime else 'FAIL'}**")
    md.append(f"- j-invariant matches: **{'PASS' if j_match else 'FAIL'}**  _(actual={hex(int(j_val))})_")
    md.append(f"- Hasse: `[{L}, {U}]`; `N_from_t = {N_from_t}` → **{'PASS' if hasse_ok else 'FAIL'}**")
    md.append(f"- `N_from_t == N_published`: **{'PASS' if N_eq_pub_via_t else 'FAIL'}**")
    if DO_PARICARD:
        md.append(f"- `N_pari == N_published`: **{'PASS' if N_pari_ok else 'FAIL'}**  _(N_pari={N_pari})_")
    md.append(f"- `N` is prime (ECPP): **{'PASS' if N_is_prime else 'FAIL'}** → Cofactor = **{cofactor}**")
    md.append("")
    md.append("## Twist Security")
    md.append(f"- `N_twist = 2p + 2 - N` = `{N_twist}`")
    md.append(f"- Large factor `q` is prime: **{'PASS' if twist_q_is_prime else 'FAIL'}**, `q | N_twist`: **{'PASS' if twist_q_divides else 'FAIL'}**")
    md.append("")
    md.append("## Anti-MOV")
    md.append(f"- For all `k ≤ {K_MOV}`, `p^k != 1 (mod N)`: **{'PASS' if mov_ok else f'FAIL (k={mov_bad_k})'}**")
    md.append("")
    md.append("## CM Discriminant (sanity)")
    md.append(f"- `D = t^2 - 4p = {D}`  (sign: **{'negative' if D < 0 else ('zero' if D == 0 else 'positive')}**, `|D|` bits: **{ZZ(abs(D)).nbits()}**)")
    md.append(f"- No small square factor up to `{CM_SQF_LIM}`: **{'PASS' if D_sf_ok else f'ATTENTION (q={D_sf_bad})'}**")
    md.append("")
    md.append("## Basepoint")
    md.append(f"- `G=(Gx,Gy)` lies on E: **{'YES' if P in E else 'NO'}**")
    md.append(f"- `ord(G) = N`: **{'PASS' if basepoint_ok else 'FAIL'}**")
    md.append("")
    md.append("## Timings")
    md.append(f"- Hash derivations: `{timings['derive_hashes_s']:.3f} s`")
    md.append(f"- Invariants & checks: `{timings['invariants_and_checks_s']:.3f} s`")
    md.append(f"- Wall total: `{timings['wall_total_s']:.3f} s`")
    md.append("")
    md_blob = "\n".join(md).encode()
    md_sha256 = hashlib.sha256(md_blob).hexdigest()
    md_b3 = blake3.blake3(md_blob).hexdigest()
    md.append("## Fingerprints (this .md content)")
    md.append(f"- SHA256: `{md_sha256}`")
    md.append(f"- BLAKE3: `{md_b3}`")
    with open(REPORT_MD, "w") as f:
        f.write("\n".join(md))

    # ---------------- Write .csv ----------------
    kv = []
    def add(k, v): kv.append(f"{k},{v}")
    add("utc", info["utc"]); add("platform", info["platform"]); add("python", info["python"])
    add("p_bits", p.nbits()); add("a", a); add("seed", SEED)
    add("b_index", b_index); add("b_pub", b_pub); add("b_derived", b_derived); add("b_eq", ZZ(b_derived) == b_pub)
    add("G_index", G_index); add("Gx_pub", Gx_pub); add("gx_derived", gx_derived); add("gx_eq", ZZ(gx_derived) == Gx_pub)
    add("Gy_pub", Gy_pub)
    L, U = hasse_bounds(p); add("hasse_L", L); add("hasse_U", U)
    add("j_hex_pub", j_hex_pub); add("j_hex_actual", hex(int(j_val))); add("j_match", j_match)
    add("N_pub", N_pub); add("t_pub", t_pub); add("N_from_t", N_from_t); add("N_from_t_eq_pub", N_eq_pub_via_t)
    if DO_PARICARD: add("N_pari", N_pari); add("N_pari_eq_pub", N_pari_ok)
    add("N_is_prime", is_prime(N_pub)); add("cofactor", 1 if N_is_prime else 0)
    add("N_twist", N_twist); add("twist_q", twist_q); add("twist_q_is_prime", twist_q_is_prime); add("twist_q_divides", twist_q_divides)
    add("mov_ok", mov_ok); add("mov_bad_k", mov_bad_k if mov_bad_k else "")
    add("D", D); add("D_bits", ZZ(abs(D)).nbits()); add("D_small_sqf_ok", D_sf_ok); add("D_small_sqf_badq", D_sf_bad if D_sf_bad else "")
    add("basepoint_ok", basepoint_ok)
    add("timing_hash_deriv_s", f"{timings['derive_hashes_s']:.6f}")
    add("timing_invariants_s", f"{timings['invariants_and_checks_s']:.6f}")
    add("timing_wall_total_s", f"{timings['wall_total_s']:.6f}")
    with open(FACTS_CSV, "w") as f:
        f.write("key,value\n"); f.write("\n".join(kv))

    print(f"✅ Reproduction complete.\n - {REPORT_TXT}\n - {REPORT_MD}\n - {FACTS_CSV}")

if __name__ == "__main__":
    main()
