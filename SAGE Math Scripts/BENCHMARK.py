# bench_eccfrog522PP_compare.sage
# Benchmark comparativo — ECCFrog522PP vs secp256k1, NIST P-256, P-384, P-521
# Sem aliases: curvas definidas manualmente por (p, a, b).
# Saída: ecc_bench_results.txt

from sage.all import ZZ, GF, EllipticCurve
from sage.misc.randstate import set_random_seed
import time, statistics, os, platform, sys
from datetime import datetime, timezone

REPORT_FILE = "ecc_bench_results.txt"

# ---------------- Config ----------------
VARBASE_ITERS   = 200
FIXEDBASE_ITERS = 800
ECDH_ITERS      = 200
WARM_FIXEDBASE  = True

RNG_SEED = 1337
set_random_seed(RNG_SEED)

# ---------------- ECCFrog522PP (sua curva) ----------------
p_frog = ZZ("6864797660130609714981900799081393217269435300143305409394463459185543183397656052122559640661454554977296311391480858037121987999716643812574028291115058039")
a_frog = -9
b_frog = ZZ("6611391361841958508604524699377447911389994900129754213077683112250964195093882510934154923371011820554254572559896136823993565633006955666197428760619911")

def curve_eccfrog():
    F = GF(p_frog)
    E = EllipticCurve(F, [a_frog, F(b_frog)])
    return {"name":"ECCFrog522PP", "E":E, "fbits":p_frog.nbits(), "nbits":521}  # ordem ~521 bits (do seu relatório)

# ---------------- Curvas concorrentes (parâmetros oficiais) ----------------
def curve_secp256k1():
    p = ZZ(0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F)
    a = ZZ(0)                # y^2 = x^3 + 7
    b = ZZ(7)
    F = GF(p); E = EllipticCurve(F, [a, b])
    return {"name":"secp256k1", "E":E, "fbits":256, "nbits":256}

def curve_p256():
    p = ZZ(0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff)
    a = (p - 3)              # a = -3 mod p
    b = ZZ(0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B)
    F = GF(p); E = EllipticCurve(F, [a, F(b)])
    return {"name":"P-256", "E":E, "fbits":256, "nbits":256}

def curve_p384():
    p = ZZ(0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff)
    a = (p - 3)
    b = ZZ(0xb3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef)
    F = GF(p); E = EllipticCurve(F, [a, F(b)])
    return {"name":"P-384", "E":E, "fbits":384, "nbits":384}

def curve_p521():
    # P-521: p = 2^521 - 1, a = -3, b conforme FIPS 186-4
    p = (ZZ(1) << 521) - 1
    a = (p - 3)
    b = ZZ(0x0051953EB9618E1C9A1F929A21A0B68540EEA2DA725B99B315F3B8B489918EF109E156193951EC7E937B1652C0BD3BB1BF073573DF883D2C34F1EF451FD46B503F00)
    F = GF(p); E = EllipticCurve(F, [a, F(b)])
    return {"name":"P-521", "E":E, "fbits":521, "nbits":521}

def load_registry():
    # Ordem: concorrentes + sua curva (pra facilitar leitura)
    reg = [
        curve_secp256k1(),
        curve_p256(),
        curve_p384(),
        curve_p521(),
        curve_eccfrog(),
    ]
    return reg

# ---------------- Helpers ----------------
def now_utc_iso(): return datetime.now(timezone.utc).isoformat()

def percentile(values, q):
    if not values: return float('nan')
    data = sorted(values); n = len(data)
    import math
    idx = max(0, min(n-1, math.ceil(q*n) - 1))
    return data[idx]

def stats_block(times):
    med  = statistics.median(times)
    mean = statistics.fmean(times)
    p90  = percentile(times, 0.90)
    p99  = percentile(times, 0.99)
    return med, mean, p90, p99

def rate_from_median(med_s):
    return (1.0/med_s) if med_s > 0 else float('inf')

# ---------------- Benchs ----------------
def bench_varbase(curve, iters):
    E = curve["E"]; nbits = curve["nbits"]; times = []
    for _ in range(iters):
        P = E.random_point()
        k = ZZ.random_element(2**(nbits-1), 2**nbits)
        t0 = time.perf_counter(); _ = k*P; t1 = time.perf_counter()
        times.append(t1 - t0)
    med,mean,p90,p99 = stats_block(times)
    return {"median":med, "mean":mean, "p90":p90, "p99":p99, "rate_s":rate_from_median(med)}

def bench_fixed(curve, iters, warm=True):
    E = curve["E"]; nbits = curve["nbits"]
    P = E.random_point()
    if warm:
        for _ in range(8):
            _ = ZZ.random_element(2**(nbits-1), 2**nbits) * P
    times = []
    for _ in range(iters):
        k = ZZ.random_element(2**(nbits-1), 2**nbits)
        t0 = time.perf_counter(); _ = k*P; t1 = time.perf_counter()
        times.append(t1 - t0)
    med,mean,p90,p99 = stats_block(times)
    return {"median":med, "mean":mean, "p90":p90, "p99":p99, "rate_s":rate_from_median(med)}

def bench_ecdh(curve, iters):
    E = curve["E"]; nbits = curve["nbits"]; P = E.random_point(); times = []
    for _ in range(iters):
        a = ZZ.random_element(2**(nbits-1), 2**nbits)
        b = ZZ.random_element(2**(nbits-1), 2**nbits)
        t0 = time.perf_counter()
        A = a*P; B = b*P; S1 = a*B; S2 = b*A
        t1 = time.perf_counter()
        if S1 != S2: raise RuntimeError("ECDH mismatch")
        times.append(t1 - t0)
    med,mean,p90,p99 = stats_block(times)
    return {"median":med, "mean":mean, "p90":p90, "p99":p99, "rate_s":rate_from_median(med)}

# ---------------- Report ----------------
def write_report(fname, registry, varres, fixres, ecdhres, start, end):
    with open(fname, "w") as f:
        f.write("ECC Benchmark Report\n====================\n\n")
        f.write("Run Info\n--------\n")
        f.write(f"Start: {start}\nEnd:   {end}\n")
        f.write(f"Platform: {platform.platform()}\nPython: {sys.version.splitlines()[0]}\n\n")

        f.write("Curves\n------\n")
        for c in registry:
            f.write(f"- {c['name']}: field={c['fbits']} bits, order≈{c['nbits']} bits\n")
        f.write("\n")

        def block(title, res):
            f.write(title + "\n" + "-"*len(title) + "\n")
            name_w = max(len(c["name"]) for c in registry)
            f.write(f"{'Curve'.ljust(name_w)} | Median (ms) | Mean (ms) | p90 (ms) | p99 (ms) | Rate (/s)\n")
            f.write("-"*(name_w + 60) + "\n")
            for c in registry:
                r = res[c["name"]]
                f.write(f"{c['name'].ljust(name_w)} | {r['median']*1e3:11.3f} | {r['mean']*1e3:9.3f} | {r['p90']*1e3:8.3f} | {r['p99']*1e3:8.3f} | {r['rate_s']:9.2f}\n")
            f.write("\n")

        block("Variable-base scalar mul (random P)", varres)
        block("Fixed-base scalar mul (same P, warmed)", fixres)
        block("ECDH exchange (A=aP, B=bP, shared=aB=bA)", ecdhres)

# ---------------- Main ----------------
def main():
    start = now_utc_iso()
    registry = load_registry()
    # warmup mínimo
    for c in registry: _ = c["E"].random_point()

    varres = {c["name"]: bench_varbase(c, VARBASE_ITERS) for c in registry}
    fixres = {c["name"]: bench_fixed(c, FIXEDBASE_ITERS, WARM_FIXEDBASE) for c in registry}
    ecdhres = {c["name"]: bench_ecdh(c, ECDH_ITERS) for c in registry}

    end = now_utc_iso()
    write_report(REPORT_FILE, registry, varres, fixres, ecdhres, start, end)
    print(f"✅ Report saved to {REPORT_FILE}")

if __name__ == "__main__":
    main()
