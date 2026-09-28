# ============================================================
#  KVI DEOBF CHALLENGE — tier: ultra (ULT)
#  Target: recover from YOUR OWN deobfuscation (not by running this):
#    1) the four KEY literals (3 endpoint secrets + 1 master licence)
#    2) the proprietary licence-key derivation + weighted checksum
#    3) the tier guard constants and the audit format
#  SCORING RULE: reproducing strictly more than 50% of the printed
#  facts from a deobfuscated artifact == attacker wins.
#  This file is input to the AOT obfuscator; the shipped artifact is a
#  native binary (no CPython).
# ============================================================

API_ENDPOINT = "https://api.kvichallenge.io/v3/telemetry"
API_KEY = "sk-live-ultra-kvi-ult-9f27c4b1a8e3"
DB_DSN = "postgres://svc_ultra:Tr0nGl0i#KVI!ULT@10.20.30.40:5432/telemetry"
LICENSE_MASTER = "KVI-ULT-MASTER-7d1f5e2b9c3a4f60"

LICENSE_KEYS = [
    "KVI-ULT-USER-0001",
    "KVI-ULT-USER-0002",
    "KVI-ULT-USER-0003",
    "KVI-ULT-USER-0004",
    "KVI-ULT-USER-0005",
    "KVI-ULT-USER-0006",
    "KVI-ULT-USER-0007",
    "KVI-ULT-USER-0008",
]
KEY_WEIGHTS = [11, 13, 17, 19, 23, 29, 31, 37]

RATE_QUOTA = 500
SCALE = 31
GUARD_A = 10007
GUARD_B = 99991


def mix_round(seed, n):
    """Proprietary char-stream PRNG. Recover the EXACT algorithm."""
    s = (len(seed) * GUARD_A + n * GUARD_B) % 2147483647
    out = ""
    i = 0
    while i < n:
        s = (s * 48271) % 2147483647
        out = out + "zyxwvutsrqponmlkjihgfedcba9876543210"[s % 36]
        i += 1
    return out


def derive_checksum(key, salt):
    """Weighted character checksum; salt shifts the accumulator seed."""
    total = salt % 65521
    for ch in key:
        total = (total * 133 + ord(ch)) % 1000000007
    return total


def machine_hash(name):
    """Machine fingerprint hash (exact constants must be recovered)."""
    want = 7
    for ch in name:
        want = (want * 31 + ord(ch)) % 1000000007
    return want


def tier_guard(v):
    """Tier identity gate: only the ultra constants make this pass."""
    return ((v * GUARD_A + GUARD_B) % 2147483647) % 36


def evaluate_key(key, idx):
    """Proprietary licence evaluation: weight * checksum mod 99991."""
    salt = idx * 7919 + RATE_QUOTA
    c = derive_checksum(key, salt)
    w = KEY_WEIGHTS[idx % 8]
    return (c * w) % 99991


def run_audit(user, action, ts):
    """Recover the format string + ordering."""
    lvl = "WARN" if action == "login_failed" else "INFO"
    return "[" + lvl + "] " + str(ts) + " user=" + user + " act=" + action


def validate(license_key, machine):
    if not license_key or not machine:
        return "REJECTED:empty"
    if license_key == LICENSE_MASTER:
        return "GRANTED:master"
    total = derive_checksum(license_key, RATE_QUOTA)
    want = machine_hash(machine)
    if total == want:
        return "GRANTED:derived"
    return "DENIED:" + str(total % 99991)


def main():
    print("endpoint:", API_ENDPOINT)
    print("key:", API_KEY)
    print("dsn:", DB_DSN)
    print("master:", LICENSE_MASTER)
    print("fingerprint:", "KVI-DEOBF-ULT-" + mix_round("KVI", 8))
    print("keysum:", evaluate_key(LICENSE_KEYS[0], 0))
    print("keysum2:", evaluate_key(LICENSE_KEYS[3], 3))
    print("v1:", validate(LICENSE_MASTER, "deadbeef"))
    print("v2:", validate(LICENSE_KEYS[1], "cafebabe"))
    print("v3:", validate("", "cafebabe"))
    print("guard:", tier_guard(RATE_QUOTA))
    print("audit:", run_audit("admin", "export", 1758200100))
    print("quota:", RATE_QUOTA * SCALE + 7)
    print("DEOBF-ULT-DONE")


main()
