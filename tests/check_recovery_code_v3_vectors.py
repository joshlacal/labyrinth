#!/usr/bin/env python3
"""Check the frozen v2/v3 recovery derivations using only Python's stdlib."""

import hashlib
import hmac
import json
import sys
from pathlib import Path

FIXTURE = Path(__file__).with_name("fixtures") / "recovery_code_v3_vectors.json"
FIELDS = (
    "vdeviceId",
    "codeKey",
    "fetchToken",
    "fetchVerifier",
    "vdeviceKey",
    "v2VdeviceId",
    "v2VdeviceKey",
)


def hkdf_sha256(ikm, salt, info, length):
    if salt is None:
        salt = bytes(hashlib.sha256().digest_size)
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    blocks = []
    previous = b""
    for counter in range(1, (length + hashlib.sha256().digest_size - 1) // hashlib.sha256().digest_size + 1):
        previous = hmac.new(prk, previous + info + bytes((counter,)), hashlib.sha256).digest()
        blocks.append(previous)
    return b"".join(blocks)[:length]


def derive(vector, did):
    entropy = vector["entropyChars"].encode("ascii")
    did_bytes = did.encode("utf-8")

    v3 = hkdf_sha256(entropy, None, b"BackupRecoveryCode_v3_0_" + did_bytes, 80)
    vdevice_id, code_key, fetch_token = v3[:16], v3[16:48], v3[48:]
    fetch_verifier = hashlib.sha256(
        b"catbird.labyrinth.recovery_share.fetch.v1|"
        + did_bytes
        + b"|"
        + vdevice_id.hex().encode("ascii")
        + b"|"
        + fetch_token
    ).digest()
    vdevice_key = hkdf_sha256(
        code_key + bytes.fromhex(vector["share"]),
        b"catbird.labyrinth.recovery_share.v1",
        b"vdevice_key|did=" + did_bytes + b"|vid=" + vdevice_id.hex().encode("ascii"),
        32,
    )

    v2 = hkdf_sha256(entropy, None, b"BackupRecoveryCode_v2_0_" + did_bytes, 48)
    return {
        "vdeviceId": vdevice_id.hex(),
        "codeKey": code_key.hex(),
        "fetchToken": fetch_token.hex(),
        "fetchVerifier": fetch_verifier.hex(),
        "vdeviceKey": vdevice_key.hex(),
        "v2VdeviceId": v2[:16].hex(),
        "v2VdeviceKey": v2[16:].hex(),
    }


def main():
    fixture = json.loads(FIXTURE.read_text(encoding="utf-8"))
    mismatches = []
    for vector in fixture["vectors"]:
        actual = derive(vector, fixture["did"])
        for field in FIELDS:
            expected = vector.get(field)
            if actual[field] != expected:
                mismatches.append(
                    f'{vector.get("name", "<unnamed>")}.{field}: '
                    f"expected {expected!r}, actual {actual[field]!r}"
                )
    if mismatches:
        print("recovery-code fixture mismatch:", file=sys.stderr)
        for mismatch in mismatches:
            print(f"  {mismatch}", file=sys.stderr)
        return 1
    print(f"{len(fixture['vectors'])} vectors: all {len(FIELDS)} independent fields match")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
