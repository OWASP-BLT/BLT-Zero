"""
decrypt_report.py — Decrypt a BLT-Zero encrypted vulnerability report.

Usage:
    python decrypt_report.py <key_hex> <iv_hex> <report.bin>

The key and IV are provided in the email sent by BLT-Zero when a report
is submitted for your domain.

The decrypted report is written to stdout (and optionally to report.json).

Requirements:
    pip install cryptography
"""

import sys
import zipfile
import json
from pathlib import Path


def decrypt(key_hex: str, iv_hex: str, ciphertext: bytes) -> bytes:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    key = bytes.fromhex(key_hex)
    iv = bytes.fromhex(iv_hex)
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(iv, ciphertext, None)


def main():
    if len(sys.argv) < 4:
        print(__doc__)
        sys.exit(1)

    key_hex, iv_hex, target_file = sys.argv[1], sys.argv[2], sys.argv[3]
    target_path = Path(target_file)

    if not target_path.exists():
        print(f"Error: file not found: {target_file}", file=sys.stderr)
        sys.exit(1)

    raw = target_path.read_bytes()

    # If the target is a ZIP, extract the first .bin file inside.
    if target_path.suffix.lower() == ".zip" or raw[:2] == b"PK":
        with zipfile.ZipFile(target_path) as zf:
            names = zf.namelist()
            bin_names = [n for n in names if n.endswith(".bin")]
            if not bin_names:
                print("Error: no .bin file found inside the ZIP.", file=sys.stderr)
                sys.exit(1)
            raw = zf.read(bin_names[0])
            print(f"Extracted '{bin_names[0]}' from ZIP.")

    plaintext = decrypt(key_hex, iv_hex, raw)

    out_path = Path("report.json")
    out_path.write_bytes(plaintext)
    print(f"✅ Decrypted report written to {out_path}")

    # Pretty-print summary
    try:
        report = json.loads(plaintext)
        print(f"\nDomain      : {report.get('domain', 'N/A')}")
        print(f"URL         : {report.get('url', 'N/A')}")
        print(f"Submitted   : {report.get('created_at', 'N/A')}")
        print(f"Description : {report.get('description', '')[:120]}")
    except Exception as exc:
        print(f"(Could not parse report summary: {exc})", file=sys.stderr)


if __name__ == "__main__":
    main()
