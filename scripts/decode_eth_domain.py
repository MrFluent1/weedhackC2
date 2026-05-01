#!/usr/bin/env python3

import base64
import binascii
import json
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path


RPC_URL = "https://ethereum-rpc.publicnode.com"
CONTRACT = "0x1280a841Fbc1F883365d3C83122260E0b2995B74"
CALLDATA = "0xce6d41de"


def eth_call() -> str:
    payload = {
        "jsonrpc": "2.0",
        "method": "eth_call",
        "params": [
            {
                "to": CONTRACT,
                "data": CALLDATA,
            },
            "latest",
        ],
        "id": 1,
    }

    result = subprocess.run(
        [
            "curl",
            "-sS",
            RPC_URL,
            "-X",
            "POST",
            "-H",
            "Content-Type: application/json",
            "-H",
            "Accept: application/json",
            "-H",
            "User-Agent: Mozilla/5.0",
            "--data",
            json.dumps(payload),
        ],
        check=True,
        capture_output=True,
        text=True,
    )

    obj = json.loads(result.stdout)

    if "error" in obj:
        raise RuntimeError(f"RPC error: {obj['error']}")

    if "result" not in obj:
        raise RuntimeError("RPC response missing result")

    return obj["result"]


def word_to_int(b: bytes) -> int:
    if len(b) != 32:
        raise ValueError(f"Expected 32-byte ABI word, got {len(b)} bytes")
    return int.from_bytes(b, "big")


def decode_abi_dynamic_single(data: bytes) -> bytes:
    if len(data) < 64:
        raise ValueError("ABI data too short for dynamic string/bytes return")

    offset = word_to_int(data[0:32])

    if offset + 32 > len(data):
        raise ValueError(f"ABI offset 0x{offset:x} is outside data length {len(data)}")

    length = word_to_int(data[offset:offset + 32])
    start = offset + 32
    end = start + length

    if end > len(data):
        raise ValueError(
            f"ABI payload length 0x{length:x} exceeds data length. "
            f"payload end=0x{end:x}, data len=0x{len(data):x}"
        )

    return data[start:end]


def try_base64_decode(s: str) -> str:
    cleaned = s.strip()
    padded = cleaned + ("=" * ((-len(cleaned)) % 4))

    try:
        raw = base64.b64decode(padded, validate=False)
    except binascii.Error:
        return ""

    Path("eth_call_field2_base64_decoded.bin").write_bytes(raw)

    try:
        text = raw.decode("utf-8")
        Path("eth_call_field2_base64_decoded.txt").write_text(
            text,
            encoding="utf-8",
            errors="replace",
        )
        return text
    except UnicodeDecodeError:
        return ""


def extract_domains_and_urls(text: str) -> list[str]:
    found = set()

    url_re = re.compile(r"\bhttps?://[^\s\"'<>|)]+", re.IGNORECASE)
    domain_re = re.compile(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,63}\b")

    for item in url_re.findall(text):
        found.add(item.rstrip(".,;:"))

    for item in domain_re.findall(text):
        found.add(item.rstrip(".,;:"))

    return sorted(found)


def append_log(domains: list[str]) -> None:
    now = datetime.now(timezone.utc).isoformat()

    log_path = Path("domains.log")

    existing = set()
    if log_path.exists():
        for line in log_path.read_text(encoding="utf-8", errors="replace").splitlines():
            existing.add(line.strip())

    rows = []

    if domains:
        for domain in domains:
            row = json.dumps(
                {
                    "timestamp": now,
                    "domain_or_url": domain,
                    "source": "eth_call",
                    "contract": CONTRACT,
                    "calldata": CALLDATA,
                },
                sort_keys=True,
            )

            if row not in existing:
                rows.append(row)
    else:
        row = json.dumps(
            {
                "timestamp": now,
                "domain_or_url": None,
                "source": "eth_call",
                "contract": CONTRACT,
                "calldata": CALLDATA,
                "note": "No domain or URL extracted",
            },
            sort_keys=True,
        )

        rows.append(row)

    if rows:
        with log_path.open("a", encoding="utf-8") as f:
            for row in rows:
                f.write(row + "\n")


def main() -> None:
    hx = eth_call()

    if not hx.startswith("0x"):
        raise ValueError("RPC result is not 0x-prefixed hex")

    data = bytes.fromhex(hx[2:])
    payload = decode_abi_dynamic_single(data)

    decoded = payload.decode("utf-8", errors="replace")

    Path("eth_call_decoded_payload.bin").write_bytes(payload)
    Path("eth_call_decoded_payload.txt").write_text(
        decoded,
        encoding="utf-8",
        errors="replace",
    )

    b64_decoded = ""

    if "|" in decoded:
        parts = decoded.split("|")

        if len(parts) >= 2:
            b64_decoded = try_base64_decode(parts[1])

    combined = decoded + "\n" + b64_decoded
    domains = extract_domains_and_urls(combined)

    append_log(domains)

    print(f"Decoded payload length: {len(payload)}")
    print(f"Extracted domains/URLs: {len(domains)}")

    for domain in domains:
        print(domain)


if __name__ == "__main__":
    main()
