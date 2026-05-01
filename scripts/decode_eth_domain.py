#!/usr/bin/env python3

import base64
import binascii
import hashlib
import json
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse


RPC_URL = "https://ethereum-rpc.publicnode.com"
CONTRACT = "0x1280a841Fbc1F883365d3C83122260E0b2995B74"
CALLDATA = "0xce6d41de"
MAX_INDICATOR_LENGTH = 2048
MAX_ARTIFACT_BYTES = 1_048_576
MAX_RPC_HEX_CHARS = 2 + (MAX_ARTIFACT_BYTES + 128) * 2
MAX_INDICATORS = 128
MAX_LOG_ROWS = 5000
RPC_TIMEOUT_SECONDS = 30
DOMAIN_RE = re.compile(r"^(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,63}$")
UNSAFE_TEXT_RE = re.compile(r"[\x00-\x1f\x7f<>\"'`]")


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
        timeout=RPC_TIMEOUT_SECONDS,
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


def require_safe_artifact_size(data: bytes, label: str) -> None:
    if len(data) > MAX_ARTIFACT_BYTES:
        raise ValueError(
            f"{label} is too large to write: "
            f"{len(data)} bytes > {MAX_ARTIFACT_BYTES} bytes"
        )


def parse_rpc_hex(hx: str) -> bytes:
    if not isinstance(hx, str) or not hx.startswith("0x"):
        raise ValueError("RPC result is not a 0x-prefixed hex string")

    if len(hx) % 2 != 0:
        raise ValueError("RPC result has odd hex length")

    if len(hx) > MAX_RPC_HEX_CHARS:
        raise ValueError(f"RPC result too large: {len(hx)} chars")

    try:
        return bytes.fromhex(hx[2:])
    except ValueError as e:
        raise ValueError("RPC result contains invalid hex") from e


def inspect_base64_field(s: str) -> dict[str, object]:
    cleaned = s.strip()
    padded = cleaned + ("=" * ((-len(cleaned)) % 4))

    try:
        raw = base64.b64decode(padded, validate=True)
    except binascii.Error:
        return {
            "field2_base64_valid": False,
            "field2_decoded_len": 0,
            "field2_decoded_sha256": None,
        }

    require_safe_artifact_size(raw, "Base64 decoded field")

    return {
        "field2_base64_valid": True,
        "field2_decoded_len": len(raw),
        "field2_decoded_sha256": hashlib.sha256(raw).hexdigest(),
    }


def normalize_indicator(value: str) -> dict[str, str] | None:
    cleaned = value.rstrip(".,;:").strip()

    if (
        not cleaned
        or len(cleaned) > MAX_INDICATOR_LENGTH
        or UNSAFE_TEXT_RE.search(cleaned)
    ):
        return None

    if cleaned.lower().startswith(("http://", "https://")):
        parsed = urlparse(cleaned)

        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            return None

        hostname = parsed.hostname.rstrip(".").lower()

        if not DOMAIN_RE.match(hostname):
            return None

        return {
            "indicator": hostname,
            "indicator_type": "domain",
            "source_url": cleaned,
        }

    domain = cleaned.rstrip(".").lower()

    if not DOMAIN_RE.match(domain):
        return None

    return {
        "indicator": domain,
        "indicator_type": "domain",
    }


def extract_indicator_records(text: str) -> list[dict[str, str]]:
    found: dict[str, dict[str, str]] = {}

    url_re = re.compile(r"\bhttps?://[^\s\"'<>|)]+", re.IGNORECASE)
    domain_re = re.compile(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,63}\b")

    for item in url_re.findall(text):
        record = normalize_indicator(item)

        if record:
            found[record["indicator"]] = record

    for item in domain_re.findall(text):
        record = normalize_indicator(item)

        if record and record["indicator"] not in found:
            found[record["indicator"]] = record

    return [found[key] for key in sorted(found)]


def read_logged_indicators(log_path: Path) -> set[str]:
    existing = set()

    if not log_path.exists():
        return existing

    for line in log_path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()

        if not line:
            continue

        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue

        value = obj.get("indicator") or obj.get("domain_or_url")

        if not isinstance(value, str):
            continue

        record = normalize_indicator(value)

        if record:
            existing.add(record["indicator"])

    return existing


def append_log(records: list[dict[str, str]]) -> bool:
    now = datetime.now(timezone.utc).isoformat()

    log_path = Path("domains.log")
    existing = read_logged_indicators(log_path)

    rows = []

    for record in records:
        indicator = record["indicator"]

        if indicator in existing:
            continue

        obj = {
            "timestamp": now,
            "indicator": indicator,
            "indicator_type": record["indicator_type"],
            "source": "eth_call",
            "contract": CONTRACT,
            "calldata": CALLDATA,
        }

        if "source_url" in record:
            obj["source_url"] = record["source_url"]

        rows.append(json.dumps(obj, sort_keys=True))
        existing.add(indicator)

    if rows:
        existing_lines = []

        if log_path.exists():
            existing_lines = log_path.read_text(
                encoding="utf-8",
                errors="replace",
            ).splitlines()

        retained_lines = existing_lines[-max(MAX_LOG_ROWS - len(rows), 0):]
        rows = rows[-MAX_LOG_ROWS:]

        with log_path.open("w", encoding="utf-8") as f:
            for line in retained_lines:
                if line.strip():
                    f.write(line + "\n")
            for row in rows:
                f.write(row + "\n")

    return bool(rows)


def read_latest_indicators(path: Path) -> list[str]:
    if not path.exists():
        return []

    try:
        obj = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except json.JSONDecodeError:
        return []

    indicators = obj.get("indicators")

    if not isinstance(indicators, list):
        return []

    return sorted(item for item in indicators if isinstance(item, str))


def write_latest(
    records: list[dict[str, str]],
    payload: bytes,
    field2_metadata: dict[str, object],
) -> bool:
    latest_path = Path("latest.json")
    payload_hash = hashlib.sha256(payload).hexdigest()
    indicators = sorted(record["indicator"] for record in records)

    if indicators == read_latest_indicators(latest_path):
        return False

    obj = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "indicators": indicators,
        "records": records,
        "payload_len": len(payload),
        "payload_sha256": payload_hash,
        "source": "eth_call",
        "contract": CONTRACT,
        "calldata": CALLDATA,
        **field2_metadata,
    }

    if not records:
        obj["note"] = "No domain or URL extracted"

    latest_path.write_text(
        json.dumps(obj, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    Path("latest_payload_sha256.txt").write_text(
        payload_hash + "\n",
        encoding="utf-8",
    )

    return True


def main() -> None:
    hx = eth_call()

    data = parse_rpc_hex(hx)
    payload = decode_abi_dynamic_single(data)
    require_safe_artifact_size(payload, "Decoded ABI payload")

    decoded = payload.decode("utf-8", errors="replace")
    field2_metadata = {
        "field2_base64_valid": False,
        "field2_decoded_len": 0,
        "field2_decoded_sha256": None,
    }

    if "|" in decoded:
        parts = decoded.split("|")

        if len(parts) >= 2:
            field2_metadata = inspect_base64_field(parts[1])

    records = extract_indicator_records(decoded)

    if len(records) > MAX_INDICATORS:
        raise ValueError(
            f"Too many indicators extracted: {len(records)} > {MAX_INDICATORS}"
        )

    log_changed = append_log(records)
    latest_changed = write_latest(records, payload, field2_metadata)

    print(f"Decoded payload length: {len(payload)}")
    print(f"Extracted indicators: {len(records)}")
    print(f"Log changed: {log_changed}")
    print(f"Latest changed: {latest_changed}")

    for record in records:
        print(record["indicator"])


if __name__ == "__main__":
    main()
