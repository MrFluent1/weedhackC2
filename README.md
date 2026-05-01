# Weedhack C2 Domain Monitor

This repository hosts a small static monitor for the current C2 domain associated with the Weedhack malware tracking target.

The scheduled GitHub Actions workflow reads an Ethereum smart contract, decodes the returned ABI string, extracts domains or URLs, and commits sanitized structured output when the normalized indicator set changes. The GitHub Pages UI reads only same-origin static files from this repository; visitor browsers do not call Ethereum RPC endpoints directly.

## Weedhack Malware Context

The observed Weedhack samples use a staged, signed C2 discovery model rather than a single hardcoded attacker host. The `dev.majanito` and `com.example` families rely on embedded public DNS-over-HTTPS endpoints and a large statically recoverable set of Ethereum RPC endpoints to perform `eth_call` requests against contract `0x1280a841Fbc1F883365d3C83122260E0b2995B74`.

The returned `value|signature` text is ABI-decoded and RSA-verified by the malware before being used as the next-stage base URL. From an offline-decoded response, the root signed base URL resolved to `whpayment.ru` and `friendlydomain.ru` since I began working on this project, which is then used for downstream paths such as handler delivery and module retrieval.

The key point is that the malware's C2 is abstracted behind public RPC infrastructure and signed configuration, but the retrieval chain itself is statically exposed and recoverable offline. This project focuses on tracking that contract-backed domain indicator. It does not contain malware, payload code, exploit code, or tooling for interacting with infected systems.

## How Domain Retrieval Works

1. A scheduled GitHub Action sends an `eth_call` request to `https://ethereum-rpc.publicnode.com`.
2. The workflow calls contract `0x1280a841Fbc1F883365d3C83122260E0b2995B74` with calldata `0xce6d41de`.
3. The returned value is decoded as a single ABI dynamic string or bytes payload.
4. The decoded payload is interpreted as UTF-8 text.
5. If the decoded text contains a `|` separator, the second field is treated as signature-like metadata: the workflow stores only Base64 validity, decoded length, and SHA-256 hash.
6. URLs and domains are extracted from the decoded text with regular expressions, normalized to host indicators, and filtered for valid domain syntax.
7. The scheduled workflow appends only new normalized indicators to `domains.log` and updates `latest.json` only when the current indicator set changes.

The public page does not perform contract reads. It fetches `latest.json`, `latest_payload_sha256.txt`, and `domains.log` from the same GitHub Pages origin, avoiding visitor-side RPC exposure, unnecessary RPC traffic on page load, and page breakage when the upstream RPC provider is unavailable.

## Repository Contents

- `index.html` - GitHub Pages UI that displays the latest sanitized workflow result from static repository files.
- `scripts/decode_eth_domain.py` - Python decoder used by GitHub Actions.
- `.github/workflows/decode-eth-domain.yml` - Scheduled workflow that updates `domains.log`.
- `.github/workflows/pages.yml` - GitHub Pages deployment workflow.
- `domains.log` - JSON-lines history of unique normalized indicators.
- `latest.json` - Latest sanitized indicator set and payload metadata.
- `latest_payload_sha256.txt` - SHA-256 hash of the latest decoded payload.

## Running Locally

Run the decoder from the repository root:

```bash
python3 scripts/decode_eth_domain.py
```

The script writes or updates:

- `domains.log`
- `latest.json`
- `latest_payload_sha256.txt`

Raw decoded payload files and Base64-decoded field artifacts are intentionally not committed. The contract output is attacker-controlled, so the workflow stores only normalized indicators and metadata.

## GitHub Pages

When GitHub Pages is enabled for this repository, the static page is served from:

```text
https://mrfluent1.github.io/Weedhack-C2-Tracking/
```

If the page is not available, check the repository Actions tab for the `Deploy GitHub Pages` workflow and confirm Pages is enabled for the repository.

## AI Usage Disclosure

AI assistance was used to help create parts of this project, including page structure, styling, decoding logic, workflow automation, and documentation. The contract address, calldata, decoded output, and logged values come from the configured Ethereum RPC call and repository workflow.

## Safety Notice

This repository is intended for malware tracking and defensive analysis. Do not use the decoded infrastructure indicators to contact, operate, or interfere with third-party systems except within an authorized security workflow.
