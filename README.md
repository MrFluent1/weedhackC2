# Weedhack C2 Domain Monitor

This repository hosts a small static monitor for the current C2 domain associated with the Weedhack malware tracking target.

The page reads an Ethereum smart contract, decodes the returned ABI string, extracts domains or URLs, and displays the current value. A scheduled GitHub Actions workflow runs the same decode process every 30 minutes and appends extracted values to `domains.log`.

## Weedhack Malware Context

The observed Weedhack samples use a staged, signed C2 discovery model rather than a single hardcoded attacker host. The `dev.majanito` and `com.example` families rely on embedded public DNS-over-HTTPS endpoints and a large statically recoverable set of Ethereum RPC endpoints to perform `eth_call` requests against contract `0x1280a841Fbc1F883365d3C83122260E0b2995B74`.

The returned `value|signature` text is ABI-decoded and RSA-verified by the malware before being used as the next-stage base URL. From an offline-decoded response, the root signed base URL resolved to `whpayment.ru` and `friendlydomain.ru` since I began working on this project, which is then used for downstream paths such as handler delivery and module retrieval.

The key point is that the malware's C2 is abstracted behind public RPC infrastructure and signed configuration, but the retrieval chain itself is statically exposed and recoverable offline. This project focuses on tracking that contract-backed domain indicator. It does not contain malware, payload code, exploit code, or tooling for interacting with infected systems.

## How Domain Retrieval Works

1. The monitor sends an `eth_call` request to `https://ethereum-rpc.publicnode.com`.
2. The request calls contract `0x1280a841Fbc1F883365d3C83122260E0b2995B74` with calldata `0xce6d41de`.
3. The returned value is decoded as a single ABI dynamic string or bytes payload.
4. The decoded payload is interpreted as UTF-8 text.
5. If the decoded text contains a `|` separator, the second field is also attempted as Base64.
6. URLs and domains are extracted from the decoded text with regular expressions.
7. The scheduled workflow appends extracted values to `domains.log`.

## Repository Contents

- `index.html` - GitHub Pages UI that performs live browser-side decoding and displays the latest logged result.
- `scripts/decode_eth_domain.py` - Python decoder used by GitHub Actions.
- `.github/workflows/decode-eth-domain.yml` - Scheduled workflow that updates `domains.log`.
- `.github/workflows/pages.yml` - GitHub Pages deployment workflow.
- `domains.log` - JSON-lines history of extracted domains and URLs.
- `eth_call_decoded_payload.txt` - Last committed decoded payload text.

## Running Locally

Run the decoder from the repository root:

```bash
python3 scripts/decode_eth_domain.py
```

The script writes or updates:

- `domains.log`
- `eth_call_decoded_payload.txt`
- `eth_call_field2_base64_decoded.txt`, when the Base64 field decodes as UTF-8

Generated binary payload files are ignored by Git.

## GitHub Pages

When GitHub Pages is enabled for this repository, the static page is served from:

```text
https://mrfluent1.github.io/weedhackC2/
```

If the page is not available, check the repository Actions tab for the `Deploy GitHub Pages` workflow and confirm Pages is enabled for the repository.

## AI Usage Disclosure

AI assistance was used to help create parts of this project, including page structure, styling, decoding logic, workflow automation, and documentation. The contract address, calldata, decoded output, and logged values come from the configured Ethereum RPC call and repository workflow.

## Safety Notice

This repository is intended for malware tracking and defensive analysis. Do not use the decoded infrastructure indicators to contact, operate, or interfere with third-party systems except within an authorized security workflow.
