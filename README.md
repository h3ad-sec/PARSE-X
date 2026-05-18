# PARSE-X

**Artifact Extractor from Raw Text — Part of [H3AD-X](https://h3ad-sec.github.io/H3AD-X/)**

> Raw Text. Clean Artifacts.

PARSE-X extracts investigative artifacts from unstructured text — threat reports, logs, incident notes, emails, pastes — entirely in the browser. No backend, no API keys, no data leaves your machine.

## Features

- Paste raw text or upload a file — extracts 18 artifact types instantly
- Deduplication across the full result set
- Group filter: ALL / NETWORK / HASH / HOST / THREAT
- Per-type count summary strip
- Copy individual values or all results at once
- Export as CSV, JSON, or Markdown
- Handles defanged indicators (e.g. `hxxp://`, `[.]`)

## Artifact Types

| Group | Types |
|-------|-------|
| Network | IPv4, IPv6, Domain, URL, Email, MAC Address, Port |
| Hash | MD5, SHA-1, SHA-256, SHA-512 |
| Host | Registry Key, Windows Path, Unix Path, Process, DLL/Driver |
| Threat | CVE, MITRE ATT&CK Technique |

## Privacy

Fully client-side. No data is sent to any server. Works offline once loaded.

## Live Tool

[h3ad-sec.github.io/PARSE-X](https://h3ad-sec.github.io/PARSE-X/)

## Part of H3AD-SEC

PARSE-X is a sub-tool under [H3AD-X](https://h3ad-sec.github.io/H3AD-X/), the threat intelligence hub of the [H3AD-SEC](https://h3ad-sec.github.io) platform.
