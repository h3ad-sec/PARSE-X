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


## H3AD-SEC Platform Modules

| Module | Tools |
|--------|-------|
| [H3AD-X](https://h3ad-sec.github.io/H3AD-X/) | X-VERDIKT, PARSE-X, DNSCOPE |
| [H3AD-AI](https://h3ad-sec.github.io/H3AD-AI/) | INSIGHT-AI, QUERYCRAFT-AI, FPLENS-AI, ATTMAP-AI, CHRONO-AI, THREATBRIEF-AI, PERSONA-AI, DEBRIEF-AI, MALBRIEF-AI |
| [H3AD-DETECT](https://h3ad-sec.github.io/H3AD-DETECT/) | TRACERULES |
| [H3AD-HUNT](https://h3ad-sec.github.io/H3AD-HUNT/) | HYPOS, PIVEX, TRACEPULSE |
| [H3AD-OPS](https://h3ad-sec.github.io/H3AD-OPS/) | QUICKTRACE, SHIFTLOG |
| [H3AD-DF](https://h3ad-sec.github.io/H3AD-DF/) | REGSCOPE, MALBRIEF-AI, EVTXPARSE, ARTIFACTDB |
| [H3AD-IR](https://h3ad-sec.github.io/H3AD-IR/) | DEBRIEF-AI, CASEBOARD |
