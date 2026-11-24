# Changelog

Notable changes to Capsight, newest first.

## 2.0.0 (2026-11-24)

- **New name:** Deepacket is now Capsight, with a new logo. The site moved to https://zerovectorlabs.github.io/capsight/ and the offline file is now `dist/capsight.html`.
- **New look:** a calm blue palette across the app and charts, soft glass buttons, tabs and filter bar, and the DM Sans typeface.
- **New start page:** headline, buttons and key numbers beside a live screenshot of the app; click the screenshot to open the sample attack.
- Exported files are now named `capsight_*` instead of `deepacket_*`.
- `tools/screenshots.py` retakes the README screenshots and the start-page images.

## 1.0.1

- Back button: returns from an open capture to the start page to open another one. The browser's Back and Forward buttons do the same.
- Security policy and private vulnerability reporting.
- Issue templates for bug reports, feature requests and detection requests, plus links to Discussions and security reporting on the New issue page.
- Contributing guide and pull request template.
- Dependabot updates for GitHub Actions.

## 1.0.0

First public release.

- Reads pcap, pcapng and gzip-wrapped captures in the browser, with no server and no network requests.
- Overview, capture strip, network map, packet list with filters, protocol tree, hex view and TCP stream reassembly.
- Threat detection mapped to MITRE ATT&CK, with a kill chain, an attack-flow diagram and a plain-language summary.
- Artifacts: carved files with hashes, cleartext credentials, indicators and a host inventory, exportable as one .zip.
- Built-in sample attack capture.
