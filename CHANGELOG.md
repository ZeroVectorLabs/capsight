# Changelog

Notable changes to Capsight, newest first.

## Unreleased

- **Capture live traffic:** a new button on the start page and **Capture** in the top bar. It opens **Capsight Capture** (`capture/`), a small helper for Mac, Windows and Linux that checks what the computer can capture, lets you pick the network port, filter and stop condition, records to `.pcap` with live counters, and sends the capture straight back into the Capsight tab. If the helper isn't running, the dialog has the download and steps to start it.

- **Shorter, clearer findings report:** it now opens with the verdict, an "At a glance" list (attacker, compromised hosts, C2, malware hosts) and "What to do now" steps built from the capture, then the **attack flow diagram** and the **network map**, a single timeline of every detection, and only the indicators, passwords and files that need action. Benign IP and domain lists, the separate tactics table and the host inventory are gone. Both diagrams are drawn as vector graphics in the web page and PDF, and as images in Word and Markdown.

## 3.0.0 (2026-11-24)

- **New demo video:** a 65-second tour of Capsight 3.0.0 (`docs/media/capsight_demo.mp4`).
- The file name in the top bar no longer runs under the tabs on narrower windows.
- **Clear filter:** one button in the filter bar removes the filter text, every chip and the selected time window.
- **Findings report:** a Report button downloads a write-up of the capture as PDF, web page, Word (.docx) or Markdown, with the summary, every detection in ATT&CK order, hosts, indicators, recovered files and credentials. Passwords are masked unless you choose to include them.
- **Smoother tabs:** the active-tab highlight slides between tabs, and each view eases in when it opens.
- **Headline:** "Open a capture. See what really happened." replaces a line that promised an attack in every capture.
- **New name:** Deepacket is now Capsight, with a new logo. The site moved to https://zerovectorlabs.github.io/capsight/ and the offline file is now `dist/capsight.html`.
- **New look:** one theme on every page, black in dark mode and soft blue in light mode, with buttons in the logo's cyan-to-blue, blue-family charts and the DM Sans typeface.
- **New start page:** a clean page that opens with the logo, the app shown on a laptop and feature tiles with real screenshots. Click the laptop to open the sample attack.
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
