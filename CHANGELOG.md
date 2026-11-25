# Changelog

Notable changes to Capsight, newest first.

## 4.0.0 (2026-11-25)

- **Wireshark display filters:** the filter bar now reads Wireshark's syntax: field names like `ip.addr`, `tcp.port`, `tcp.flags.syn`, `http.request.method`, `dns.qry.name` and `tls.handshake.extensions_server_name`; `== != > < >= <=` and `eq ne gt lt ge le`; `contains` and `matches`; byte slices like `tcp[13:1] == 02`; and `&& || !`, `and or not` with brackets. The bar turns green or red as you type, and Enter applies the filter. Capsight's short forms still work.
- **Right-click a packet** (long-press on a phone) for Wireshark's packet menu: Apply as filter and Prepare as filter in all six forms, conversation filters, colourise conversation, follow TCP/UDP/TLS/HTTP stream, mark, ignore, time reference, packet comment, copy (summary, CSV, value, filter, hex dump, hex stream, text, escaped) and export the packet's bytes or the packet as .pcapng.
- **Right-click a field** in the packet details to filter on it, copy it or export its bytes; double-click applies it as a filter. Fields without a named filter use a byte slice counted from their protocol's start.
- **Packet list:** new **Src port** and **Dst port** columns (filter on them with a right-click; on phones they sit beside each address), sortable columns, Wireshark's default colouring rules, time formats (since start, since previous, time of day, UTC, epoch) with time references, go to packet, find by text, hex or filter, next and previous marked packet or packet in the same conversation, and a status bar with displayed, marked and ignored counts.
- **Export** shown or marked packets as .pcapng with your comments, or the packet list as CSV or text.
- **Follow stream** shows one direction or both, as ASCII, a hex dump or raw hex, and can show, filter out or save the stream.
- **Buttons:** monochrome, solid main buttons and underlined secondary ones, replacing the cyan gradient pills.
- **Phones:** every screen reworked: a one-row header with icons, two-line packet rows with a long-press menu, the attack flow as a step list, a network map you can pan and pinch, and nothing pushing the page sideways.
- Filter help lists clickable examples and every packet-list shortcut.

## 3.1.1 (2026-11-25)

- **Capture live traffic:** record from a network port on your computer and analyse it straight away. The **Capture live traffic** button on the start page, or **Capture** in the top bar, opens the Capture page inside Capsight. It connects to **Capsight Capture** (`capture/`), a small open-source helper for Mac, Windows and Linux that runs in the background, because browsers can't read network ports. The page shows what your computer can capture with a fix for anything missing, a drop-down list of network ports, an optional filter and stop condition, and live counters with a traffic graph, top protocols and busiest addresses. It follows the light and dark theme.
- **Saved captures:** every finished capture is kept in your browser (IndexedDB) on this computer, never uploaded, with open, download and delete, and **Delete all**. Captures are removed after 1, 7 or 30 days, or kept until you delete them. Turn on **Keep a copy on disk** to also keep `.pcap` files in `~/Captures`.
- The helper's API only answers Capsight's own site, on loopback, and the page explains how to update when an older helper is running. On a Mac it starts with `bash "Capsight Capture.command"` in Terminal, which avoids macOS's "could not verify" warning.
- **Shorter, clearer findings report:** it opens with the verdict, an "At a glance" list (attacker, compromised hosts, C2, malware hosts) and "What to do now" steps built from the capture, then the **attack flow diagram** and the **network map**, a single timeline of every detection, and only the indicators, passwords and files that need action. Benign IP and domain lists, the separate tactics table and the host inventory are gone. Both diagrams are drawn as vector graphics in the web page and PDF, and as images in Word and Markdown.

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
