# Capsight Capture

Record network traffic from the port you choose and save it as a `.pcap` file, ready to open in
[Capsight](https://zerovectorlabs.github.io/capsight/), Wireshark or tcpdump.

It runs on your own computer only and nothing is sent anywhere. A web page can't read network ports,
which is why this small helper has to run; Capsight's Capture page is its interface.

## How it works with Capsight

Capsight Capture has no window of its own. Start it once and leave it running; everything else happens
on Capsight's **Capture** page (the **Capture live traffic** button on the start page, or **Capture** in
the top bar, or https://zerovectorlabs.github.io/capsight/#capture). The page connects to this helper
on `127.0.0.1:47115`, and:

- shows what your computer can capture, with a fix for anything missing,
- lets you choose the network port from a drop-down list, add a filter and a stop condition,
- shows live packets, data, rate, a traffic graph, top protocols and busiest addresses,
- saves each finished capture in your browser (IndexedDB) under **Saved captures**, where you can
  open it, download the `.pcap` or delete it. Saved captures are removed after 1, 7 or 30 days, or
  kept until you delete them. By default the helper's own copy is deleted once the browser has it;
  turn on **Keep a copy on disk** to also keep `.pcap` files in `~/Captures`.

Light and dark follow Capsight's theme switch.

## What it does

1. **Checks this computer**: operating system, Python, the capture library, permission to
   capture (admin/root, `/dev/bpf` on macOS, `CAP_NET_RAW` on Linux, Npcap on Windows), whether
   capture filters work, the network interfaces, and free space in the save folder. Anything
   missing comes with the exact fix.
2. **Lets you choose the network port**: every interface with its type (Ethernet, Wi-Fi, virtual,
   loopback), up or down, IPv4, MAC, link speed and traffic so far. The one carrying your internet
   traffic is marked "default".
3. **Records**: optional capture filter (BPF, e.g. `tcp port 443`, with one-click presets), stop
   after N seconds, N packets or N MB, promiscuous mode on or off. Live packet count, data, rate,
   top protocols and busiest addresses while it runs.
4. **Saves a .pcap** to `~/Captures` (named `capsight_<port>_<date-time>.pcap`), with buttons to
   download it, show it in its folder, or open it in Capsight.

## Security

- Listens on `127.0.0.1` only, and answers only requests addressed to `127.0.0.1` or `localhost`
  (no DNS rebinding).
- Only Capsight's page can use it: every request must come from `https://zerovectorlabs.github.io`
  (or Capsight served from localhost while developing), which browsers enforce with CORS. Other
  websites can't start a capture or read one.

## Start it

**Mac:** open **Terminal**, type `bash ` (with a space), drag `Capsight Capture.command` from the
unzipped folder into the Terminal window and press Return. It installs scapy once, asks for your Mac
password, and opens Capsight's Capture page in your browser.

If you double-click the file instead, macOS may say it "could not verify" the script, because it was
downloaded and isn't signed by Apple. Starting it with `bash` as above avoids that. You can also allow
it once: click **Done**, open **System Settings → Privacy & Security**, scroll down and click
**Open Anyway** next to "Capsight Capture.command", then double-click it again.

**Windows:** install [Npcap](https://npcap.com) first, then double-click `Capsight Capture.bat`
and allow it to run as administrator.

**Linux, or from a terminal anywhere:**

```bash
python3 -m pip install scapy
sudo python3 capsight_capture.py          # runs in the background; use Capsight's Capture page
sudo python3 capsight_capture.py --cli    # terminal only
python3 capsight_capture.py --check       # just check what this computer can do
```

### Terminal options

| Option | What it does |
|---|---|
| `--cli` | Record from the terminal instead of Capsight |
| `--check` | Only run the computer check |
| `--list` | List the network interfaces |
| `-i en0` | Capture on this interface without asking |
| `-f "tcp port 443"` | Capture filter (BPF syntax) |
| `-d 60` / `-c 5000` / `--max-mb 100` | Stop after seconds / packets / MB |
| `--no-promisc` | Only traffic to and from this computer |
| `-o ~/Desktop/pcaps` | Save folder |
| `--port 47115` | Port to listen on (Capsight looks for 47115) |
| `--no-browser` | Don't open Capsight when it starts |

Example: `sudo python3 capsight_capture.py -i en0 -f "port 53" -d 30` records 30 seconds of DNS on `en0`.

## Requirements

- Python 3.8 or newer and [scapy](https://scapy.net) (`pip install scapy`; `psutil` is optional and adds link speed and traffic counters)
- Admin rights to capture: `sudo` on macOS and Linux, Administrator plus Npcap on Windows
- Capture filters use libpcap (built into macOS; `sudo apt install libpcap0.8` on Linux; Npcap on Windows). Without it you can still record everything.

Only capture on networks you own or are allowed to monitor.
