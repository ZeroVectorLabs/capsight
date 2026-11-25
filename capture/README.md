# Capsight Capture

Record network traffic from the port you choose and save it as a `.pcap` file, ready to open in
[Capsight](https://zerovectorlabs.github.io/capsight/), Wireshark or tcpdump.

It runs on your own computer only. The app opens in your browser at `http://127.0.0.1:47115`, and
nothing is sent anywhere.

## From Capsight

Click **Capture live traffic** on the Capsight start page (or **Capture** in the top bar). Capsight
looks for this helper on port 47115 and opens it in a window. Record, click **Open in Capsight**, and
the capture opens straight in the Capsight tab. If the helper isn't running, the same dialog has the
download and the steps to start it.

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
- Starting, stopping and downloading need a random key that only its own page has; other websites
  can't drive it, and its page can't be framed.
- A finished capture goes only to the Capsight tab that opened the window
  (`https://zerovectorlabs.github.io`, or Capsight served from localhost while developing).

## Start it

**Mac:** open **Terminal**, type `bash ` (with a space), drag `Capsight Capture.command` from the
unzipped folder into the Terminal window and press Return. It installs scapy once, asks for your Mac
password, and opens the app in your browser.

If you double-click the file instead, macOS may say it "could not verify" the script, because it was
downloaded and isn't signed by Apple. Starting it with `bash` as above avoids that. You can also allow
it once: click **Done**, open **System Settings → Privacy & Security**, scroll down and click
**Open Anyway** next to "Capsight Capture.command", then double-click it again.

**Windows:** install [Npcap](https://npcap.com) first, then double-click `Capsight Capture.bat`
and allow it to run as administrator.

**Linux, or from a terminal anywhere:**

```bash
python3 -m pip install scapy
sudo python3 capsight_capture.py          # browser app
sudo python3 capsight_capture.py --cli    # terminal only
python3 capsight_capture.py --check       # just check what this computer can do
```

### Terminal options

| Option | What it does |
|---|---|
| `--cli` | Use the terminal instead of the browser |
| `--check` | Only run the computer check |
| `--list` | List the network interfaces |
| `-i en0` | Capture on this interface without asking |
| `-f "tcp port 443"` | Capture filter (BPF syntax) |
| `-d 60` / `-c 5000` / `--max-mb 100` | Stop after seconds / packets / MB |
| `--no-promisc` | Only traffic to and from this computer |
| `-o ~/Desktop/pcaps` | Save folder |
| `--port 47115` | Port for the browser app (Capsight looks for 47115) |

Example: `sudo python3 capsight_capture.py -i en0 -f "port 53" -d 30` records 30 seconds of DNS on `en0`.

## Requirements

- Python 3.8 or newer and [scapy](https://scapy.net) (`pip install scapy`; `psutil` is optional and adds link speed and traffic counters)
- Admin rights to capture: `sudo` on macOS and Linux, Administrator plus Npcap on Windows
- Capture filters use libpcap (built into macOS; `sudo apt install libpcap0.8` on Linux; Npcap on Windows). Without it you can still record everything.

Only capture on networks you own or are allowed to monitor.
