#!/usr/bin/env python3
"""
Capsight Capture: record network traffic from one interface and save it as a .pcap file.

Capsight (https://zerovectorlabs.github.io/capsight/#capture) drives it: the Capture page checks what
your computer can do (permissions, capture driver, interfaces, disk space), lets you pick the network
port, shows live counters while it records, and keeps the finished capture in the browser.
Browsers can't read network ports themselves, which is why this small helper has to run.

    python3 capsight_capture.py            # runs in the background; capture from Capsight's Capture page
    python3 capsight_capture.py --cli      # same thing in the terminal
    python3 capsight_capture.py --check    # only show what this computer can capture

Needs Python 3.8+ and scapy (pip install scapy). Capturing needs extra rights:
  macOS / Linux  run with sudo (or give your user access to /dev/bpf* / CAP_NET_RAW)
  Windows        install Npcap (https://npcap.com) and run as Administrator
Only capture on networks you own or are allowed to monitor.
"""
import argparse, json, os, platform, secrets, shutil, socket, subprocess, sys, threading, time, webbrowser
from collections import Counter
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

VERSION = '2.0.0'
CAPSIGHT_URL = 'https://zerovectorlabs.github.io/capsight/'
DEFAULT_PORT = 47115  # Capsight's "Capture live traffic" button looks for the helper here
CAPSIGHT_ORIGINS = ('https://zerovectorlabs.github.io',)

try:
    import logging
    logging.getLogger('scapy.runtime').setLevel(logging.ERROR)
    from scapy.all import conf, AsyncSniffer, PcapWriter, get_if_list  # noqa: E402
    from scapy.layers.l2 import ARP, Ether  # noqa: E402,F401
    from scapy.layers.inet import IP, TCP, UDP, ICMP  # noqa: E402
    from scapy.layers.inet6 import IPv6  # noqa: E402
    import scapy
    SCAPY = scapy.__version__
except Exception as e:  # pragma: no cover - shown to the user
    SCAPY = None
    SCAPY_ERR = str(e)

try:
    import psutil
except Exception:
    psutil = None

OS = platform.system()  # 'Darwin', 'Linux', 'Windows'


def real_user():
    """When started with sudo, the person who ran it: (home, uid, gid). Captures belong to them, not root."""
    try:
        if OS != 'Windows' and os.environ.get('SUDO_UID'):
            import pwd
            pw = pwd.getpwuid(int(os.environ['SUDO_UID']))
            return Path(pw.pw_dir), pw.pw_uid, pw.pw_gid
    except Exception:
        pass
    return Path.home(), None, None


def give_back(path):
    """Hand a file or folder made under sudo back to the user who ran sudo."""
    _, uid, gid = real_user()
    if uid is not None:
        try:
            os.chown(path, uid, gid)
        except OSError:
            pass


# ---------------------------------------------------------------- capabilities
def is_admin():
    try:
        if OS == 'Windows':
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        return os.geteuid() == 0
    except Exception:
        return False


def linux_cap_net_raw():
    try:
        for line in open('/proc/self/status'):
            if line.startswith('CapEff:'):
                return bool(int(line.split()[1], 16) & (1 << 13))
    except Exception:
        pass
    return False


def mac_bpf_access():
    """True if this user can open a /dev/bpf device for reading."""
    for i in range(256):
        p = f'/dev/bpf{i}'
        if not os.path.exists(p):
            break
        try:
            fd = os.open(p, os.O_RDWR)
            os.close(fd)
            return True
        except PermissionError:
            return False
        except OSError:
            continue  # busy, try the next one
    return False


def npcap_installed():
    root = os.environ.get('SystemRoot', r'C:\Windows')
    return any(os.path.exists(os.path.join(root, d)) for d in (r'System32\Npcap', r'System32\Npcap\wpcap.dll')) or os.path.exists(os.path.join(root, r'System32\wpcap.dll'))


def interface_kind(name, desc=''):
    n = (name + ' ' + (desc or '')).lower()
    if n.startswith('lo') or 'loopback' in n:
        return 'Loopback'
    if any(k in n for k in ('wi-fi', 'wifi', 'wlan', 'wireless', '802.11', 'airport')) or (OS == 'Darwin' and name == 'en0' and is_wifi_mac(name)):
        return 'Wi-Fi'
    if any(k in n for k in ('docker', 'veth', 'br-', 'virbr', 'vmnet', 'vbox', 'utun', 'tun', 'tap', 'ifb', 'awdl', 'llw', 'bridge', 'gif', 'stf', 'anpi', 'ap1', 'hyper-v', 'virtual', 'wsl')):
        return 'Virtual'
    if any(k in n for k in ('eth', 'en', 'ethernet', 'lan', 'realtek', 'intel', 'gigabit')):
        return 'Ethernet'
    return 'Other'


_wifi_cache = {}
def is_wifi_mac(name):
    if name in _wifi_cache:
        return _wifi_cache[name]
    r = False
    try:
        out = subprocess.run(['networksetup', '-listallhardwareports'], capture_output=True, text=True, timeout=3).stdout
        block = ''
        for chunk in out.split('\n\n'):
            if f'Device: {name}' in chunk:
                block = chunk
        r = 'Wi-Fi' in block or 'AirPort' in block
    except Exception:
        pass
    _wifi_cache[name] = r
    return r


def list_interfaces():
    """Every interface scapy can see, with addresses, link state and speed."""
    out = []
    stats = psutil.net_if_stats() if psutil else {}
    io = psutil.net_io_counters(pernic=True) if psutil else {}
    if not SCAPY:
        return out
    try:
        ifaces = list(conf.ifaces.values())
    except Exception:
        ifaces = []
    seen = set()
    for i in ifaces:
        name = getattr(i, 'network_name', None) or i.name
        if name in seen:
            continue
        seen.add(name)
        desc = getattr(i, 'description', '') or ''
        label = getattr(i, 'name', name)
        st = stats.get(label) or stats.get(name)
        ips6 = []
        try:
            ips6 = [a for a in (getattr(i, 'ips', {}) or {}).get(6, []) if not a.startswith('fe80')][:2]
        except Exception:
            pass
        counters = io.get(label) or io.get(name)
        out.append({
            'name': name,
            'label': label if label != name else name,
            'description': desc if desc and desc != label else '',
            'mac': getattr(i, 'mac', '') or '',
            'ipv4': getattr(i, 'ip', '') or '',
            'ipv6': ips6,
            'up': bool(st.isup) if st else None,
            'speed': (st.speed or None) if st else None,
            'mtu': st.mtu if st else None,
            'traffic': (counters.bytes_recv + counters.bytes_sent) if counters else None,
            'kind': interface_kind(label, desc),
            'default': name == getattr(conf.iface, 'network_name', str(conf.iface)) or label == str(conf.iface),
        })
    order = {'Ethernet': 0, 'Wi-Fi': 1, 'Other': 2, 'Virtual': 3, 'Loopback': 4}
    out.sort(key=lambda x: (not x['default'], x['up'] is False, order.get(x['kind'], 5), not x['ipv4'], x['label']))
    return out


def filters_supported():
    """Capture filters are compiled by libpcap (or tcpdump); returns (ok, detail)."""
    if not SCAPY:
        return False, 'scapy is not installed'
    try:
        from scapy.arch.common import compile_filter
        compile_filter('tcp port 443')
        return True, 'Supported'
    except Exception as e:
        return False, 'Not available: ' + (str(e).strip().split('\n')[0][:120] or 'libpcap missing')


def check_filter(bpf):
    if not bpf.strip():
        return ''
    try:
        from scapy.arch.common import compile_filter
        compile_filter(bpf)
        return ''
    except Exception as e:
        msg = str(e).strip().split('\n')[0]
        if 'libpcap' in msg.lower() or 'tcpdump' in msg.lower():
            return 'Capture filters need libpcap on this computer. ' + FILTER_FIX.get(OS, '') + ' Or leave the filter empty to record everything.'
        return f'The capture filter "{bpf}" is not valid. Examples: tcp port 443, host 10.0.0.5, udp and not port 53.'


FILTER_FIX = {'Linux': 'Install it with: sudo apt install libpcap0.8 (or tcpdump).', 'Windows': 'Install Npcap from https://npcap.com.', 'Darwin': ''}


def can_capture_on(iface):
    """Open a capture handle on the interface for a moment; returns (ok, reason)."""
    if not SCAPY:
        return False, 'scapy is not installed'
    try:
        s = conf.L2listen(iface=iface, promisc=False)
        s.close()
        return True, ''
    except PermissionError:
        return False, 'Permission denied'
    except OSError as e:
        return False, (e.strerror or str(e)).strip()
    except Exception as e:
        return False, str(e).strip()[:200]


def capabilities(out_dir):
    """A checklist of what this computer can do, each with a fix when it can't."""
    checks = []
    def add(key, label, ok, detail, fix=''):
        checks.append({'key': key, 'label': label, 'ok': ok, 'detail': detail, 'fix': fix})

    add('os', 'Operating system', True, f'{platform.system()} {platform.release()} ({platform.machine()})')
    add('python', 'Python', sys.version_info >= (3, 8), platform.python_version(), 'Install Python 3.8 or newer from python.org.')
    add('scapy', 'Capture library (scapy)', bool(SCAPY), f'scapy {SCAPY}' if SCAPY else 'Not installed',
        f'{Path(sys.executable).name} -m pip install scapy')

    admin = is_admin()
    if OS == 'Linux':
        raw = admin or linux_cap_net_raw()
        add('rights', 'Permission to capture', raw, 'Running as root' if admin else ('Has CAP_NET_RAW' if raw else 'Normal user'),
            'Run with sudo, or: sudo setcap cap_net_raw,cap_net_admin=eip ' + os.path.realpath(sys.executable))
    elif OS == 'Darwin':
        bpf = admin or mac_bpf_access()
        add('rights', 'Permission to capture', bpf, 'Running as root' if admin else ('Can read /dev/bpf' if bpf else 'Cannot read /dev/bpf*'),
            'Run with sudo, or install Wireshark and its "ChmodBPF" helper so your user can capture.')
    elif OS == 'Windows':
        np_ = npcap_installed()
        add('driver', 'Capture driver (Npcap)', np_, 'Installed' if np_ else 'Not found', 'Install Npcap from https://npcap.com (tick "WinPcap API-compatible mode").')
        add('rights', 'Administrator', admin, 'Yes' if admin else 'No', 'Right-click your terminal and choose "Run as administrator".')
    else:
        add('rights', 'Permission to capture', admin, 'Administrator' if admin else 'Normal user', 'Run as administrator or root.')

    if SCAPY:
        libpcap = getattr(conf, 'use_pcap', False) or OS == 'Windows'
        backend = 'libpcap / Npcap' if libpcap else ('Linux packet socket' if OS == 'Linux' else 'BPF')
        add('backend', 'Capture method', True, backend)
        fok, fdet = filters_supported()
        add('bpf', 'Capture filters (optional)', fok, fdet, FILTER_FIX.get(OS, '') + ' You can still record everything without a filter.')

    ifs = list_interfaces()
    up = [i for i in ifs if i['up'] is not False and i['kind'] != 'Loopback']
    add('ifaces', 'Network interfaces', bool(up), f'{len(ifs)} found, {len(up)} up', 'Connect a network cable or Wi-Fi.')

    try:
        Path(out_dir).mkdir(parents=True, exist_ok=True)
        free = shutil.disk_usage(out_dir).free
        test = Path(out_dir) / '.capsight_write_test'
        test.write_bytes(b''); test.unlink()
        add('disk', 'Save folder', free > 200 * 1024 * 1024, f'{out_dir} ({human(free)} free)', 'Free some disk space or choose another folder with --out.')
    except Exception as e:
        add('disk', 'Save folder', False, f'{out_dir}: {e}', 'Choose a folder you can write to with --out.')

    ready = all(c['ok'] for c in checks if c['key'] in ('python', 'scapy', 'rights', 'driver', 'disk'))
    return {'ready': ready, 'checks': checks, 'interfaces': ifs, 'admin': admin, 'os': OS, 'filters': any(c['key'] == 'bpf' and c['ok'] for c in checks)}


def human(n):
    n = float(n or 0)
    for u in ('B', 'KB', 'MB', 'GB', 'TB'):
        if n < 1024 or u == 'TB':
            return f'{n:.0f} {u}' if u == 'B' else f'{n:.1f} {u}'
        n /= 1024


# ---------------------------------------------------------------- capture session
WELL_KNOWN = {53: 'DNS', 80: 'HTTP', 443: 'HTTPS', 22: 'SSH', 21: 'FTP', 25: 'SMTP', 587: 'SMTP', 110: 'POP3', 143: 'IMAP', 993: 'IMAPS',
              123: 'NTP', 67: 'DHCP', 68: 'DHCP', 137: 'NetBIOS', 138: 'NetBIOS', 139: 'SMB', 445: 'SMB', 3389: 'RDP', 5353: 'mDNS',
              1900: 'SSDP', 161: 'SNMP', 23: 'Telnet', 3306: 'MySQL', 5432: 'PostgreSQL', 8080: 'HTTP-alt', 1883: 'MQTT', 502: 'Modbus',
              5355: 'LLMNR', 853: 'DoT', 3478: 'STUN', 51820: 'WireGuard', 4444: 'tcp/4444'}


def classify(p):
    try:
        if p.haslayer(ARP):
            return 'ARP'
        l3 = p.getlayer(IP) or p.getlayer(IPv6)
        if l3 is None:
            return 'Other L2'
        if p.haslayer(TCP) or p.haslayer(UDP):
            l4 = p.getlayer(TCP) or p.getlayer(UDP)
            for port in (l4.dport, l4.sport):
                if port in WELL_KNOWN:
                    return WELL_KNOWN[port]
            if p.haslayer(UDP) and (l4.dport == 443 or l4.sport == 443):
                return 'QUIC'
            return 'TCP other' if p.haslayer(TCP) else 'UDP other'
        if p.haslayer(ICMP) or getattr(l3, 'nh', None) == 58:
            return 'ICMP'
        return 'IP other'
    except Exception:
        return 'Other'


class Session:
    """One recording: a sniffer thread writing straight to a pcap file."""

    def __init__(self, iface, out_dir, bpf='', duration=0, count=0, max_mb=0, promisc=True):
        self.iface, self.bpf, self.duration, self.count, self.max_mb, self.promisc = iface, bpf.strip(), duration, count, max_mb, promisc
        stamp = datetime.now().strftime('%Y%m%d-%H%M%S')
        safe = ''.join(c if c.isalnum() or c in '-_.' else '_' for c in iface)[:40]
        self.path = Path(out_dir) / f'capsight_{safe}_{stamp}.pcap'
        self.packets = self.bytes = 0
        self.protos, self.talkers = Counter(), Counter()
        self.started = self.ended = None
        self.error = ''
        self.stop_reason = ''
        self.lock = threading.Lock()
        self.writer = None
        self.sniffer = None
        self.rate = []  # (t, packets, bytes)

    def _on_packet(self, p):
        with self.lock:
            self.writer.write(p)
            self.packets += 1
            ln = len(p)
            self.bytes += ln
            self.protos[classify(p)] += 1
            l3 = p.getlayer(IP) or p.getlayer(IPv6)
            if l3 is not None:
                self.talkers[l3.src] += ln
                self.talkers[l3.dst] += ln
            if self.packets % 200 == 0:
                self.writer.flush()

    def _stop_filter(self, _p):
        if self.count and self.packets >= self.count:
            self.stop_reason = f'Reached {self.count:,} packets'
            return True
        if self.max_mb and self.bytes >= self.max_mb * 1024 * 1024:
            self.stop_reason = f'Reached {self.max_mb} MB'
            return True
        return False

    def start(self):
        bad = check_filter(self.bpf)
        if bad:
            raise RuntimeError(bad)
        made = not self.path.parent.exists()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if made:
            give_back(self.path.parent)
        self.writer = PcapWriter(str(self.path), append=False, sync=False, linktype=None)
        conf.sniff_promisc = self.promisc
        kw = dict(iface=self.iface, prn=self._on_packet, store=False, stop_filter=self._stop_filter)
        if self.bpf:
            kw['filter'] = self.bpf
        self.sniffer = AsyncSniffer(**kw)
        self.started = time.time()
        self.sniffer.start()
        # surface errors that happen while the sniffer opens the interface
        time.sleep(0.4)
        if not self.sniffer.running and getattr(self.sniffer, 'exception', None):
            self.error = friendly_error(self.sniffer.exception)
            self._close()
            try:
                self.path.unlink()
            except OSError:
                pass
            raise RuntimeError(self.error)
        threading.Thread(target=self._watch, daemon=True).start()

    def _watch(self):
        try:
            while self.sniffer.running:
                self.sniffer.join(timeout=0.25)
                if self.duration and time.time() - self.started >= self.duration and self.sniffer.running:
                    self.stop_reason = 'Time limit reached'
                    self.sniffer.stop(join=True)
        except Exception as e:
            self.error = friendly_error(e)
        if getattr(self.sniffer, 'exception', None) and not self.error:
            self.error = friendly_error(self.sniffer.exception)
        if not self.stop_reason:
            self.stop_reason = 'Stopped'
        self._close()

    def stop(self):
        if self.sniffer and self.sniffer.running:
            self.stop_reason = self.stop_reason or 'Stopped'
            try:
                self.sniffer.stop(join=True)
            except Exception:
                pass
        self._close()

    def _close(self):
        with self.lock:
            if self.writer:
                try:
                    self.writer.flush(); self.writer.close()
                except Exception:
                    pass
                self.writer = None
                give_back(self.path)
            if not self.ended:
                self.ended = time.time()

    @property
    def running(self):
        return bool(self.sniffer and self.sniffer.running and not self.ended)

    def snapshot(self):
        with self.lock:
            now = self.ended or time.time()
            el = max(0.001, now - (self.started or now))
            self.rate.append((now, self.packets, self.bytes))
            self.rate = [r for r in self.rate if now - r[0] <= 3]
            r0 = self.rate[0]
            dt = max(0.5, now - r0[0])
            return {
                'running': self.running, 'iface': self.iface, 'filter': self.bpf, 'file': str(self.path), 'name': self.path.name,
                'packets': self.packets, 'bytes': self.bytes, 'elapsed': el,
                'pps': (self.packets - r0[1]) / dt if self.running else 0, 'bps': (self.bytes - r0[2]) / dt if self.running else 0,
                'size': self.path.stat().st_size if self.path.exists() else 0,
                'protocols': self.protos.most_common(8), 'talkers': self.talkers.most_common(6),
                'limits': {'duration': self.duration, 'count': self.count, 'max_mb': self.max_mb},
                'stop_reason': self.stop_reason, 'error': self.error,
            }


def friendly_error(e):
    s = str(e)
    low = s.lower()
    if 'permission' in low or 'operation not permitted' in low or 'access is denied' in low:
        return 'Permission denied. ' + ('Run as Administrator with Npcap installed.' if OS == 'Windows' else 'Run again with sudo.')
    if 'syntax' in low or 'filter' in low:
        return 'The capture filter is not valid: ' + s
    if 'no such device' in low or 'not found' in low:
        return 'That interface is not available any more: ' + s
    return s or e.__class__.__name__


# ---------------------------------------------------------------- terminal mode
def cli(args):
    cap = capabilities(args.out)
    print_checks(cap)
    if args.check:
        return 0 if cap['ready'] else 1
    if not cap['ready']:
        print('\nFix the items marked ✗ above, then run this again.')
        return 1
    ifs = cap['interfaces']
    iface = args.iface
    if not iface:
        print('\nNetwork interfaces:')
        for n, i in enumerate(ifs, 1):
            state = 'up' if i['up'] else ('down' if i['up'] is False else '')
            print(f"  {n:>2}. {i['label']:<18} {i['kind']:<9} {i['ipv4'] or '-':<16} {i['mac'] or '':<18} {state}{'  (default)' if i['default'] else ''}")
        while True:
            pick = input(f'\nWhich interface do you want to capture on? [1-{len(ifs)}]: ').strip()
            if pick.isdigit() and 1 <= int(pick) <= len(ifs):
                iface = ifs[int(pick) - 1]['name']; break
            print('Type one of the numbers above.')
        if args.filter is None and cap.get('filters'):
            args.filter = input('Capture filter (e.g. "tcp port 443", Enter for all traffic): ').strip()
        if not args.duration and not args.count:
            d = input('Stop after how many seconds? (Enter to stop with Ctrl+C): ').strip()
            args.duration = int(d) if d.isdigit() else 0
    ok, why = can_capture_on(iface)
    if not ok:
        print(f'\n✗ Cannot capture on {iface}: {why}'); return 1
    s = Session(iface, args.out, args.filter or '', args.duration, args.count, args.max_mb, not args.no_promisc)
    try:
        s.start()
    except RuntimeError as e:
        print(f'\n✗ {e}'); return 1
    except Exception as e:
        print(f'\n✗ {friendly_error(e)}'); return 1
    print(f'\nRecording on {iface}{" with filter: " + s.bpf if s.bpf else ""}. Press Ctrl+C to stop.\n')
    try:
        while s.running:
            time.sleep(0.5)
            x = s.snapshot()
            sys.stdout.write(f"\r  {x['packets']:>9,} packets  {human(x['bytes']):>9}  {x['pps']:>7.0f} pkt/s  {fmt_time(x['elapsed'])}   ")
            sys.stdout.flush()
    except KeyboardInterrupt:
        pass
    s.stop()
    x = s.snapshot()
    print(f"\n\n{x['stop_reason'] or 'Stopped'}. Saved {x['packets']:,} packets ({human(x['size'])}) to:\n  {x['file']}")
    if x['error']:
        print('  Note: ' + x['error'])
    if x['protocols']:
        print('\nTop protocols: ' + ', '.join(f'{k} {v:,}' for k, v in x['protocols']))
    print(f'\nOpen it in Capsight: {CAPSIGHT_URL}')
    return 0


def print_checks(cap):
    print(f'Capsight Capture {VERSION}: checking this computer\n')
    for c in cap['checks']:
        mark = '✓' if c['ok'] else '✗'
        print(f"  {mark} {c['label']:<26} {c['detail']}")
        if not c['ok'] and c['fix']:
            print(f"      → {c['fix']}")


def fmt_time(s):
    s = int(s)
    return f'{s // 3600}:{s // 60 % 60:02d}:{s % 60:02d}' if s >= 3600 else f'{s // 60}:{s % 60:02d}'


# ---------------------------------------------------------------- browser app
def saved_captures(out_dir, limit=30):
    """The captures Capsight Capture has saved in the folder, newest first."""
    out = []
    try:
        for p in Path(out_dir).glob('capsight_*.pcap'):
            try:
                st = p.stat()
            except OSError:
                continue
            parts = p.stem.split('_')
            out.append({'name': p.name, 'size': st.st_size, 'mtime': st.st_mtime,
                        'iface': '_'.join(parts[1:-1]) if len(parts) >= 3 else ''})
    except OSError:
        pass
    out.sort(key=lambda x: -x['mtime'])
    return out[:limit]


def move_to_trash(path):
    """Move a file to the user's Trash / Recycle Bin. Returns True if it went to the trash, False if it was deleted."""
    path = Path(path)
    home, uid, gid = real_user()
    try:
        if OS == 'Darwin':
            tdir = home / '.Trash'
            tdir.mkdir(exist_ok=True)
            dest = tdir / path.name
            n = 1
            while dest.exists():
                dest = tdir / f'{path.stem} {n}{path.suffix}'; n += 1
            shutil.move(str(path), str(dest)); give_back(dest)
            return True
        if OS == 'Linux':
            base = Path(os.environ.get('XDG_DATA_HOME') or home / '.local/share') / 'Trash'
            (base / 'files').mkdir(parents=True, exist_ok=True); (base / 'info').mkdir(parents=True, exist_ok=True)
            dest = base / 'files' / path.name
            n = 1
            while dest.exists():
                dest = base / 'files' / f'{path.stem}.{n}{path.suffix}'; n += 1
            (base / 'info' / (dest.name + '.trashinfo')).write_text(
                f'[Trash Info]\nPath={path.resolve()}\nDeletionDate={datetime.now().strftime("%Y-%m-%dT%H:%M:%S")}\n')
            shutil.move(str(path), str(dest))
            for q in (dest, base / 'info' / (dest.name + '.trashinfo')):
                give_back(q)
            return True
        if OS == 'Windows':
            import ctypes
            from ctypes import wintypes

            class SHFILEOPSTRUCTW(ctypes.Structure):
                _fields_ = [('hwnd', wintypes.HWND), ('wFunc', wintypes.UINT), ('pFrom', wintypes.LPCWSTR), ('pTo', wintypes.LPCWSTR),
                            ('fFlags', ctypes.c_uint16), ('fAnyOperationsAborted', wintypes.BOOL), ('hNameMappings', ctypes.c_void_p),
                            ('lpszProgressTitle', wintypes.LPCWSTR)]
            op = SHFILEOPSTRUCTW(None, 3, str(path.resolve()) + '\0', None, 0x40 | 0x10 | 0x04 | 0x400, False, None, None)
            if ctypes.windll.shell32.SHFileOperationW(ctypes.byref(op)) == 0 and not path.exists():
                return True
    except Exception:
        pass
    path.unlink()
    return False


class App:
    def __init__(self, out_dir):
        self.out_dir = out_dir
        self.session = None
        self.token = secrets.token_urlsafe(18)
        self.cap = None

    def state(self, refresh=False):
        if refresh or not self.cap:
            self.cap = capabilities(self.out_dir)
        return {'version': VERSION, 'capabilities': self.cap, 'outDir': self.out_dir, 'os': OS,
                'session': self.session.snapshot() if self.session else None,
                'captures': saved_captures(self.out_dir)}


def allowed_origin(o):
    """Capsight's own site, or Capsight served from localhost while developing. Never 'null' (sandboxed pages)."""
    import re
    return o in CAPSIGHT_ORIGINS or bool(re.fullmatch(r'http://(localhost|127\.0\.0\.1)(:\d+)?', o or ''))


def make_handler(app, host_port):
    own = (f'http://127.0.0.1:{host_port}', f'http://localhost:{host_port}')

    class H(BaseHTTPRequestHandler):
        server_version = 'CapsightCapture'

        def log_message(self, *a):
            pass

        def _ok_host(self):
            # refuse DNS-rebinding tricks: only loopback names reach this helper
            return self.headers.get('Host', '') in (f'127.0.0.1:{host_port}', f'localhost:{host_port}')

        def _origin(self):
            o = self.headers.get('Origin', '')
            return o if o not in own and allowed_origin(o) else ''

        def _cors(self):
            o = self._origin()
            return {'Access-Control-Allow-Origin': o, 'Vary': 'Origin', 'Access-Control-Allow-Private-Network': 'true'} if o else {}

        def _send(self, code, body, ctype='application/json', extra=None):
            data = body if isinstance(body, bytes) else (json.dumps(body) if ctype == 'application/json' else body).encode()
            self.send_response(code)
            self.send_header('Content-Type', ctype + ('; charset=utf-8' if ctype.startswith(('text', 'application/json')) else ''))
            self.send_header('Content-Length', str(len(data)))
            self.send_header('Cache-Control', 'no-store')
            self.send_header('X-Content-Type-Options', 'nosniff')
            for k, v in {**self._cors(), **(extra or {})}.items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(data)

        def do_OPTIONS(self):
            ok = self._ok_host() and self._origin()
            self.send_response(204 if ok else 403)
            if ok:
                for k, v in self._cors().items():
                    self.send_header(k, v)
                self.send_header('Access-Control-Allow-Methods', 'GET, POST')
                self.send_header('Access-Control-Allow-Headers', 'Content-Type')
                self.send_header('Access-Control-Max-Age', '600')
            self.send_header('Content-Length', '0')
            self.end_headers()

        def _guard(self):
            """Every action needs a request from Capsight's page (checked Origin) on a loopback Host."""
            if not self._ok_host():
                self._send(403, {'error': 'forbidden'}); return False
            if not self._origin():
                self._send(403, {'error': 'Only Capsight can use this helper.'}); return False
            return True

        def do_GET(self):
            u = urlparse(self.path)
            if not self._ok_host():
                return self._send(403, 'Forbidden', 'text/plain')
            if u.path == '/':
                return self._send(200, STATUS_PAGE, 'text/html', {'X-Frame-Options': 'DENY', 'Content-Security-Policy': "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'"})
            if u.path == '/api/ping':
                return self._send(200, {'app': 'capsight-capture', 'version': VERSION, 'os': OS})
            if not self._guard():
                return
            q = parse_qs(u.query)
            if u.path == '/api/state':
                return self._send(200, app.state(refresh=q.get('refresh') == ['1']))
            if u.path == '/api/download':
                name = Path(q.get('name', [''])[0]).name
                p = Path(app.out_dir) / name
                if not (name.startswith('capsight_') and name.endswith('.pcap')) or not p.is_file():
                    return self._send(404, {'error': 'That capture is not there any more.'})
                return self._send(200, p.read_bytes(), 'application/vnd.tcpdump.pcap')
            self._send(404, {'error': 'not found'})

        def do_POST(self):
            if not self._guard():
                return
            n = int(self.headers.get('Content-Length') or 0)
            try:
                body = json.loads(self.rfile.read(min(n, 65536)) or b'{}')
            except Exception:
                body = {}
            path = urlparse(self.path).path
            if path == '/api/start':
                if app.session and app.session.running:
                    return self._send(409, {'error': 'Already recording.'})
                iface = str(body.get('iface', ''))
                ok, why = can_capture_on(iface)
                if not ok:
                    return self._send(400, {'error': friendly_error(why) if why else 'Cannot capture on that network port.'})
                try:
                    s = Session(iface, app.out_dir, str(body.get('filter', '')), int(body.get('duration') or 0), int(body.get('count') or 0),
                                int(body.get('maxMb') or 0), bool(body.get('promisc', True)))
                    s.start()
                except RuntimeError as e:
                    return self._send(400, {'error': str(e)})
                except Exception as e:
                    return self._send(400, {'error': friendly_error(e)})
                app.session = s
                return self._send(200, {'ok': True})
            if path == '/api/stop':
                if app.session:
                    app.session.stop()
                return self._send(200, {'ok': True})
            if path == '/api/delete':
                name = Path(str(body.get('name', ''))).name
                p = Path(app.out_dir) / name
                if not (name.startswith('capsight_') and name.endswith('.pcap')) or not p.is_file():
                    return self._send(200, {'ok': True, 'gone': True})
                if app.session and app.session.running and app.session.path.name == name:
                    return self._send(409, {'error': 'Stop the recording before deleting it.'})
                try:
                    trashed = move_to_trash(p) if body.get('trash', True) else (p.unlink() or False)
                except Exception as e:
                    return self._send(500, {'error': f'Could not delete it: {e}'})
                return self._send(200, {'ok': True, 'trashed': trashed})
            if path == '/api/reveal':
                p = Path(app.out_dir) / Path(str(body.get('name', ''))).name
                try:
                    target = p if p.exists() else Path(app.out_dir)
                    if OS == 'Darwin':
                        subprocess.Popen(['open', '-R', str(target)] if target.is_file() else ['open', str(target)])
                    elif OS == 'Windows':
                        subprocess.Popen(['explorer', '/select,', str(target)] if target.is_file() else ['explorer', str(target)])
                    else:
                        subprocess.Popen(['xdg-open', str(target if target.is_dir() else target.parent)])
                except Exception as e:
                    return self._send(500, {'error': str(e)})
                return self._send(200, {'ok': True})
            self._send(404, {'error': 'not found'})
    return H


def serve(args):
    app = App(args.out)
    try:
        srv = ThreadingHTTPServer(('127.0.0.1', args.port or DEFAULT_PORT), None)
    except OSError:
        print(f'Port {args.port or DEFAULT_PORT} is in use. Is Capsight Capture already running?' + ('' if args.port else ' Close the other copy, or use --port.'))
        return 1
    port = srv.server_address[1]
    srv.RequestHandlerClass = make_handler(app, port)
    cap = app.state(refresh=True)['capabilities']
    print_checks(cap)
    page = CAPSIGHT_URL + '#capture'
    print(f'\nCapsight Capture is running in the background (127.0.0.1:{port}).\nOpen Capsight and click "Capture live traffic":\n  {page}\n\nKeep this window open while you capture. Press Ctrl+C here to quit.')
    if not args.no_browser:
        threading.Timer(0.4, lambda: webbrowser.open(page)).start()
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        if app.session:
            app.session.stop()
        srv.server_close()
        print('\nBye.')
    return 0


STATUS_PAGE = """<!doctype html><meta charset="utf-8"><title>Capsight Capture</title>
<body style="margin:0;display:grid;place-items:center;height:100vh;background:#000;color:#f5f5f7;font:15px/1.5 -apple-system,BlinkMacSystemFont,Segoe UI,Helvetica,Arial,sans-serif">
<div style="text-align:center;max-width:460px;padding:24px"><h1 style="font-size:22px;margin:0 0 8px">Capsight Capture is running</h1>
<p style="color:#b4b6bd;margin:0 0 20px">Capturing happens from Capsight. Open it and click <b>Capture live traffic</b>.</p>
<a href="https://zerovectorlabs.github.io/capsight/#capture" style="display:inline-block;padding:12px 22px;border-radius:999px;background:linear-gradient(135deg,#67e8f9,#1fa6dd 60%,#2a8de0);color:#04111f;font-weight:600;text-decoration:none">Open Capsight</a></div></body>"""


# ---------------------------------------------------------------- main
def main():
    ap = argparse.ArgumentParser(description='Record network traffic from one interface into a .pcap file.')
    ap.add_argument('--cli', action='store_true', help='use the terminal instead of the browser app')
    ap.add_argument('--check', action='store_true', help='only check what this computer can capture')
    ap.add_argument('--list', action='store_true', help='list the network interfaces and exit')
    ap.add_argument('-i', '--iface', help='interface to capture on (terminal mode)')
    ap.add_argument('-f', '--filter', default=None, help='capture filter in BPF syntax, e.g. "tcp port 443"')
    ap.add_argument('-d', '--duration', type=int, default=0, help='stop after this many seconds')
    ap.add_argument('-c', '--count', type=int, default=0, help='stop after this many packets')
    ap.add_argument('--max-mb', type=int, default=0, help='stop when the file reaches this size in MB')
    ap.add_argument('--no-promisc', action='store_true', help='only see traffic to and from this computer')
    ap.add_argument('-o', '--out', default=str(real_user()[0] / 'Captures'), help='folder to save captures in (default ~/Captures)')
    ap.add_argument('--port', type=int, default=0, help=f'port for the browser app (default {DEFAULT_PORT})')
    ap.add_argument('--no-browser', action='store_true', help="don't open Capsight in the browser automatically")
    ap.add_argument('--version', action='version', version=f'Capsight Capture {VERSION}')
    args = ap.parse_args()
    args.out = os.path.abspath(os.path.expanduser(args.out))
    if not SCAPY:
        print('Capsight Capture needs scapy to read network traffic.\n\nInstall it with:\n  ' + Path(sys.executable).name + ' -m pip install scapy\n')
        print('(' + SCAPY_ERR + ')')
        return 1
    if args.list:
        for i in list_interfaces():
            print(f"{i['name']:<20} {i['kind']:<9} {i['ipv4'] or '-':<16} {i['mac'] or '-':<18} {'up' if i['up'] else 'down' if i['up'] is False else ''}")
        return 0
    if args.cli or args.check or args.iface:
        return cli(args)
    return serve(args)


if __name__ == '__main__':
    sys.exit(main())
