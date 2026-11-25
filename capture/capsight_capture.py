#!/usr/bin/env python3
"""
Capsight Capture: record network traffic from one interface and save it as a .pcap file.

It checks what your computer can do (permissions, capture driver, interfaces, disk space),
lets you pick the network port to listen on, shows live counters while it records,
and writes a standard pcap file you can open in Capsight, Wireshark or tcpdump.

    python3 capsight_capture.py            # opens the app in your browser
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

VERSION = '1.1.0'
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
class App:
    def __init__(self, out_dir):
        self.out_dir = out_dir
        self.session = None
        self.history = []
        self.token = secrets.token_urlsafe(18)
        self.cap = None

    def state(self, refresh=False):
        if refresh or not self.cap:
            self.cap = capabilities(self.out_dir)
        return {'version': VERSION, 'capabilities': self.cap, 'outDir': self.out_dir,
                'session': self.session.snapshot() if self.session else None,
                'history': [h for h in self.history if Path(h['file']).exists()][-8:][::-1]}


def make_handler(app, host_port):
    class H(BaseHTTPRequestHandler):
        server_version = 'CapsightCapture'

        def log_message(self, *a):
            pass

        def _ok_host(self):
            # refuse DNS-rebinding tricks: only loopback names reach this app
            return self.headers.get('Host', '') in (f'127.0.0.1:{host_port}', f'localhost:{host_port}')

        def _ok_origin(self):
            # only this app's own page, which carries the session token, may drive the sniffer
            if not self._ok_host():
                return False
            return self.headers.get('X-Token') == app.token or parse_qs(urlparse(self.path).query).get('t', [''])[0] == app.token

        def _cors(self):
            o = self.headers.get('Origin', '')
            return {'Access-Control-Allow-Origin': o, 'Vary': 'Origin', 'Access-Control-Allow-Private-Network': 'true'} if o in CAPSIGHT_ORIGINS else {}

        def do_OPTIONS(self):
            h = self._cors()
            self.send_response(204 if h else 403)
            for k, v in h.items():
                self.send_header(k, v)
            if h:
                self.send_header('Access-Control-Allow-Methods', 'GET')
                self.send_header('Access-Control-Max-Age', '600')
            self.send_header('Content-Length', '0')
            self.end_headers()

        def _send(self, code, body, ctype='application/json', extra=None):
            data = body if isinstance(body, bytes) else (json.dumps(body) if ctype == 'application/json' else body).encode()
            self.send_response(code)
            self.send_header('Content-Type', ctype + ('; charset=utf-8' if ctype.startswith(('text', 'application/json')) else ''))
            self.send_header('Content-Length', str(len(data)))
            self.send_header('Cache-Control', 'no-store')
            self.send_header('X-Content-Type-Options', 'nosniff')
            for k, v in (extra or {}).items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self):
            u = urlparse(self.path)
            if not self._ok_host():
                return self._send(403, 'Forbidden', 'text/plain')
            if u.path == '/':
                return self._send(200, PAGE.replace('__TOKEN__', app.token).replace('__ORIGINS__', json.dumps(list(CAPSIGHT_ORIGINS))), 'text/html',
                                  {'Content-Security-Policy': "default-src 'self'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; img-src data:; connect-src 'self'; frame-ancestors 'none'",
                                   'X-Frame-Options': 'DENY', 'Referrer-Policy': 'no-referrer'})
            if u.path == '/api/ping':
                return self._send(200, {'app': 'capsight-capture', 'version': VERSION}, extra=self._cors())
            if not self._ok_origin():
                return self._send(403, {'error': 'forbidden'})
            if u.path == '/api/state':
                return self._send(200, app.state(refresh=parse_qs(u.query).get('refresh') == ['1']))
            if u.path == '/api/download':
                name = parse_qs(u.query).get('name', [''])[0]
                p = (Path(app.out_dir) / Path(name).name)
                if not name.endswith('.pcap') or not p.exists():
                    return self._send(404, {'error': 'not found'})
                return self._send(200, p.read_bytes(), 'application/vnd.tcpdump.pcap', {'Content-Disposition': f'attachment; filename="{p.name}"'})
            self._send(404, {'error': 'not found'})

        def do_POST(self):
            if not self._ok_origin():
                return self._send(403, {'error': 'forbidden'})
            n = int(self.headers.get('Content-Length') or 0)
            try:
                body = json.loads(self.rfile.read(n) or b'{}')
            except Exception:
                body = {}
            path = urlparse(self.path).path
            if path == '/api/test':
                ok, why = can_capture_on(body.get('iface', ''))
                return self._send(200, {'ok': ok, 'reason': why})
            if path == '/api/start':
                if app.session and app.session.running:
                    return self._send(409, {'error': 'Already recording'})
                iface = body.get('iface', '')
                ok, why = can_capture_on(iface)
                if not ok:
                    return self._send(400, {'error': friendly_error(why) if why else 'Cannot capture on that interface'})
                try:
                    s = Session(iface, app.out_dir, body.get('filter', ''), int(body.get('duration') or 0), int(body.get('count') or 0),
                                int(body.get('maxMb') or 0), bool(body.get('promisc', True)))
                    s.start()
                except RuntimeError as e:
                    return self._send(400, {'error': str(e)})
                except Exception as e:
                    return self._send(400, {'error': friendly_error(e)})
                app.session = s
                app.history.append({'file': str(s.path), 'name': s.path.name, 'iface': iface, 'started': s.started})
                return self._send(200, {'ok': True})
            if path == '/api/stop':
                if app.session:
                    app.session.stop()
                return self._send(200, {'ok': True})
            if path == '/api/reveal':
                p = Path(app.out_dir) / Path(body.get('name', '')).name
                try:
                    if OS == 'Darwin':
                        subprocess.Popen(['open', '-R', str(p)])
                    elif OS == 'Windows':
                        subprocess.Popen(['explorer', '/select,', str(p)])
                    else:
                        subprocess.Popen(['xdg-open', str(p.parent)])
                except Exception as e:
                    return self._send(500, {'error': str(e)})
                return self._send(200, {'ok': True})
            if path == '/api/open-capsight':
                webbrowser.open(CAPSIGHT_URL)
                return self._send(200, {'ok': True})
            self._send(404, {'error': 'not found'})
    return H


def serve(args):
    app = App(args.out)
    try:
        srv = ThreadingHTTPServer(('127.0.0.1', args.port or DEFAULT_PORT), None)
    except OSError:
        if args.port:
            print(f'Port {args.port} is in use. Try another with --port.'); return 1
        srv = ThreadingHTTPServer(('127.0.0.1', 0), None)
        print(f'Note: port {DEFAULT_PORT} is busy (is Capsight Capture already running?), so the Capture button in Capsight will not find this copy.\n')
    port = srv.server_address[1]
    srv.RequestHandlerClass = make_handler(app, port)
    url = f'http://127.0.0.1:{port}/'
    cap = app.state(refresh=True)['capabilities']
    print_checks(cap)
    print(f'\nCapsight Capture is running at:\n  {url}\n\nKeep this window open. Press Ctrl+C here to quit.')
    if not args.no_browser:
        threading.Timer(0.6, lambda: webbrowser.open(url)).start()
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


PAGE = r'''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Capsight Capture</title><style>
:root{--bg:#000;--panel:#141416;--panel2:#1b1c1f;--line:#26272b;--line2:#3a3b40;--text:#f5f5f7;--text2:#b4b6bd;--muted:#8b8d95;--ok:#6fcf97;--bad:#f2727f;--warn:#f2c66d;--cy:#67e8f9;--btn:linear-gradient(135deg,#67e8f9,#1fa6dd 60%,#2a8de0)}
*{box-sizing:border-box}html,body{margin:0;background:var(--bg);color:var(--text);font:14px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Helvetica,Arial,sans-serif;-webkit-font-smoothing:antialiased}
.wrap{max-width:1080px;margin:0 auto;padding:28px 28px 60px}
header{display:flex;align-items:center;gap:14px;margin-bottom:26px}header svg{width:38px;height:38px}header h1{font-size:22px;margin:0;letter-spacing:-.02em}header p{margin:0;color:var(--muted);font-size:13px}
.sp{flex:1}.card{background:var(--panel);border:1px solid var(--line);border-radius:18px;padding:20px 22px;margin-bottom:18px}
.card h2{font-size:16px;margin:0 0 4px;letter-spacing:-.01em}.card .lead{color:var(--muted);margin:0 0 14px;font-size:13px}
.checks{display:grid;grid-template-columns:repeat(auto-fill,minmax(300px,1fr));gap:8px 18px}
.chk{display:flex;gap:10px;align-items:flex-start;padding:8px 0}.chk i{flex:none;width:20px;height:20px;border-radius:50%;display:grid;place-items:center;font-style:normal;font-size:12px;font-weight:700;margin-top:1px}
.chk i.y{background:rgba(111,207,151,.16);color:var(--ok)}.chk i.n{background:rgba(242,114,127,.16);color:var(--bad)}
.chk b{display:block;font-weight:600}.chk span{color:var(--text2);font-size:13px;word-break:break-word}.chk .fix{color:var(--warn);font-size:12.5px;margin-top:2px;font-family:ui-monospace,Menlo,Consolas,monospace}
.banner{border-radius:12px;padding:12px 16px;margin-bottom:14px;font-weight:600}.banner.ok{background:rgba(111,207,151,.1);color:var(--ok)}.banner.bad{background:rgba(242,114,127,.1);color:var(--bad)}
.ifs{display:grid;grid-template-columns:repeat(auto-fill,minmax(310px,1fr));gap:10px}
.if{position:relative;text-align:left;background:var(--panel2);border:1.5px solid var(--line);border-radius:14px;padding:14px 16px;color:var(--text);cursor:pointer;font:inherit;transition:border-color .15s,background .15s}
.if:hover{border-color:var(--line2)}.if.on{border-color:var(--cy);background:rgba(103,232,249,.06)}.if.off{opacity:.55}
.if .top{display:flex;align-items:center;gap:8px}.if .nm{font-weight:650;font-size:15px}.tag{font-size:11px;font-weight:600;padding:2px 8px;border-radius:999px;background:#26272b;color:var(--text2)}
.tag.Ethernet{color:#8bbaff}.tag.Wi-Fi{color:#c4b5fd}.tag.def{background:rgba(103,232,249,.14);color:var(--cy)}
.if .meta{margin-top:8px;display:grid;grid-template-columns:auto 1fr;gap:2px 12px;font-size:12.5px;color:var(--muted)}.if .meta b{color:var(--text2);font-weight:500;font-family:ui-monospace,Menlo,Consolas,monospace;word-break:break-all}
.dot{width:8px;height:8px;border-radius:50%;display:inline-block}.dot.up{background:var(--ok)}.dot.down{background:var(--bad)}.dot.unk{background:var(--muted)}
.row{display:grid;grid-template-columns:2fr 1fr 1fr 1fr;gap:12px;margin-top:6px}label.f{display:block;font-size:12.5px;color:var(--muted);margin-bottom:5px}
input[type=text],input[type=number]{width:100%;background:var(--panel2);border:1px solid var(--line2);border-radius:10px;padding:10px 12px;color:var(--text);font:13px ui-monospace,Menlo,Consolas,monospace}
input:focus{outline:2px solid rgba(103,232,249,.5);outline-offset:1px}.presets{display:flex;gap:6px;flex-wrap:wrap;margin-top:8px}
.chip:disabled,input:disabled{opacity:.45;cursor:not-allowed}.chip{background:#1f2024;border:1px solid var(--line2);color:var(--text2);border-radius:999px;padding:4px 11px;font-size:12px;cursor:pointer;font-family:inherit}.chip:hover{color:var(--text)}
.opts{display:flex;align-items:center;gap:18px;margin-top:14px;color:var(--text2);font-size:13px;flex-wrap:wrap}
.btn{border:0;border-radius:999px;padding:11px 22px;font:600 14px/1 inherit;font-family:inherit;cursor:pointer}.btn.go{background:var(--btn);color:#04111f}.btn.stop{background:#f2727f;color:#1a0306}
.btn.ghost{background:transparent;color:var(--text);border:1px solid var(--line2)}.btn:disabled{opacity:.45;cursor:not-allowed}
.live{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin:6px 0 16px}.stat{background:var(--panel2);border-radius:12px;padding:12px 14px}.stat small{color:var(--muted);font-size:12px}.stat div{font-size:24px;font-weight:700;letter-spacing:-.02em;font-variant-numeric:tabular-nums}
.rec{display:inline-flex;align-items:center;gap:8px;font-weight:600;color:var(--bad)}.rec i{width:10px;height:10px;border-radius:50%;background:var(--bad);animation:p 1.2s infinite}@keyframes p{50%{opacity:.25}}
.bars{display:grid;grid-template-columns:1fr 1fr;gap:18px}.bar{display:grid;grid-template-columns:110px 1fr 70px;align-items:center;gap:10px;font-size:12.5px;margin:5px 0}.bar .t{height:8px;border-radius:4px;background:#26272b;overflow:hidden}.bar .t i{display:block;height:100%;background:var(--btn)}
.bar span:first-child{color:var(--text2);overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.bar span:last-child{text-align:right;color:var(--muted);font-variant-numeric:tabular-nums}
.done{display:flex;align-items:center;gap:12px;flex-wrap:wrap;background:rgba(111,207,151,.08);border:1px solid rgba(111,207,151,.25);border-radius:14px;padding:14px 16px;margin-top:6px}
.done .fn{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:12.5px;color:var(--text2);word-break:break-all}.err{color:var(--bad);margin-top:10px;font-weight:600}
.hist a{color:var(--cy);text-decoration:none}.hist li{margin:4px 0;color:var(--text2)}.hist{padding-left:18px;margin:0}
.foot{color:var(--muted);font-size:12px;margin-top:10px}.hidden{display:none!important}
@media(max-width:760px){.row,.live,.bars{grid-template-columns:1fr 1fr}}
</style></head><body><div class="wrap">
<header><svg viewBox="0 0 48 48" aria-hidden="true"><defs><linearGradient id="g" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="#67e8f9"/><stop offset=".6" stop-color="#1fa6dd"/><stop offset="1" stop-color="#2a8de0"/></linearGradient></defs><circle cx="24" cy="24" r="17" fill="none" stroke="url(#g)" stroke-width="6" stroke-dasharray="80 30" stroke-linecap="round" transform="rotate(35 24 24)"/><circle cx="24" cy="24" r="6.5" fill="url(#g)"/></svg>
<div><h1>Capsight Capture</h1><p>Record traffic from a network port and save it as a .pcap file.</p></div><span class="sp"></span><button class="btn ghost" id="recheck">Check again</button></header>

<section class="card"><h2>This computer</h2><p class="lead">What Capsight Capture needs to record traffic here.</p><div id="banner" class="banner"></div><div class="checks" id="checks"></div></section>

<section class="card" id="setup"><h2>1. Choose a network port</h2><p class="lead">Pick the interface the traffic goes through. The one marked “default” carries your internet traffic.</p><div class="ifs" id="ifs"></div>
<h2 style="margin-top:22px">2. Options</h2>
<div class="row"><div><label class="f" for="flt">Capture filter (optional, BPF syntax)</label><input type="text" id="flt" placeholder="all traffic" spellcheck="false">
<div class="presets"><button class="chip" data-f="">All traffic</button><button class="chip" data-f="tcp port 80 or tcp port 443">Web</button><button class="chip" data-f="port 53">DNS</button><button class="chip" data-f="not port 22">Not SSH</button><button class="chip" data-f="arp or icmp">ARP and ping</button></div></div>
<div><label class="f" for="dur">Stop after (seconds)</label><input type="number" id="dur" min="0" placeholder="no limit"></div>
<div><label class="f" for="cnt">Stop after (packets)</label><input type="number" id="cnt" min="0" placeholder="no limit"></div>
<div><label class="f" for="mb">Stop at file size (MB)</label><input type="number" id="mb" min="0" placeholder="no limit"></div></div>
<div class="opts"><label><input type="checkbox" id="promisc" checked> Promiscuous mode (see traffic for other devices too)</label><span class="sp"></span><span id="savehint" class="foot"></span><button class="btn go" id="start" disabled>Start capture</button></div>
<div class="err hidden" id="err"></div></section>

<section class="card hidden" id="run"><div style="display:flex;align-items:center;gap:12px;margin-bottom:10px"><span class="rec" id="recl"><i></i>Recording</span><span id="runon" class="foot" style="margin:0"></span><span class="sp"></span><button class="btn stop" id="stop">Stop and save</button></div>
<div class="live"><div class="stat"><small>Packets</small><div id="sp">0</div></div><div class="stat"><small>Data</small><div id="sb">0 B</div></div><div class="stat"><small>Rate</small><div id="sr">0</div></div><div class="stat"><small>Time</small><div id="st">0:00</div></div></div>
<div class="bars"><div><h2 style="font-size:14px">Protocols</h2><div id="pr"></div></div><div><h2 style="font-size:14px">Busiest addresses</h2><div id="tk"></div></div></div>
<div class="done hidden" id="done"><div style="flex:1;min-width:240px"><b id="dmsg">Saved</b><div class="fn" id="dfile"></div></div><a class="btn go" id="dl" href="#" style="text-decoration:none">Download .pcap</a><button class="btn ghost" id="reveal">Show in folder</button><button class="btn ghost" id="capsight">Open Capsight</button><button class="btn ghost" id="again">New capture</button></div>
<div class="err hidden" id="rerr"></div></section>

<section class="card hidden" id="histc"><h2>Recent captures</h2><ul class="hist" id="hist"></ul></section>
<p class="foot">Runs only on this computer (127.0.0.1); captures are only handed to the Capsight tab that opened this window. Only capture on networks you own or are allowed to monitor.</p>
</div><script>
const T = '__TOKEN__', $ = s => document.querySelector(s);
const esc = s => String(s ?? '').replace(/[&<>"]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
const human = n => { n = +n || 0; for (const u of ['B','KB','MB','GB']) { if (n < 1024 || u === 'GB') return u === 'B' ? n.toFixed(0) + ' B' : n.toFixed(1) + ' ' + u; n /= 1024; } };
const fmtT = s => { s = Math.floor(s); return s >= 3600 ? Math.floor(s/3600) + ':' + String(Math.floor(s/60)%60).padStart(2,'0') + ':' + String(s%60).padStart(2,'0') : Math.floor(s/60) + ':' + String(s%60).padStart(2,'0'); };
const api = (p, body) => fetch(p + (p.includes('?') ? '&' : '?') + 't=' + T, body ? { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-Token': T }, body: JSON.stringify(body) } : { headers: { 'X-Token': T } }).then(async r => { const j = await r.json().catch(() => ({})); if (!r.ok) throw new Error(j.error || r.statusText); return j; });
let S = null, sel = null, poll = null, ready = false;

function renderChecks(c) {
  ready = c.ready;
  $('#banner').className = 'banner ' + (c.ready ? 'ok' : 'bad');
  $('#banner').textContent = c.ready ? 'Ready to capture.' : 'Not ready yet. Fix the items marked ✗, then click Check again.';
  $('#checks').innerHTML = c.checks.map(x => `<div class="chk"><i class="${x.ok ? 'y' : 'n'}">${x.ok ? '✓' : '✕'}</i><div><b>${esc(x.label)}</b><span>${esc(x.detail)}</span>${!x.ok && x.fix ? `<div class="fix">${esc(x.fix)}</div>` : ''}</div></div>`).join('');
}
function renderIfs(list) {
  if (!sel || !list.some(i => i.name === sel)) sel = (list.find(i => i.default) || list.find(i => i.up && i.kind !== 'Loopback') || list[0] || {}).name;
  $('#ifs').innerHTML = list.map(i => `<button class="if ${i.name === sel ? 'on' : ''} ${i.up === false ? 'off' : ''}" data-n="${esc(i.name)}"><div class="top"><span class="dot ${i.up ? 'up' : i.up === false ? 'down' : 'unk'}" title="${i.up ? 'Up' : i.up === false ? 'Down' : 'Unknown'}"></span><span class="nm">${esc(i.label)}</span><span class="tag ${esc(i.kind)}">${esc(i.kind)}</span>${i.default ? '<span class="tag def">default</span>' : ''}</div>
    ${i.description ? `<div class="foot" style="margin:4px 0 0">${esc(i.description)}</div>` : ''}
    <div class="meta"><span>IPv4</span><b>${esc(i.ipv4 || '—')}</b><span>MAC</span><b>${esc(i.mac || '—')}</b>${i.speed ? `<span>Speed</span><b>${i.speed >= 1000 ? i.speed / 1000 + ' Gb/s' : i.speed + ' Mb/s'}</b>` : ''}${i.traffic != null ? `<span>Traffic so far</span><b>${human(i.traffic)}</b>` : ''}</div></button>`).join('');
  document.querySelectorAll('.if').forEach(b => b.onclick = () => { sel = b.dataset.n; renderIfs(list); });
  $('#start').disabled = !ready || !sel;
}
function renderRun(s) {
  const on = s && (s.running || s.packets || s.error || s.stop_reason);
  $('#setup').classList.toggle('hidden', !!(s && s.running));
  $('#run').classList.toggle('hidden', !on);
  if (!on) return;
  $('#recl').classList.toggle('hidden', !s.running); $('#stop').classList.toggle('hidden', !s.running);
  $('#runon').textContent = 'on ' + s.iface + (s.filter ? ', filter: ' + s.filter : '') + (s.limits.duration ? ', stops after ' + s.limits.duration + ' s' : '');
  $('#sp').textContent = s.packets.toLocaleString(); $('#sb').textContent = human(s.bytes);
  $('#sr').textContent = s.running ? Math.round(s.pps).toLocaleString() + '/s' : '—'; $('#st').textContent = fmtT(s.elapsed);
  const bars = (rows, total, fmt) => rows.length ? rows.map(([k, v]) => `<div class="bar"><span title="${esc(k)}">${esc(k)}</span><div class="t"><i style="width:${Math.max(2, v / total * 100)}%"></i></div><span>${fmt(v)}</span></div>`).join('') : '<div class="foot">Waiting for packets…</div>';
  $('#pr').innerHTML = bars(s.protocols, Math.max(1, s.protocols[0]?.[1] || 1), v => v.toLocaleString());
  $('#tk').innerHTML = bars(s.talkers, Math.max(1, s.talkers[0]?.[1] || 1), human);
  $('#done').classList.toggle('hidden', s.running);
  if (!s.running) { $('#dmsg').textContent = (s.stop_reason || 'Stopped') + '. Saved ' + s.packets.toLocaleString() + ' packets (' + human(s.size) + ').'; $('#dfile').textContent = s.file; $('#dl').href = '/api/download?name=' + encodeURIComponent(s.name) + '&t=' + T; }
  $('#rerr').classList.toggle('hidden', !s.error); $('#rerr').textContent = s.error || '';
}
function renderHist(h) {
  $('#histc').classList.toggle('hidden', !h.length);
  $('#hist').innerHTML = h.map(x => `<li><a href="/api/download?name=${encodeURIComponent(x.name)}&t=${T}">${esc(x.name)}</a> · ${esc(x.iface)}</li>`).join('');
}
async function refresh(full) {
  try { S = await api('/api/state' + (full ? '?refresh=1' : '')); } catch (e) { $('#banner').className = 'banner bad'; $('#banner').textContent = 'Lost contact with Capsight Capture. Is it still running in the terminal?'; return; }
  if (full) { renderChecks(S.capabilities); renderIfs(S.capabilities.interfaces); $('#savehint').textContent = 'Saves to ' + S.outDir;
    const f = S.capabilities.filters; $('#flt').disabled = !f; $('#flt').placeholder = f ? 'all traffic' : 'filters need libpcap; records all traffic'; document.querySelectorAll('.chip[data-f]').forEach(c => c.disabled = !f); }
  renderRun(S.session); renderHist(S.history);
  clearInterval(poll); if (S.session && S.session.running) poll = setInterval(() => refresh(false), 700);
}
$('#recheck').onclick = () => refresh(true);
document.querySelectorAll('.chip[data-f]').forEach(c => c.onclick = () => { $('#flt').value = c.dataset.f; });
$('#start').onclick = async () => {
  $('#err').classList.add('hidden'); $('#start').disabled = true; $('#start').textContent = 'Starting…';
  try { await api('/api/start', { iface: sel, filter: $('#flt').value, duration: +$('#dur').value || 0, count: +$('#cnt').value || 0, maxMb: +$('#mb').value || 0, promisc: $('#promisc').checked }); await refresh(false); }
  catch (e) { $('#err').textContent = e.message; $('#err').classList.remove('hidden'); }
  $('#start').disabled = !ready; $('#start').textContent = 'Start capture';
};
$('#stop').onclick = async () => { $('#stop').disabled = true; await api('/api/stop', {}).catch(() => {}); $('#stop').disabled = false; refresh(false); };
$('#reveal').onclick = () => api('/api/reveal', { name: S.session.name }).catch(e => alert(e.message));
// Opened from Capsight's "Capture live traffic" button? Then the finished capture goes straight back into it.
const ORIGINS = __ORIGINS__; let capsight = null;
const okOrigin = o => ORIGINS.includes(o) || /^http:\/\/(localhost|127\.0\.0\.1)(:\d+)?$/.test(o) && o !== location.origin;
window.addEventListener('message', e => { if (e.source === window.opener && okOrigin(e.origin) && e.data && e.data.type === 'capsight-hello') { capsight = e.origin; $('#capsight').textContent = 'Open in Capsight'; } });
if (window.opener) try { window.opener.postMessage({ type: 'capsight-capture-ready' }, '*'); } catch (e) {}
$('#capsight').onclick = async () => {
  if (capsight && window.opener && !window.opener.closed) {
    const b = $('#capsight'); b.disabled = true; b.textContent = 'Sending…';
    try {
      const r = await fetch('/api/download?name=' + encodeURIComponent(S.session.name) + '&t=' + T); const buf = await r.arrayBuffer();
      window.opener.postMessage({ type: 'capsight-pcap', name: S.session.name, buf }, capsight, [buf]);
      b.textContent = 'Opened in Capsight ✓'; setTimeout(() => window.close(), 900);
    } catch (e) { b.textContent = 'Open in Capsight'; alert('Could not send the capture: ' + e.message); }
    b.disabled = false; return;
  }
  api('/api/open-capsight', {});
};
$('#again').onclick = () => { $('#run').classList.add('hidden'); $('#setup').classList.remove('hidden'); };
refresh(true);
</script></body></html>'''


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
    ap.add_argument('--no-browser', action='store_true', help="don't open the browser automatically")
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
