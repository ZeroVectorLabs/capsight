/* ===================== Loading & post-processing ===================== */
async function loadCapture(u8, name, onProgress) {
  const fmt = captureFormat(u8);
  if (!fmt) throw new Error('Not a pcap or pcapng file (unrecognised magic number). Try exporting from Wireshark as .pcap or .pcapng.');
  const it = fmt === 'pcap' ? readPcap(u8) : readPcapng(u8);
  const pk = [];
  let last = performance.now();
  for (const r of it) {
    r.i = pk.length;
    r.s = dissect(u8.subarray(r.off, r.off + r.cap), r.lt, null);
    pk.push(r);
    if ((pk.length & 2047) === 0 && performance.now() - last > 60) {
      onProgress && onProgress(r.off / u8.length, pk.length);
      await new Promise(res => setTimeout(res, 0));
      last = performance.now();
    }
  }
  if (!pk.length) throw new Error('The capture contains no packets.');
  onProgress && onProgress(1, pk.length);
  const cap = { name, fmt, u8, pk, size: u8.length };
  postProcess(cap);
  return cap;
}

function pkBytes(cap, i) { const r = cap.pk[i]; return cap.u8.subarray(r.off, r.off + r.cap); }
function payloadText(cap, i, max) { const r = cap.pk[i], s = r.s; if (!s.pll) return ''; return latin(cap.u8, r.off + s.plo, r.off + s.plo + s.pll, max || 4096); }

function postProcess(cap) {
  const pk = cap.pk;
  let t0 = Infinity, t1 = -Infinity, bytes = 0;
  for (const r of pk) { if (r.t < t0) t0 = r.t; if (r.t > t1) t1 = r.t; bytes += r.len; }
  cap.t0 = t0; cap.t1 = t1; cap.bytes = bytes; cap.dur = Math.max(t1 - t0, 1e-6);
  // streams
  const map = new Map(), streams = [];
  for (const r of pk) {
    const s = r.s;
    if (s.sp < 0 || !s.src) continue;
    const a = s.src + '|' + s.sp, b = s.dst + '|' + s.dp;
    const fwd = a < b;
    const key = s.l4 + '|' + (fwd ? a + '|' + b : b + '|' + a);
    let st = map.get(key);
    if (!st) {
      st = { id: streams.length, l4: s.l4, a: s.src, ap: s.sp, b: s.dst, bp: s.dp, pk: [], bytes: 0, ab: 0, ba: 0, t0: r.t, t1: r.t, isn: {}, proto: s.proto, syn: false, client: null, payload: 0 };
      map.set(key, st); streams.push(st);
    }
    const dirA = s.src === st.a && s.sp === st.ap;
    s.st = st.id; s.dirA = dirA;
    st.pk.push(r.i); st.bytes += r.len; if (dirA) st.ab += r.len; else st.ba += r.len;
    st.t1 = r.t; st.payload += s.pll;
    if (s.proto !== 'TCP' && s.proto !== 'UDP' && (st.proto === 'TCP' || st.proto === 'UDP')) st.proto = s.proto;
    if (s.l4 === 'TCP') {
      const side = dirA ? 'a' : 'b', other = dirA ? 'b' : 'a';
      if ((s.fl & 2) && !(s.fl & 16)) { st.syn = true; st.client = st.client || (dirA ? 'a' : 'b'); st.isn[side] = s.seq; }
      else if ((s.fl & 2) && (s.fl & 16)) st.isn[side] = s.seq;
      if (st.isn[side] === undefined) st.isn[side] = s.seq;
      if (s.ti) {
        const rel = (s.seq - st.isn[side] + 4294967296) % 4294967296;
        const ra = st.isn[other] !== undefined ? (s.ack - st.isn[other] + 4294967296) % 4294967296 : s.ack;
        s.info = s.sp + ' → ' + s.dp + ' [' + tcpFlagStr(s.fl) + '] Seq=' + rel + (s.fl & 16 ? ' Ack=' + ra : '') + ' Win=' + s.win + ' Len=' + s.pll;
      }
    } else if (!st.client) st.client = 'a';
    // HTTP request/response pairing
    if (s.http) {
      if (!s.http.resp) { (st.pend || (st.pend = [])).push(r.i); }
      else if (st.pend && st.pend.length) { const q = st.pend.shift(); pk[q].s.http.status = s.http.status; pk[q].s.http.respIdx = r.i; s.http.reqIdx = q; }
    }
  }
  for (const st of streams) {
    if (st.client === 'b') { // normalise so a = client
      [st.a, st.b] = [st.b, st.a]; [st.ap, st.bp] = [st.bp, st.ap]; [st.ab, st.ba] = [st.ba, st.ab];
      st.isn = { a: st.isn.b, b: st.isn.a };
      for (const i of st.pk) pk[i].s.dirA = !pk[i].s.dirA;
    }
    if (!st.client && st.l4 === 'TCP' && st.ap < st.bp && st.ap < 1024) { // guess client by port
      [st.a, st.b] = [st.b, st.a]; [st.ap, st.bp] = [st.bp, st.ap]; [st.ab, st.ba] = [st.ba, st.ab];
      for (const i of st.pk) pk[i].s.dirA = !pk[i].s.dirA;
    }
    delete st.pend;
  }
  cap.streams = streams;
  // MAC → IP map for labelling
  const macIp = new Map();
  for (const r of pk) { const s = r.s; if (s.smac && s.ipv === 4 && isPrivate(s.src)) { if (!macIp.has(s.smac)) macIp.set(s.smac, new Set()); macIp.get(s.smac).add(s.src); } }
  cap.macIp = macIp;
  cap.threats = detectThreats(cap);
  cap.flow = buildAttackFlow(cap, cap.threats);
}

/* ===================== Aggregation (respects filters) ===================== */
function aggregate(cap, idx) {
  const pk = cap.pk;
  const A = { n: 0, bytes: 0, t0: Infinity, t1: -Infinity, protos: new Map(), hosts: new Map(), pairs: new Map(), ports: new Map(), sizes: new Array(7).fill(0), dns: new Map(), sni: new Map(), http: [], streams: new Set() };
  const SZ = [64, 128, 256, 512, 1024, 1518];
  const host = ip => { let h = A.hosts.get(ip); if (!h) { h = { ip, tx: 0, rx: 0, ptx: 0, prx: 0, protos: new Map() }; A.hosts.set(ip, h); } return h; };
  const n = idx ? idx.length : pk.length;
  for (let k = 0; k < n; k++) {
    const r = pk[idx ? idx[k] : k], s = r.s, L = r.len;
    A.n++; A.bytes += L; if (r.t < A.t0) A.t0 = r.t; if (r.t > A.t1) A.t1 = r.t;
    let pr = A.protos.get(s.proto); if (!pr) { pr = { name: s.proto, p: 0, b: 0 }; A.protos.set(s.proto, pr); } pr.p++; pr.b += L;
    let b = 0; while (b < SZ.length && L > SZ[b]) b++; A.sizes[b]++;
    if (s.src && s.dst) {
      const hs = host(s.src), hd = host(s.dst);
      hs.tx += L; hs.ptx++; hd.rx += L; hd.prx++;
      hs.protos.set(s.proto, (hs.protos.get(s.proto) || 0) + L);
      const fwd = s.src < s.dst, key = fwd ? s.src + '|' + s.dst : s.dst + '|' + s.src;
      let c = A.pairs.get(key);
      if (!c) { c = { a: fwd ? s.src : s.dst, b: fwd ? s.dst : s.src, ab: 0, ba: 0, p: 0, protos: new Map(), t0: r.t, t1: r.t }; A.pairs.set(key, c); }
      if (fwd) c.ab += L; else c.ba += L; c.p++; c.t1 = r.t;
      c.protos.set(s.proto, (c.protos.get(s.proto) || 0) + L);
    }
    if (s.st !== undefined) A.streams.add(s.st);
    if (s.dp >= 0) {
      const st = s.st !== undefined ? cap.streams[s.st] : null;
      const port = st ? st.bp : Math.min(s.sp, s.dp);
      const key = s.l4 + '/' + port;
      let po = A.ports.get(key); if (!po) { po = { key, l4: s.l4, port, p: 0, b: 0, name: (s.l4 === 'TCP' ? TCP_PORTS : UDP_PORTS)[port] || '' }; A.ports.set(key, po); }
      po.p++; po.b += L;
    }
    if (s.dns) {
      const q = s.dns.qs[0];
      if (q) {
        const nm = q.name.toLowerCase();
        let d = A.dns.get(nm); if (!d) { d = { name: nm, q: 0, r: 0, types: new Set(), ans: new Set(), nx: 0, clients: new Set(), first: r.i }; A.dns.set(nm, d); }
        d.types.add(q.type);
        if (s.dns.qr) { d.r++; if (s.dns.rcode === 3) d.nx++; s.dns.ans.forEach(a => { if (a.type === 'A' || a.type === 'AAAA' || a.type === 'CNAME') d.ans.add(a.val); }); }
        else { d.q++; d.clients.add(s.src); }
      }
    }
    if (s.sni && s.tlsHello === 'client') {
      let t = A.sni.get(s.sni); if (!t) { t = { name: s.sni, n: 0, clients: new Set(), servers: new Set(), first: r.i, alpn: s.alpn || '', bytes: 0 }; A.sni.set(s.sni, t); }
      t.n++; t.clients.add(s.src); t.servers.add(s.dst);
      if (s.st !== undefined) t.bytes += cap.streams[s.st].bytes;
    }
    if (s.http && !s.http.resp) A.http.push(r.i);
  }
  if (!isFinite(A.t0)) { A.t0 = cap.t0; A.t1 = cap.t0; }
  return A;
}

/* ===================== Threat detection ===================== */
function isPrivate(ip) {
  if (!ip) return false;
  if (ip.includes(':')) { const l = ip.toLowerCase(); return l === '::1' || l.startsWith('fe80') || l.startsWith('fc') || l.startsWith('fd') || l.startsWith('ff'); }
  const p = ip.split('.').map(Number);
  if (p.length !== 4) return true; // MAC addresses etc.
  return p[0] === 10 || p[0] === 127 || (p[0] === 172 && p[1] >= 16 && p[1] < 32) || (p[0] === 192 && p[1] === 168) || (p[0] === 169 && p[1] === 254) || p[0] >= 224 || p[0] === 0 || ip === '255.255.255.255';
}
function isMac(x) { return /^([0-9a-f]{2}:){5}[0-9a-f]{2}$/i.test(x); }
function isIp(x) { return /^\d{1,3}(\.\d{1,3}){3}$/.test(x) || (x.includes(':') && !isMac(x) && /^[0-9a-f:.]+$/i.test(x)); }
function entropy(str) { const m = {}; for (const c of str) m[c] = (m[c] || 0) + 1; let e = 0; const n = str.length; for (const k in m) { const p = m[k] / n; e -= p * Math.log2(p); } return e; }
function baseDomain(n) { const p = n.toLowerCase().replace(/\.$/, '').split('.'); if (p.length <= 2) return p.join('.'); const sl = p[p.length - 2]; if (['co', 'com', 'net', 'org', 'gov', 'ac', 'edu'].includes(sl) && p[p.length - 1].length === 2) return p.slice(-3).join('.'); return p.slice(-2).join('.'); }
function safeDecode(x) { try { return decodeURIComponent(x.replace(/\+/g, ' ')); } catch (e) { return x; } }
function mask(pw) { if (!pw) return ''; return pw.length <= 2 ? '••' : pw[0] + '•'.repeat(Math.min(10, pw.length - 2)) + pw[pw.length - 1]; }

const STAGES = [
  { k: 'recon', name: 'Reconnaissance', ta: 'TA0043' },
  { k: 'resource', name: 'Resource Development', ta: 'TA0042' },
  { k: 'access', name: 'Initial Access', ta: 'TA0001' },
  { k: 'exec', name: 'Execution', ta: 'TA0002' },
  { k: 'cred', name: 'Credential Access', ta: 'TA0006' },
  { k: 'disc', name: 'Discovery', ta: 'TA0007' },
  { k: 'lateral', name: 'Lateral Movement', ta: 'TA0008' },
  { k: 'c2', name: 'Command & Control', ta: 'TA0011' },
  { k: 'exfil', name: 'Exfiltration', ta: 'TA0010' },
  { k: 'impact', name: 'Impact', ta: 'TA0040' },
];
const SEV_RANK = { critical: 4, high: 3, medium: 2, low: 1 };
const AUTH_PORTS = { 21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 110: 'POP3', 143: 'IMAP', 389: 'LDAP', 445: 'SMB', 1433: 'MSSQL', 3306: 'MySQL', 3389: 'RDP', 5432: 'PostgreSQL', 5900: 'VNC', 5985: 'WinRM', 6379: 'Redis' };
const ADMIN_PORTS = { 22: 'SSH', 23: 'Telnet', 135: 'MSRPC', 139: 'NetBIOS', 445: 'SMB', 3389: 'RDP', 5985: 'WinRM', 5986: 'WinRM', 5900: 'VNC' };
const BAD_PORTS = { 4444: 'Metasploit default', 1337: 'leet', 31337: 'Back Orifice / elite', 6666: 'IRC/backdoor', 6667: 'IRC', 12345: 'NetBus', 5555: 'common RAT / ADB', 9001: 'Tor ORPort', 4445: 'Metasploit alt', 1234: 'common backdoor' };
const WEB_RULES = [
  { k: 'cmdi', name: 'Command injection', sev: 'critical', re: /((;|\|\|?|`|&&)\s*(cat|id|whoami|uname|wget|curl|nc|ncat|bash|sh|python\d?|perl|powershell|ping|rm|chmod)\b|\$\((cat|id|whoami|curl|wget)|\/bin\/(ba)?sh\b|cmd\.exe|nc\s+-e)/i },
  { k: 'log4j', name: 'Log4Shell (JNDI injection)', sev: 'critical', re: /\$\{(jndi|\$\{lower:j|\$\{::-j|\$\{env:)/i, hdr: true },
  { k: 'shellshock', name: 'Shellshock (CVE-2014-6271)', sev: 'critical', re: /\(\)\s*\{\s*:?\s*;?\s*\}\s*;/, hdr: true },
  { k: 'sqli', name: 'SQL injection', sev: 'high', re: /(=[\w-]*'(\s|&|$)|\bunion\b[\s\S]{0,40}\bselect\b|information_schema|'\s*or\s*'?\w*'?\s*=\s*'?\w*|\bor\s+1\s*=\s*1\b|\band\s+\d+\s*=\s*\d+|\bsleep\s*\(\s*\d+\s*\)|benchmark\s*\(|waitfor\s+delay|order\s+by\s+\d+\s*--|;\s*drop\s+table|xp_cmdshell|load_file\s*\(|into\s+outfile|'\s*--)/i },
  { k: 'lfi', name: 'Path traversal / LFI', sev: 'high', re: /(\.\.\/|\.\.\\|%2e%2e%2f|\/etc\/passwd|\/etc\/shadow|win\.ini|boot\.ini|\/proc\/self\/)/i },
  { k: 'xss', name: 'Cross-site scripting', sev: 'medium', re: /(<script|javascript:|onerror\s*=|onload\s*=|<svg[^>]*\son\w+=|document\.cookie|alert\s*\()/i },
];
const TOOL_UA = /(sqlmap|nikto|nmap|masscan|zgrab|gobuster|dirbuster|\bdirb\b|wfuzz|ffuf|feroxbuster|nuclei|acunetix|nessus|openvas|hydra|metasploit|wpscan|havij|w3af|arachni|skipfish|commix|xsstrike)/i;

function detectThreats(cap) {
  const pk = cap.pk, streams = cap.streams, D = [];
  const add = d => { d.id = D.length; d.ev = d.ev || []; d.t0 = d.t0 ?? pk[d.ev[0]]?.t; d.t1 = d.t1 ?? pk[d.ev[d.ev.length - 1]]?.t; D.push(d); };
  const pairKey = (a, b) => a + '→' + b;

  // ---------- gather TCP/UDP/ICMP/ARP facts in one pass ----------
  const synBy = new Map();     // src→dst : {ports:Set, ev:[], t0,t1, kinds}
  const synAns = new Map();    // dst→src : {open:Set, closed:Set, ev:[]}
  const synToPort = new Map(); // dst|port : {n, srcs:Set, ev:[], times:[]}
  const echoBy = new Map();    // src : {dsts:Set, ev:[]}
  const echoRep = new Map();   // replier→src
  const udpProbe = new Map();  // src→dst : ports
  const unreach = new Map();
  const arpReq = new Map();    // smac : Set targets, ev
  const arpClaims = new Map(); // ip : Map mac→{n, ev:[], unsolicited}
  const arpAsked = new Set();
  const icmpBig = new Map();
  const dhcpServers = new Map(), dhcpDisc = new Map();
  const heart = [];
  for (const r of pk) {
    const s = r.s;
    if (s.l4 === 'TCP' && s.sp >= 0) {
      const f = s.fl;
      const probe = ((f & 2) && !(f & 16)) || f === 0 || f === 1 || (f & 0x29) === 0x29 && !(f & 16);
      if (probe) {
        const k = pairKey(s.src, s.dst);
        let o = synBy.get(k); if (!o) { o = { src: s.src, dst: s.dst, ports: new Set(), ev: [], kinds: new Set() }; synBy.set(k, o); }
        if (!o.ports.has(s.dp)) { o.ports.add(s.dp); o.ev.push(r.i); } o.kinds.add(f === 0 ? 'NULL' : f === 1 ? 'FIN' : (f & 0x29) === 0x29 ? 'Xmas' : 'SYN');
        if (f & 2) {
          const pk2 = s.dst + '|' + s.dp;
          let q = synToPort.get(pk2); if (!q) { q = { dst: s.dst, port: s.dp, n: 0, srcs: new Set(), ev: [], acked: 0 }; synToPort.set(pk2, q); }
          q.n++; q.srcs.add(s.src); q.ev.push(r.i);
        }
      } else if ((f & 2) && (f & 16) || (f & 4)) {
        const k = pairKey(s.dst, s.src);
        let o = synAns.get(k); if (!o) { o = { open: new Set(), closed: new Set(), ev: [] }; synAns.set(k, o); }
        if (f & 2) o.open.add(s.sp); else o.closed.add(s.sp);
        o.ev.push(r.i);
      }
    }
    if (s.l4 === 'UDP' && s.sp >= 0 && s.pll < 64 && !s.dns) {
      const k = pairKey(s.src, s.dst);
      let o = udpProbe.get(k); if (!o) { o = { src: s.src, dst: s.dst, ports: new Set(), ev: [] }; udpProbe.set(k, o); }
      o.ports.add(s.dp); o.ev.push(r.i);
    }
    if (s.icmp) {
      const ty = s.icmp.type;
      if ((ty === 8 && !s.icmp.v6) || (ty === 128 && s.icmp.v6)) {
        let o = echoBy.get(s.src); if (!o) { o = { dsts: new Set(), ev: [] }; echoBy.set(s.src, o); }
        o.dsts.add(s.dst); o.ev.push(r.i);
        if (s.pll >= 120) { const k = pairKey(s.src, s.dst); let b = icmpBig.get(k); if (!b) { b = { src: s.src, dst: s.dst, ev: [], bytes: 0 }; icmpBig.set(k, b); } b.ev.push(r.i); b.bytes += s.pll; }
      }
      if ((ty === 0 && !s.icmp.v6) || (ty === 129 && s.icmp.v6)) { let o = echoRep.get(s.dst); if (!o) { o = new Set(); echoRep.set(s.dst, o); } o.add(s.src); }
      if (ty === 3 && s.icmp.code === 3 && s.icmp.inner) { const k = pairKey(s.icmp.inner.src, s.icmp.inner.dst); unreach.set(k, (unreach.get(k) || 0) + 1); }
    }
    if (s.arp) {
      const a = s.arp;
      if (a.op === 1) {
        arpAsked.add(a.tpa);
        if (a.spa !== a.tpa) { let o = arpReq.get(a.sha); if (!o) { o = { tg: new Set(), ev: [], ip: a.spa }; arpReq.set(a.sha, o); } o.tg.add(a.tpa); o.ev.push(r.i); }
      }
      if (a.spa !== '0.0.0.0') {
        let m = arpClaims.get(a.spa); if (!m) { m = new Map(); arpClaims.set(a.spa, m); }
        let c = m.get(a.sha); if (!c) { c = { n: 0, ev: [], unsol: 0, first: r.t }; m.set(a.sha, c); }
        c.n++; c.ev.push(r.i);
        if (a.op === 2 && !arpAsked.has(a.spa)) c.unsol++;
        if (a.op === 2) arpAsked.delete(a.spa);
      }
    }
    if (s.dhcp) {
      if (s.dhcp.type === 2 || s.dhcp.type === 5) { const sv = s.dhcp.server || s.src; let o = dhcpServers.get(sv); if (!o) { o = { ev: [], mac: s.smac }; dhcpServers.set(sv, o); } o.ev.push(r.i); }
      if (s.dhcp.type === 1) { let o = dhcpDisc.get('all'); if (!o) { o = { macs: new Set(), ev: [] }; dhcpDisc.set('all', o); } o.macs.add(s.dhcp.mac); o.ev.push(r.i); }
    }
    if (s.heartbeat && s.heartbeat.payloadLen > s.heartbeat.len) heart.push(r.i);
  }

  // ---------- 1. Port scans ----------
  for (const o of synBy.values()) {
    if (o.ports.size < 15) continue;
    const ans = synAns.get(pairKey(o.src, o.dst)) || { open: new Set(), closed: new Set(), ev: [] };
    const ext = !isPrivate(o.src);
    const ta = pk[o.ev[0]].t, tb = pk[o.ev[o.ev.length - 1]].t + 2;
    const ansEv = ans.ev.filter(i => pk[i].t >= ta && pk[i].t <= tb);
    const openS = new Set(), closedS = new Set();
    ansEv.forEach(i => { const s = pk[i].s; if (s.fl & 2) openS.add(s.sp); else closedS.add(s.sp); });
    ans.open = openS; ans.closed = closedS; ans.ev = ansEv;
    const open = [...openS].sort((a, b) => a - b);
    const kinds = [...o.kinds].join('/');
    add({
      type: 'portscan', title: 'TCP ' + kinds + ' port scan', sev: open.length ? 'high' : 'medium',
      stage: ext ? 'recon' : 'disc', tech: ext ? 'T1595.001' : 'T1046', techName: ext ? 'Active Scanning: Scanning IP Blocks' : 'Network Service Discovery',
      src: o.src, dst: o.dst, count: o.ports.size,
      summary: o.src + ' probed ' + o.ports.size + ' TCP ports on ' + o.dst + (open.length ? ' and found ' + open.length + ' open: ' + open.slice(0, 12).join(', ') : ' (no open ports answered)') + '.',
      details: [['Ports probed', o.ports.size], ['Scan type', kinds], ['Open ports', open.join(', ') || '—'], ['Closed (RST)', ans.closed.size], ['Probe packets', o.ev.length]],
      ev: o.ev.concat(ans.ev).sort((a, b) => a - b), tags: open.map(p => p + '/' + (TCP_PORTS[p] || 'tcp')),
    });
  }
  for (const o of udpProbe.values()) {
    if (o.ports.size < 20) continue;
    const un = unreach.get(pairKey(o.src, o.dst)) || 0;
    if (un < 5) continue;
    add({ type: 'udpscan', title: 'UDP port scan', sev: 'medium', stage: isPrivate(o.src) ? 'disc' : 'recon', tech: 'T1046', techName: 'Network Service Discovery', src: o.src, dst: o.dst, count: o.ports.size, summary: o.src + ' sent empty/small UDP probes to ' + o.ports.size + ' ports on ' + o.dst + ' (' + un + ' ICMP port-unreachable replies).', details: [['Ports probed', o.ports.size], ['ICMP unreachable', un]], ev: o.ev });
  }
  // horizontal SYN scan (same port, many hosts, mostly unanswered)
  const horiz = new Map();
  for (const [k, q] of synToPort) for (const src of q.srcs) { const hk = src + '|' + q.port; let h = horiz.get(hk); if (!h) { h = { src, port: q.port, dsts: new Set(), ev: [] }; horiz.set(hk, h); } h.dsts.add(q.dst); }
  for (const h of horiz.values()) {
    if (h.dsts.size < 10) continue;
    let answered = 0; for (const d of h.dsts) { const a = synAns.get(pairKey(h.src, d)); if (a && a.open.has(h.port)) answered++; }
    if (answered / h.dsts.size > 0.5) continue;
    for (const d of h.dsts) { const q = synToPort.get(d + '|' + h.port); if (q) q.ev.forEach(i => { if (pk[i].s.src === h.src) h.ev.push(i); }); }
    h.ev.sort((a, b) => a - b);
    add({ type: 'hscan', title: 'Horizontal scan on port ' + h.port, sev: 'medium', stage: isPrivate(h.src) ? 'disc' : 'recon', tech: 'T1046', techName: 'Network Service Discovery', src: h.src, dst: h.dsts.size + ' hosts', count: h.dsts.size, summary: h.src + ' probed port ' + h.port + ' on ' + h.dsts.size + ' hosts; ' + answered + ' answered.', details: [['Port', h.port + ' (' + (TCP_PORTS[h.port] || 'tcp') + ')'], ['Targets', h.dsts.size], ['Answered', answered]], ev: h.ev });
  }
  // ping sweep
  for (const [src, o] of echoBy) {
    if (o.dsts.size < 10) continue;
    const alive = [...(echoRep.get(src) || [])];
    add({ type: 'sweep', title: 'ICMP ping sweep', sev: 'medium', stage: isPrivate(src) ? 'disc' : 'recon', tech: 'T1018', techName: 'Remote System Discovery', src, dst: o.dsts.size + ' hosts', count: o.dsts.size, summary: src + ' pinged ' + o.dsts.size + ' addresses; ' + alive.length + ' responded (' + alive.slice(0, 6).join(', ') + (alive.length > 6 ? ', …' : '') + ').', details: [['Addresses pinged', o.dsts.size], ['Live hosts', alive.length], ['Responders', alive.join(', ') || '—']], ev: o.ev, tags: alive.slice(0, 10) });
  }
  // ARP sweep
  for (const [m, o] of arpReq) {
    if (o.tg.size < 25) continue;
    add({ type: 'arpsweep', title: 'ARP scan', sev: 'medium', stage: 'disc', tech: 'T1018', techName: 'Remote System Discovery', src: o.ip || m, dst: o.tg.size + ' hosts', count: o.tg.size, summary: m + ' (' + o.ip + ') sent ARP requests for ' + o.tg.size + ' different addresses.', details: [['MAC', m], ['Addresses requested', o.tg.size]], ev: o.ev });
  }

  // ---------- 2. Lateral movement attempts ----------
  const lat = new Map();
  for (const q of synToPort.values()) {
    if (!ADMIN_PORTS[q.port] || !isPrivate(q.dst)) continue;
    for (const src of q.srcs) { if (!isPrivate(src)) continue; let o = lat.get(src); if (!o) { o = { src, dsts: new Set(), ports: new Set(), ev: [] }; lat.set(src, o); } o.dsts.add(q.dst); o.ports.add(q.port); q.ev.forEach(i => { if (pk[i].s.src === src) o.ev.push(i); }); }
  }
  for (const o of lat.values()) {
    if (o.dsts.size < 3) continue;
    let ok = []; for (const d of o.dsts) { const a = synAns.get(pairKey(o.src, d)); if (a) for (const p of a.open) if (ADMIN_PORTS[p]) ok.push(d + ':' + p); }
    o.ev.sort((a, b) => a - b);
    add({ type: 'lateral', title: 'Lateral movement attempts (' + [...o.ports].map(p => ADMIN_PORTS[p]).filter((v, i, a) => a.indexOf(v) === i).join('/') + ')', sev: 'high', stage: 'lateral', tech: 'T1021', techName: 'Remote Services', src: o.src, dst: o.dsts.size + ' internal hosts', targets: [...o.dsts], count: o.dsts.size, summary: o.src + ' tried remote-admin services on ' + o.dsts.size + ' internal hosts' + (ok.length ? '; reachable: ' + ok.join(', ') : '') + '.', details: [['Targets', [...o.dsts].join(', ')], ['Services', [...o.ports].map(p => p + '/' + ADMIN_PORTS[p]).join(', ')], ['Reachable', ok.join(', ') || 'none']], ev: o.ev });
  }

  // ---------- 3. Brute force ----------
  const bf = new Map();
  for (const st of streams) {
    if (st.l4 !== 'TCP' || !AUTH_PORTS[st.bp] || !st.syn) continue;
    const k = st.a + '|' + st.b + '|' + st.bp;
    let o = bf.get(k); if (!o) { o = { src: st.a, dst: st.b, port: st.bp, n: 0, withData: 0, ev: [], t0: st.t0, t1: st.t1, banner: '' }; bf.set(k, o); }
    o.n++; if (st.payload > 0) o.withData++; o.t1 = Math.max(o.t1, st.t1);
    o.ev.push(st.pk[0]);
    if (!o.banner) for (const i of st.pk) { const s = pk[i].s; if (s.banner && s.dirA) { o.banner = s.banner; break; } }
  }
  for (const o of bf.values()) {
    if (o.n < 10 || o.withData < 5) continue;
    const dur = Math.max(o.t1 - o.t0, 0.001);
    add({ type: 'bruteforce', title: AUTH_PORTS[o.port] + ' brute force', sev: 'high', stage: 'cred', tech: 'T1110.001', techName: 'Brute Force: Password Guessing', src: o.src, dst: o.dst, dport: o.port, count: o.n, t0: o.t0, t1: o.t1, summary: o.src + ' opened ' + o.n + ' ' + AUTH_PORTS[o.port] + ' sessions to ' + o.dst + ' in ' + fmtDur(dur) + ' (' + (o.n / dur * 60).toFixed(0) + '/min)' + (o.banner ? ', client "' + o.banner + '"' : '') + '.', details: [['Service', o.port + '/' + AUTH_PORTS[o.port]], ['Connections', o.n], ['Rate', (o.n / dur * 60).toFixed(1) + ' per minute'], ['Client banner', o.banner || '—']], ev: o.ev });
  }
  // FTP failed logins
  const ftpFail = new Map();
  for (const r of pk) { const s = r.s; if (s.proto === 'FTP' && s.txt && /^530 /m.test(s.txt)) { const k = s.dst + '|' + s.src; let o = ftpFail.get(k); if (!o) { o = { src: s.dst, dst: s.src, ev: [] }; ftpFail.set(k, o); } o.ev.push(r.i); } }
  for (const o of ftpFail.values()) if (o.ev.length >= 5 && !bf.has(o.src + '|' + o.dst + '|21')) add({ type: 'bruteforce', title: 'FTP login failures', sev: 'high', stage: 'cred', tech: 'T1110', techName: 'Brute Force', src: o.src, dst: o.dst, count: o.ev.length, summary: o.ev.length + ' failed FTP logins from ' + o.src + '.', details: [['Failures', o.ev.length]], ev: o.ev });

  // ---------- 4. Web attacks ----------
  const web = new Map(), tools = new Map(), notFound = new Map(), httpLogin = new Map();
  for (const r of pk) {
    const s = r.s, h = s.http; if (!h) continue;
    if (h.resp) {
      if (h.status === 404) { const k = s.dst + '|' + s.src; let o = notFound.get(k); if (!o) { o = { src: s.dst, dst: s.src, ev: [] }; notFound.set(k, o); } o.ev.push(r.i); }
      continue;
    }
    const uri = safeDecode(h.uri || ''), body = safeDecode(h.body || ''), hdr = h.raw || '';
    for (const rule of WEB_RULES) {
      const target = rule.hdr ? hdr : uri + ' ' + body;
      const m = target.match(rule.re);
      if (!m) continue;
      const k = s.src + '|' + s.dst + '|' + rule.k;
      let o = web.get(k); if (!o) { o = { rule, src: s.src, dst: s.dst, ev: [], samples: [], success: '', statuses: {} }; web.set(k, o); }
      o.ev.push(r.i); if (h.respIdx !== undefined) o.ev.push(h.respIdx);
      if (o.samples.length < 4) o.samples.push(h.method + ' ' + (h.uri.length > 140 ? h.uri.slice(0, 140) + '…' : h.uri) + (rule.hdr ? '  [header: ' + (hdr.split('\r\n').find(l => rule.re.test(l)) || '').slice(0, 100) + ']' : ''));
      if (h.status) o.statuses[h.status] = (o.statuses[h.status] || 0) + 1;
      if (h.respIdx !== undefined) {
        const rt = payloadText(cap, h.respIdx, 4096);
        if (rule.k === 'lfi' && /root:.*:0:0:/.test(rt)) o.success = '/etc/passwd contents returned in the response';
        if (rule.k === 'sqli' && /(SQL syntax|mysql_fetch|ORA-\d{5}|SQLSTATE|sqlite3?\.|PostgreSQL.*ERROR|Unclosed quotation)/i.test(rt)) o.success = o.success || 'Database error message leaked (injectable parameter)';
        if (rule.k === 'cmdi' && h.status === 200) o.success = o.success || 'Server answered 200 OK to the injected command';
        if (rule.k === 'xss' && /<script/i.test(rt)) o.success = o.success || 'Payload reflected unencoded in the response';
      }
    }
    const ua = h.ua || '';
    const tm = ua.match(TOOL_UA);
    if (tm) { const k = s.src + '|' + tm[1].toLowerCase(); let o = tools.get(k); if (!o) { o = { src: s.src, dst: s.dst, tool: tm[1], ua, ev: [], dsts: new Set() }; tools.set(k, o); } o.ev.push(r.i); o.dsts.add(s.dst); }
    if (h.method === 'POST' && /(login|signin|sign-in|auth|wp-login|session|logon)/i.test(h.uri)) { const k = s.src + '|' + s.dst + '|' + h.uri.split('?')[0]; let o = httpLogin.get(k); if (!o) { o = { src: s.src, dst: s.dst, uri: h.uri.split('?')[0], ev: [] }; httpLogin.set(k, o); } o.ev.push(r.i); }
  }
  for (const o of tools.values()) add({ type: 'tool', title: 'Attack tool fingerprint: ' + o.tool, sev: 'medium', stage: 'recon', tech: 'T1595.002', techName: 'Active Scanning: Vulnerability Scanning', src: o.src, dst: [...o.dsts].join(', '), count: o.ev.length, summary: o.src + ' sent ' + o.ev.length + ' HTTP requests with the User-Agent of ' + o.tool + '.', details: [['User-Agent', o.ua], ['Requests', o.ev.length]], ev: o.ev });
  for (const o of notFound.values()) {
    if (o.ev.length < 20) continue;
    add({ type: 'dirbrute', title: 'Web content discovery (forced browsing)', sev: 'medium', stage: 'recon', tech: 'T1595.003', techName: 'Active Scanning: Wordlist Scanning', src: o.src, dst: o.dst, count: o.ev.length, summary: o.src + ' requested ' + o.ev.length + ' paths on ' + o.dst + ' that returned 404 Not Found.', details: [['404 responses', o.ev.length]], ev: o.ev.map(i => pk[i].s.http.reqIdx ?? i).concat(o.ev).sort((a, b) => a - b) });
  }
  for (const o of web.values()) {
    const st = Object.entries(o.statuses).map(([k, v]) => k + '×' + v).join(', ');
    add({ type: 'web-' + o.rule.k, title: o.rule.name + (o.success ? ' (likely successful)' : ' attempts'), sev: o.success && o.rule.sev === 'high' ? 'critical' : o.rule.sev, stage: 'access', tech: 'T1190', techName: 'Exploit Public-Facing Application', src: o.src, dst: o.dst, count: o.ev.filter(i => !pk[i].s.http.resp).length,
      summary: o.src + ' sent ' + o.ev.filter(i => !pk[i].s.http.resp).length + ' ' + o.rule.name.toLowerCase() + ' payload(s) to ' + o.dst + '.' + (o.success ? ' Evidence of success: ' + o.success + '.' : ''),
      details: [['Sample requests', o.samples.join('\n')], ['Response codes', st || '—'], ['Outcome', o.success || 'No clear sign of success']], ev: o.ev.sort((a, b) => a - b) });
  }
  for (const o of httpLogin.values()) if (o.ev.length >= 10) add({ type: 'bruteforce', title: 'HTTP login brute force', sev: 'high', stage: 'cred', tech: 'T1110', techName: 'Brute Force', src: o.src, dst: o.dst, count: o.ev.length, summary: o.src + ' sent ' + o.ev.length + ' POSTs to ' + o.uri + ' on ' + o.dst + '.', details: [['Endpoint', o.uri], ['Attempts', o.ev.length]], ev: o.ev });

  // ---------- 5. Tool / payload downloads ----------
  for (const r of pk) {
    const h = r.s.http; if (!h || !h.resp) continue;
    const ct = (h.headers['content-type'] || '').toLowerCase();
    const req = h.reqIdx !== undefined ? pk[h.reqIdx].s.http : null;
    const uri = req ? req.uri : '';
    const path = safeDecode(uri.split('?')[0]);
    const body = payloadText(cap, r.i, 600);
    const scripty = /(x-sh|x-shellscript|x-executable|x-msdownload|x-elf|x-dosexec|x-powershell)/.test(ct) || /\.(sh|ps1|exe|elf|bin|dll|bat|vbs|hta|py)$/i.test(path) || /\r\n\r\n(#!\/bin\/|MZ|\x7fELF)/.test(body);
    if (!scripty || h.status !== 200) continue;
    const dl = r.s.dst, from = r.s.src;
    const shell = /\/dev\/tcp\/|bash -i|nc -e|powershell.*-enc|IEX\s*\(/i.test(body);
    const disguised = /^image\/|^text\/plain/.test(ct) && /\r\n\r\n(MZ|\x7fELF)/.test(body);
    add({ type: 'download', title: disguised ? 'Executable disguised as ' + ct : 'Suspicious file download' + (shell ? ' (reverse-shell stager)' : ''), sev: disguised || shell ? 'critical' : 'high', stage: 'c2', tech: disguised ? 'T1036.008' : 'T1105', techName: disguised ? 'Masquerading: Masquerade File Type' : 'Ingress Tool Transfer', src: dl, dst: from, count: 1, summary: dl + ' downloaded ' + (uri || 'a file') + ' from ' + from + ' (' + (ct || 'unknown type') + ').' + (shell ? ' The script opens a reverse shell.' : ''), details: [['URL', 'http://' + (req ? req.host : from) + uri], ['Content-Type', ct || '—'], ['User-Agent', req ? req.ua : '—'], ['Preview', body.split('\r\n\r\n').slice(1).join('').slice(0, 200)]], ev: [h.reqIdx, r.i].filter(x => x !== undefined) });
  }

  // ---------- 6. Reverse shells / suspicious ports ----------
  const SHELL_RE = /(uid=\d+\([\w-]+\)|\/bin\/(ba)?sh|bash -i|Microsoft Windows \[Version|PS [A-Z]:\\>|root@[\w.-]+:|www-data@|\bwhoami\b|cmd\.exe|\/dev\/tcp\/|cat \/etc\/(passwd|shadow))/;
  const shellStreams = new Set();
  for (const st of streams) {
    if (st.l4 !== 'TCP' || st.payload === 0 || st.payload > 2e6) continue;
    let txt = '', hit = null, cmds = [];
    for (const i of st.pk) {
      const s = pk[i].s; if (!s.pll || s.proto === 'HTTP' || s.proto === 'TLS' || s.proto === 'SSH') continue;
      const t = payloadText(cap, i, 2048);
      if (!isText(cap.u8, cap.pk[i].off + s.plo, cap.pk[i].off + s.plo + s.pll, 64)) continue;
      txt += t;
      if (!s.dirA) t.split('\n').map(x => x.trim()).filter(x => x && x.length < 120).forEach(x => cmds.push(x));
      if (!hit) { const m = t.match(SHELL_RE); if (m) hit = m[0]; }
    }
    if (!hit) continue;
    shellStreams.add(st.id);
    const reverse = isPrivate(st.a) && !isPrivate(st.b);
    add({ type: 'shell', title: (reverse ? 'Reverse shell' : 'Interactive shell') + ' over TCP/' + st.bp, sev: 'critical', stage: 'exec', tech: 'T1059.004', techName: 'Command and Scripting Interpreter: Unix Shell', src: st.a, dst: st.b, dport: st.bp, stream: st.id, count: cmds.length, summary: st.a + ' connected out to ' + st.b + ':' + st.bp + ' and served a command shell. Commands issued by the remote side: ' + cmds.slice(0, 6).map(c => '"' + c + '"').join(', ') + (cmds.length > 6 ? ', …' : '') + '.', details: [['Indicator', hit], ['Commands', cmds.slice(0, 20).join('\n') || '—'], ['Duration', fmtDur(st.t1 - st.t0)]], ev: st.pk.slice() });
  }
  for (const st of streams) {
    if (st.l4 !== 'TCP' || shellStreams.has(st.id)) continue;
    const bad = BAD_PORTS[st.bp];
    if (!bad || st.payload === 0) continue;
    add({ type: 'badport', title: 'Session on suspicious port ' + st.bp, sev: 'medium', stage: 'c2', tech: 'T1571', techName: 'Non-Standard Port', src: st.a, dst: st.b, dport: st.bp, stream: st.id, count: st.pk.length, summary: st.a + ' exchanged ' + fmtBytes(st.bytes) + ' with ' + st.b + ' on port ' + st.bp + ' (' + bad + ').', details: [['Port', st.bp + ' — ' + bad], ['Bytes', fmtBytes(st.bytes)]], ev: st.pk.slice() });
  }

  // ---------- 7. Beaconing ----------
  const conns = new Map();
  for (const st of streams) {
    if (st.l4 !== 'TCP' || !st.syn) continue;
    const k = st.a + '|' + st.b + '|' + st.bp;
    let o = conns.get(k); if (!o) { o = { src: st.a, dst: st.b, port: st.bp, t: [], ev: [], bytes: 0 }; conns.set(k, o); }
    o.t.push(st.t0); o.ev.push(...st.pk); o.bytes += st.bytes;
  }
  for (const o of conns.values()) {
    if (o.t.length < 6) continue;
    o.t.sort((a, b) => a - b);
    const iv = []; for (let i = 1; i < o.t.length; i++) iv.push(o.t[i] - o.t[i - 1]);
    const mean = iv.reduce((a, b) => a + b, 0) / iv.length;
    if (mean < 2) continue;
    const sd = Math.sqrt(iv.reduce((a, b) => a + (b - mean) ** 2, 0) / iv.length);
    const cv = sd / mean;
    if (cv > 0.2) continue;
    add({ type: 'beacon', title: 'Periodic beaconing every ~' + fmtDur(mean), sev: isPrivate(o.dst) ? 'medium' : 'high', stage: 'c2', tech: o.port === 80 || o.port === 8080 || o.port === 443 ? 'T1071.001' : 'T1071', techName: 'Application Layer Protocol' + (o.port === 80 || o.port === 8080 || o.port === 443 ? ': Web Protocols' : ''), src: o.src, dst: o.dst, dport: o.port, count: o.t.length, t0: o.t[0], t1: o.t[o.t.length - 1], summary: o.src + ' connected to ' + o.dst + ':' + o.port + ' ' + o.t.length + ' times at a regular ' + fmtDur(mean) + ' interval (jitter ' + (cv * 100).toFixed(1) + '%), a typical C2 check-in pattern.', details: [['Connections', o.t.length], ['Mean interval', fmtDur(mean)], ['Jitter (CV)', (cv * 100).toFixed(1) + '%'], ['Total bytes', fmtBytes(o.bytes)]], ev: o.ev.sort((a, b) => a - b) });
  }

  // ---------- 8. DNS tunneling & DGA ----------
  const dq = new Map(), nx = new Map();
  for (const r of pk) {
    const d = r.s.dns; if (!d || !d.qs[0]) continue;
    const nm = d.qs[0].name.toLowerCase();
    if (r.s.proto !== 'DNS') continue;
    if (!d.qr) {
      const bd = baseDomain(nm); const sub = nm.slice(0, Math.max(0, nm.length - bd.length - 1));
      const k = r.s.src + '|' + bd;
      let o = dq.get(k); if (!o) { o = { src: r.s.src, dst: r.s.dst, bd, subs: new Set(), len: 0, ent: 0, txt: 0, ev: [], longest: '' }; dq.set(k, o); }
      if (!o.subs.has(sub)) { o.subs.add(sub); o.len += sub.replace(/\./g, '').length; o.ent += entropy(sub.replace(/\./g, '')); }
      if (d.qs[0].type === 'TXT' || d.qs[0].type === 'NULL') o.txt++;
      if (nm.length > o.longest.length) o.longest = nm;
      o.ev.push(r.i);
    } else if (d.rcode === 3) {
      let o = nx.get(r.s.dst); if (!o) { o = { src: r.s.dst, names: new Set(), ev: [] }; nx.set(r.s.dst, o); }
      o.names.add(nm); o.ev.push(r.i);
    }
  }
  for (const o of dq.values()) {
    const u = o.subs.size; if (u < 15) continue;
    const avgLen = o.len / u, avgEnt = o.ent / u;
    if (!(avgLen >= 25 || (avgEnt >= 3.6 && avgLen >= 12) || (o.txt >= 15 && avgLen >= 12))) continue;
    // include responses
    const ids = new Set(o.ev.map(i => pk[i].s.dns.id));
    for (const r of pk) { const d = r.s.dns; if (d && d.qr && r.s.dst === o.src && ids.has(d.id) && baseDomain(d.qs[0]?.name || '') === o.bd) o.ev.push(r.i); }
    o.ev.sort((a, b) => a - b);
    const est = Math.round(o.len * 5 / 8);
    add({ type: 'dnstunnel', title: 'DNS tunneling to ' + o.bd, sev: 'high', stage: 'exfil', tech: 'T1048.003', techName: 'Exfiltration Over Unencrypted Non-C2 Protocol (DNS)', src: o.src, dst: o.bd, viaDns: o.dst, count: u, summary: o.src + ' sent ' + u + ' unique, high-entropy subdomains of ' + o.bd + ' (avg ' + avgLen.toFixed(0) + ' chars, entropy ' + avgEnt.toFixed(2) + ' bits/char' + (o.txt ? ', ' + o.txt + ' TXT queries' : '') + '), encoding roughly ' + fmtBytes(est) + ' of data.', details: [['Base domain', o.bd], ['Unique subdomains', u], ['Avg label length', avgLen.toFixed(1)], ['Avg entropy', avgEnt.toFixed(2) + ' bits/char'], ['TXT queries', o.txt], ['Est. data encoded', fmtBytes(est)], ['Longest query', o.longest]], ev: o.ev });
  }
  for (const o of nx.values()) if (o.names.size >= 15) add({ type: 'dga', title: 'Burst of NXDOMAIN responses (possible DGA)', sev: 'medium', stage: 'c2', tech: 'T1568.002', techName: 'Dynamic Resolution: Domain Generation Algorithms', src: o.src, dst: 'DNS', count: o.names.size, summary: o.src + ' looked up ' + o.names.size + ' names that do not exist, e.g. ' + [...o.names].slice(0, 3).join(', ') + '.', details: [['Failed names', o.names.size], ['Examples', [...o.names].slice(0, 8).join('\n')]], ev: o.ev });

  // ---------- 9. ARP spoofing ----------
  for (const [ip, m] of arpClaims) {
    if (m.size < 2) continue;
    const arr = [...m.entries()].sort((a, b) => a[1].first - b[1].first);
    const legit = arr[0][0];
    for (const [mc, c] of arr.slice(1)) {
      const owner = cap.macIp?.get(mc);
      const who = owner && owner.size ? [...owner][0] : mc;
      add({ type: 'arpspoof', title: 'ARP spoofing of ' + ip, sev: 'high', stage: 'cred', tech: 'T1557.002', techName: 'Adversary-in-the-Middle: ARP Cache Poisoning', src: who, srcMac: mc, dst: ip, count: c.n, summary: 'MAC ' + mc + ' claimed to own ' + ip + ' (' + c.n + ' ARP packets, ' + c.unsol + ' unsolicited replies), which belongs to ' + legit + '. Traffic for ' + ip + ' can be intercepted.', details: [['Spoofed IP', ip], ['Legitimate MAC', legit], ['Attacker MAC', mc], ['ARP packets', c.n], ['Unsolicited replies', c.unsol]], ev: c.ev });
    }
  }

  // ---------- 10. Rogue DHCP / starvation ----------
  if (dhcpServers.size >= 2) {
    const arr = [...dhcpServers.entries()];
    add({ type: 'rogue-dhcp', title: 'Multiple DHCP servers (possible rogue DHCP)', sev: 'high', stage: 'cred', tech: 'T1557.003', techName: 'Adversary-in-the-Middle: DHCP Spoofing', src: arr[1][0], dst: 'clients', count: arr.length, summary: arr.length + ' different DHCP servers answered clients: ' + arr.map(a => a[0]).join(', ') + '.', details: [['Servers', arr.map(a => a[0] + ' (' + (a[1].mac || '?') + ')').join('\n')]], ev: arr.flatMap(a => a[1].ev) });
  }
  const dd = dhcpDisc.get('all');
  if (dd && dd.macs.size >= 30) add({ type: 'dhcp-starve', title: 'DHCP starvation', sev: 'medium', stage: 'impact', tech: 'T1499', techName: 'Endpoint Denial of Service', src: 'multiple MACs', dst: 'DHCP', count: dd.macs.size, summary: dd.macs.size + ' different client MACs sent DHCP Discover messages.', details: [['Distinct MACs', dd.macs.size]], ev: dd.ev });

  // ---------- 11. Exfiltration (large outbound) ----------
  const out = new Map();
  for (const st of streams) {
    const inside = isPrivate(st.a), outside = !isPrivate(st.b);
    if (!inside || !outside) continue;
    const k = st.a + '|' + st.b; let o = out.get(k); if (!o) { o = { src: st.a, dst: st.b, up: 0, down: 0, ev: [], ports: new Set(), sni: '' }; out.set(k, o); }
    o.up += st.ab; o.down += st.ba; o.ev.push(...st.pk); o.ports.add(st.bp);
    if (!o.sni) for (const i of st.pk.slice(0, 6)) if (pk[i].s.sni) { o.sni = pk[i].s.sni; break; }
  }
  for (const o of out.values()) {
    if (o.up < 1e6 || o.up < o.down * 4) continue;
    o.ev.sort((a, b) => a - b);
    const big = streams.filter(st => st.a === o.src && st.b === o.dst).sort((x, y) => y.ab - x.ab)[0];
    add({ t0: big.t0, t1: big.t1, type: 'exfil', title: 'Large outbound transfer (' + fmtBytes(o.up) + ')', sev: 'high', stage: 'exfil', tech: 'T1041', techName: 'Exfiltration Over C2 Channel', src: o.src, dst: o.dst, count: o.ev.length, summary: o.src + ' uploaded ' + fmtBytes(o.up) + ' to external host ' + o.dst + (o.sni ? ' (' + o.sni + ')' : '') + ' while receiving only ' + fmtBytes(o.down) + ' (ratio ' + (o.up / Math.max(o.down, 1)).toFixed(0) + ':1).', details: [['Uploaded', fmtBytes(o.up)], ['Downloaded', fmtBytes(o.down)], ['Ports', [...o.ports].join(', ')], ['TLS server name', o.sni || '—']], ev: o.ev });
  }

  // ---------- 12. Floods ----------
  const burst = (ev, minWin) => {
    const ts = ev.map(i => pk[i].t); let lo = 0, peak = 0, first = -1, last = -1;
    for (let j = 0; j < ts.length; j++) { while (ts[j] - ts[lo] > 1) lo++; const c = j - lo + 1; if (c > peak) peak = c; if (c >= minWin) { if (first < 0) first = lo; last = j; } }
    if (first < 0) return null;
    return { peak, ev: ev.slice(first, last + 1), span: Math.max(ts[last] - ts[first], 0.001) };
  };
  for (const q of synToPort.values()) {
    if (q.n < 300) continue;
    const b = burst(q.ev, 100); if (!b || b.ev.length < 300) continue;
    const srcs = new Set(b.ev.map(i => pk[i].s.src));
    const spoofed = srcs.size > 50;
    add({ type: 'synflood', title: 'SYN flood on ' + q.dst + ':' + q.port, sev: 'critical', stage: 'impact', tech: 'T1498.001', techName: 'Network Denial of Service: Direct Network Flood', src: spoofed ? srcs.size + ' spoofed sources' : [...srcs].join(', '), spoofed, dst: q.dst, dport: q.port, count: b.ev.length, summary: b.ev.length + ' SYN packets hit ' + q.dst + ':' + q.port + ' in ' + fmtDur(b.span) + ' (peak ' + b.peak + ' pkt/s) from ' + srcs.size + ' source address' + (srcs.size > 1 ? 'es' : '') + (spoofed ? ' (randomised — likely spoofed)' : '') + '.', details: [['SYN packets', b.ev.length], ['Peak rate', b.peak + ' pkt/s'], ['Distinct sources', srcs.size], ['Duration', fmtDur(b.span)]], ev: b.ev });
  }
  for (const [src, o] of echoBy) {
    const byDst = new Map(); o.ev.forEach(i => { const d = pk[i].s.dst; byDst.set(d, (byDst.get(d) || []).concat(i)); });
    for (const [d, ev] of byDst) { if (ev.length < 300) continue; const b = burst(ev, 100); if (!b || b.ev.length < 300) continue; add({ type: 'icmpflood', title: 'ICMP flood', sev: 'high', stage: 'impact', tech: 'T1498.001', techName: 'Network Denial of Service: Direct Network Flood', src, dst: d, count: b.ev.length, summary: src + ' sent ' + b.ev.length + ' echo requests to ' + d + ' (peak ' + b.peak + '/s).', details: [['Packets', b.ev.length], ['Peak rate', b.peak + '/s']], ev: b.ev }); }
  }
  for (const b of icmpBig.values()) if (b.ev.length >= 10) add({ type: 'icmptunnel', title: 'Possible ICMP tunnel', sev: 'medium', stage: 'c2', tech: 'T1095', techName: 'Non-Application Layer Protocol', src: b.src, dst: b.dst, count: b.ev.length, summary: b.src + ' sent ' + b.ev.length + ' oversized echo requests (' + fmtBytes(b.bytes) + ' of payload) to ' + b.dst + '.', details: [['Packets', b.ev.length], ['Payload', fmtBytes(b.bytes)]], ev: b.ev });
  if (heart.length) add({ type: 'heartbleed', title: 'TLS Heartbleed exploitation', sev: 'critical', stage: 'cred', tech: 'T1190', techName: 'Exploit Public-Facing Application', src: pk[heart[0]].s.src, dst: pk[heart[0]].s.dst, count: heart.length, summary: 'TLS heartbeat requests claim a payload larger than the record (CVE-2014-0160).', details: [['Packets', heart.length]], ev: heart });

  // ---------- 13. Cleartext credentials ----------
  const creds = new Map();
  const addCred = (r, proto, user, pw, extra) => {
    const s = r.s; const k = s.src + '|' + s.dst + '|' + proto + '|' + user;
    let o = creds.get(k); if (!o) { o = { src: s.src, dst: s.dst, proto, user: user || '', pw: '', ev: [] }; creds.set(k, o); }
    if (pw) o.pw = pw; o.ev.push(r.i); if (extra) o.extra = extra;
  };
  const pending = new Map();
  for (const r of pk) {
    const s = r.s;
    if ((s.proto === 'FTP' || s.proto === 'POP3' || s.proto === 'IMAP' || s.proto === 'SMTP') && s.txt && s.dirA) {
      const k = s.st; const t = s.txt;
      let m;
      if ((m = t.match(/^USER\s+(\S+)/im))) pending.set(k, m[1]);
      if ((m = t.match(/^PASS\s+(\S+)/im))) addCred(r, s.proto, pending.get(k) || '?', m[1]);
      if ((m = t.match(/^\S+\s+LOGIN\s+"?([^"\s]+)"?\s+"?([^"\s]+)"?/im))) addCred(r, 'IMAP', m[1], m[2]);
      if ((m = t.match(/^AUTH PLAIN\s+(\S+)/im))) { try { const d = atob(m[1]).split('\0'); addCred(r, 'SMTP', d[1], d[2]); } catch (e) {} }
    }
    if (s.http && !s.http.resp) {
      const au = s.http.headers.authorization || '';
      if (/^basic\s+/i.test(au)) { try { const d = atob(au.split(/\s+/)[1]); const c = d.indexOf(':'); addCred(r, 'HTTP Basic', d.slice(0, c), d.slice(c + 1), s.http.uri); } catch (e) {} }
      if (s.http.method === 'POST' && s.http.body) {
        const b = safeDecode(s.http.body);
        const pm = b.match(/(?:^|&)(pass|password|passwd|pwd)=([^&]*)/i), um = b.match(/(?:^|&)(user|username|login|email|uname)=([^&]*)/i);
        if (pm) addCred(r, 'HTTP form', um ? um[2] : '?', pm[2], s.http.uri);
      }
    }
    if (s.proto === 'Telnet' && s.pll) { const k = s.src + '|' + s.dst + '|Telnet|'; if (!creds.has(k)) creds.set(k, { src: s.dirA ? s.src : s.dst, dst: s.dirA ? s.dst : s.src, proto: 'Telnet', user: '(interactive)', pw: '', ev: [] }); creds.get(k).ev.push(r.i); }
  }
  // ---------- 14. Web shells ----------
  const SHELL_EXT = /\.(aspx?|ashx|asmx|php\d?|phtml|jspx?|cfm|cgi|pl)$/i;
  const shells = new Map();
  const shellOf = (src, dst, path) => { const k = src + '|' + dst + '|' + path.toLowerCase(); let o = shells.get(k); if (!o) { o = { src, dst, path, upload: null, cmds: [], ev: [], ok: 0 }; shells.set(k, o); } return o; };
  for (const r of pk) {
    const h = r.s.http; if (!h || h.resp) continue;
    const body = h.body || '';
    const up = h.method === 'POST' && body.match(/filename="([^"]+)"/i);
    if (up && SHELL_EXT.test(up[1])) { const o = shellOf(r.s.src, r.s.dst, up[1]); o.upload = { i: r.i, uri: h.uri, name: up[1], code: /<%|<\?php|Runtime\.getRuntime|Request\[|eval\(|system\(|exec\(/i.test(body) }; o.ev.push(r.i); if (h.respIdx !== undefined) o.ev.push(h.respIdx); }
    const path = safeDecode((h.uri || '').split('?')[0]), q = safeDecode((h.uri || '').split('?')[1] || '');
    const cm = q.match(/(?:^|&)(cmd|exec|command|c|run|q)=([^&]*)/i);
    if (cm && SHELL_EXT.test(path)) { const o = shellOf(r.s.src, r.s.dst, path.split('/').pop()); o.path2 = path; o.cmds.push(cm[2]); o.ev.push(r.i); if (h.respIdx !== undefined) { o.ev.push(h.respIdx); if (h.status === 200) o.ok++; } }
  }
  for (const o of shells.values()) {
    if (!(o.upload && o.cmds.length) && !(o.cmds.length >= 3 && o.ok)) continue;
    const uniq = [...new Set(o.cmds)];
    add({ type: 'webshell', title: 'Web shell ' + (o.upload ? 'uploaded and used' : 'in use') + ': ' + (o.path2 || o.path), sev: 'critical', stage: 'exec', tech: 'T1505.003', techName: 'Server Software Component: Web Shell', src: o.src, dst: o.dst, count: o.cmds.length,
      summary: o.src + (o.upload ? ' uploaded ' + o.upload.name + ' through ' + o.upload.uri.split('?')[0] + ' and then' : '') + ' ran ' + o.cmds.length + ' command' + (o.cmds.length > 1 ? 's' : '') + ' through it on ' + o.dst + ': ' + uniq.slice(0, 5).map(c => '"' + c + '"').join(', ') + (uniq.length > 5 ? ', …' : '') + '.',
      details: [['Shell', o.path2 || o.path], ['Uploaded through', o.upload ? o.upload.uri.split('?')[0] + (o.upload.code ? ' (server-side code in the upload)' : '') : '—'], ['Commands', uniq.slice(0, 15).join('\n')], ['Requests', o.cmds.length + ' (' + o.ok + ' answered 200)']], ev: o.ev.sort((a, b) => a - b) });
  }

  // ---------- 15. Cloud credentials from the instance metadata service ----------
  const IMDS_HOSTS = new Set(['169.254.169.254', 'fd00:ec2::254', '169.254.170.2']);
  const imds = new Map();
  for (const r of pk) {
    const h = r.s.http; if (!h || h.resp || !(IMDS_HOSTS.has(r.s.dst) || /metadata\.google\.internal/i.test(h.host || ''))) continue;
    const u = h.uri || '';
    const cred = /(identity\/oauth2\/token|iam\/security-credentials|service-accounts\/[^/]+\/token|\/latest\/api\/token|credentials)/i.test(u);
    let o = imds.get(r.s.src); if (!o) { o = { src: r.s.src, dst: r.s.dst, paths: [], cred: 0, token: false, res: new Set(), ev: [] }; imds.set(r.s.src, o); }
    o.paths.push(h.method + ' ' + (u.length > 120 ? u.slice(0, 120) + '…' : u)); o.ev.push(r.i); if (cred) o.cred++;
    const rm = u.match(/resource=([^&]+)/); if (rm) o.res.add(safeDecode(rm[1]));
    if (h.respIdx !== undefined) { o.ev.push(h.respIdx); if (/"(access_token|AccessKeyId|Token)"/.test(payloadText(cap, h.respIdx, 4096))) o.token = true; }
  }
  for (const o of imds.values()) if (o.cred) add({ type: 'imds', title: 'Cloud credentials taken from instance metadata', sev: o.token ? 'critical' : 'high', stage: 'cred', tech: 'T1552.005', techName: 'Unsecured Credentials: Cloud Instance Metadata API', src: o.src, dst: o.dst, count: o.cred,
    summary: o.src + ' asked the cloud instance metadata service for ' + o.cred + ' credential token' + (o.cred > 1 ? 's' : '') + (o.res.size ? ' (for ' + [...o.res].join(', ') + ')' : '') + (o.token ? ' and received ' + (o.cred > 1 ? 'them' : 'it') : '') + '. Code running on a compromised server can use these to act as the server in the cloud.',
    details: [['Requests', o.paths.slice(0, 8).join('\n')], ['Resources', [...o.res].join('\n') || '—'], ['Token returned', o.token ? 'Yes' : 'Not seen']], ev: o.ev.sort((a, b) => a - b) });

  // ---------- 16. LDAP: cleartext binds and Active Directory reconnaissance ----------
  const ldapRecon = new Map();
  const berLen = (u, p) => { const b = u[p]; if (b < 128) return [b, p + 1]; const n = b & 127; let v = 0; for (let k = 0; k < n; k++) v = v * 256 + u[p + 1 + k]; return [v, p + 1 + n]; };
  const SENSITIVE = /(servicePrincipalName|adminCount|ms-Mcs-AdmPwd|msLAPS|trustPartner|memberOf|userAccountControl|unicodePwd|msDS-AllowedToDelegateTo|gMSA|msDS-ManagedPassword)/i;
  for (const r of pk) {
    const s = r.s; if (s.l4 !== 'TCP' || s.dp !== 389 || !s.pll) continue;
    const u = cap.u8, a0 = r.off + s.plo, e = a0 + s.pll;
    if (u[a0] !== 0x30) continue;
    let [, p] = berLen(u, a0 + 1); if (u[p] !== 0x02) continue; p = p + 2 + u[p + 1];
    const op = u[p];
    if (op === 0x60) { // BindRequest: version, name, simple password [0]
      let [, q] = berLen(u, p + 1); q += 3; if (u[q] !== 0x04) continue;
      let nl; [nl, q] = berLen(u, q + 1); const name = latin(u, q, q + nl, 256); q += nl;
      if (u[q] === 0x80) { let pl; [pl, q] = berLen(u, q + 1); if (pl > 0) addCred(r, 'LDAP', name, latin(u, q, q + pl, 128), 'simple bind'); }
    }
    if (op === 0x63) {
      let o = ldapRecon.get(s.src + '|' + s.dst); if (!o) { o = { src: s.src, dst: s.dst, n: 0, attrs: new Set(), base: '', ev: [] }; ldapRecon.set(s.src + '|' + s.dst, o); }
      o.n++; o.ev.push(r.i);
      const txt = latin(u, a0, e, 4096);
      (txt.match(/[A-Za-z][\w-]{3,40}/g) || []).forEach(w => { if (SENSITIVE.test(w)) o.attrs.add(w); });
      const bm = txt.match(/((?:CN|OU|DC)=[\w-]+(?:,(?:CN|OU|DC)=[\w-]+)*)/i); if (bm && !o.base) o.base = bm[1];
    }
  }
  for (const o of ldapRecon.values()) if (o.n >= 3 && o.attrs.size >= 2) add({ type: 'ldaprecon', title: 'Active Directory reconnaissance over LDAP', sev: 'high', stage: 'disc', tech: 'T1087.002', techName: 'Account Discovery: Domain Account', src: o.src, dst: o.dst, count: o.n,
    summary: o.src + ' ran ' + o.n + ' LDAP searches against ' + o.dst + (o.base ? ' (' + o.base + ')' : '') + ' asking for ' + [...o.attrs].join(', ') + ': the attributes used to find service accounts, admins and local admin passwords.',
    details: [['Searches', o.n], ['Sensitive attributes', [...o.attrs].join('\n')], ['Base', o.base || '—']], ev: o.ev });
  cap.credList = [...creds.values()];
  for (const o of creds.values()) {
    add({ type: 'cleartext', title: 'Cleartext ' + o.proto + ' credentials', sev: o.proto === 'Telnet' ? 'medium' : 'medium', stage: 'cred', tech: 'T1040', techName: 'Network Sniffing (exposed credentials)', src: o.src, dst: o.dst, count: o.ev.length, secret: o.pw, summary: o.src + ' sent ' + o.proto + ' credentials' + (o.user ? ' for user "' + o.user + '"' : '') + ' to ' + o.dst + ' without encryption. Anyone on the path can read them.', details: [['Protocol', o.proto], ['Username', o.user || '—'], ['Password', o.pw ? mask(o.pw) : '—'], ['Resource', o.extra || '—']], ev: o.ev });
  }



  // ---------- 17. Kerberoasting ----------
  const kerb = new Map();
  for (const r of pk) {
    const s = r.s; if (s.dp !== 88 || !s.pll) continue;
    const u = cap.u8, a0 = r.off + s.plo + (s.l4 === 'TCP' ? 4 : 0), e = r.off + s.plo + s.pll;
    if (u[a0] !== 0x6c) continue; // TGS-REQ
    const strs = []; for (let q = a0; q < e - 2; q++) if (u[q] === 0x1b && u[q + 1] > 1 && u[q + 1] < 80 && q + 2 + u[q + 1] <= e) { const v = latin(u, q + 2, q + 2 + u[q + 1], 80); if (/^[\x21-\x7e]+$/.test(v)) { strs.push(v); q += 1 + u[q + 1]; } }
    const parts = strs.filter(x => !/^[A-Z0-9-]+(\.[A-Z0-9-]+)+$/.test(x));
    if (parts.length < 2) continue;
    const spn = parts.join('/');
    if (/^krbtgt\//i.test(spn)) continue;
    const rc4 = /\x02\x01\x17/.test(latin(u, a0, e, 2048));
    let o = kerb.get(s.src); if (!o) { o = { src: s.src, dst: s.dst, spns: new Set(), rc4: 0, ev: [] }; kerb.set(s.src, o); }
    o.spns.add(spn); if (rc4) o.rc4++; o.ev.push(r.i);
  }
  for (const o of kerb.values()) if (o.spns.size >= 3) add({ type: 'kerberoast', title: 'Kerberoasting (' + o.spns.size + ' service tickets)', sev: 'high', stage: 'cred', tech: 'T1558.003', techName: 'Steal or Forge Kerberos Tickets: Kerberoasting', src: o.src, dst: o.dst, count: o.spns.size,
    summary: o.src + ' requested Kerberos service tickets for ' + o.spns.size + ' service accounts' + (o.rc4 ? ', asking for weak RC4 encryption' : '') + '. The tickets can be cracked offline to recover the accounts\' passwords.',
    details: [['Service principal names', [...o.spns].join('\n')], ['RC4 requested', o.rc4 ? o.rc4 + ' of ' + o.ev.length + ' requests' : 'No']], ev: o.ev });

  // ---------- 18. Is the attacker an AI agent? ----------
  aiAssess(cap, D, add);
  D.sort((a, b) => a.t0 - b.t0 || SEV_RANK[b.sev] - SEV_RANK[a.sev]);
  D.forEach((d, i) => { d.id = i; d.evSet = null; });
  return D;
}


/* ===================== AI-driven attack assessment ===================== */
// AI agent frameworks (ARTEX and its "siblings") leave a recognisable shape on the wire.
// No single sign proves an AI is driving: scripts are fast too. So each sign carries a weight
// and its own packets, "strong" signs are ones ordinary scanners rarely show, and the verdict
// needs at least one strong sign. The evidence is listed sign by sign so an analyst can check it.
const AI_TYPES = new Set(['ai', 'aiuse', 'aitool', 'aiframework', 'llmcalls', 'oast', 'cleartext']);
const LLM_API = /(^|\.)(api\.openai\.com|api\.anthropic\.com|generativelanguage\.googleapis\.com|aiplatform\.googleapis\.com|api\.x\.ai|api\.mistral\.ai|api\.groq\.com|openrouter\.ai|api\.deepseek\.com|api\.together\.xyz|api\.cohere\.(ai|com)|api\.perplexity\.ai|api\.fireworks\.ai|openai\.azure\.com|bedrock-runtime\.[\w-]+\.amazonaws\.com|api\.moonshot\.cn|dashscope\.aliyuncs\.com|ollama\.com)$/i;
const AGENT_UA = /(python-httpx|python-requests|aiohttp|Go-http-client|node-fetch|axios|undici|okhttp|libwww-perl|httpie|langchain|llama[-_ ]?index|crewai|autogen|browser-use|openai|anthropic|HeadlessChrome|Playwright|puppeteer)/i;
const API_MAP = /(swagger(\.json|\/v\d+\/swagger\.json|-ui)?|openapi\.(json|ya?ml)|api-docs|\.well-known\/(openid-configuration|ai-plugin\.json|mcp|security\.txt)|graphql|robots\.txt|sitemap\.xml|llms\.txt)(\?|$)/i;
// Text an AI assistant leaves in code it writes: chat preambles, self-references, attributions,
// markdown fences, emoji status lines, numbered "Step" comments, fill-in placeholders.
const AI_TEXT = [
  ['Chat-style preamble', /\b(Sure|Certainly|Absolutely|Of course)[!,.]?\s+(here('s| is| are)|below is)\b|\bHere('s| is) (a|an|the|your) [\w -]{0,40}(script|code|payload|function|tool|program)\b/i, true],
  ['Mentions being an AI', /\bAs an AI\b|\bI('m| am) an AI\b|\blanguage model\b/i, true],
  ['Credits an AI', /\b(generated|written|created|assisted|produced) (by|with|using) (ChatGPT|GPT-?[\d.o]*|Claude|Copilot|Gemini|Grok|Codex|Cursor|(an? )?(AI|LLM)( assistan(t|ce))?)\b/i, true],
  ['Markdown code fence', /```[a-z]*\r?\n/i, false],
  ['Emoji status lines', /[✅❌⚠\u{1F680}\u{1F512}\u{1F50D}\u{1F4E6}\u{1F389}\u{1F525}]/u, false],
  ['Numbered "Step" comments', /^\s*(#|\/\/|--|REM|')\s*Step \d+\s*[:.)-]/im, false],
  ['Fill-in placeholders', /\b(YOUR_[A-Z_]{3,}|your[-_](server|domain|ip|api[-_]key)[-_]here|<your[-_ ][\w -]{3,30}>|replace (this|with your))\b/i, false],
];
// User-Agents that AI attack frameworks send themselves. From the frameworks' source code as published in the
// open detection packs (Theori aipt-detections, ThreatDefence agentic-attack-detections, ARTEX-NSM) and Theori's
// lab report on ARTEX and CyberStrikeAI (November 2026).
const AI_FRAMEWORK_UA = [
  [/\bartex[-/ ]|artex\)|\bARTEX-worker\/|ArtExVerify|\bscopeweaver\b/i, 'ARTEX'],
  [/^norma\/\d/i, 'ARTEX (its WebFetch client, norma)'],
  [/spa-api-recon/i, 'ARTEX (its api-recon skill)'],
  [/CyberStrikeAI|^cyberstrike\//i, 'CyberStrikeAI'],
  [/HexStrike|\(Compatible Exploit( Scanner)?\)/i, 'HexStrike-AI'],
  [/LuaN1aoAgent/i, 'LuaN1aoAgent'],
  [/^PentAGI\//i, 'PentAGI'],
  [/^agent-zero\//i, 'Agent Zero'],
  [/RedAmon/i, 'RedAmon'],
  [/xalgorix/i, 'Xalgorix'],
  [/pentestswarm-/i, 'Pentest Swarm AI'],
  [/PentestGPT/i, 'PentestGPT'],
];
// AI coding agents: normal on a developer's machine, telling only on a host that is part of an attack
const AI_ASSISTANT_UA = [[/claude-code|Claude-User/i, 'Claude Code'], [/QwenCode/i, 'Qwen Code'], [/codex[-_ ]cli|\bcodex\/\d/i, 'Codex CLI'], [/gemini-cli/i, 'Gemini CLI'], [/aider\/\d/i, 'Aider']];
// out-of-band callback services that scanners and AI agents use to confirm blind vulnerabilities
const OAST = /(^|\.)(dnslog\.cn|ceye\.io|oast\.(fun|live|site|online|me|pro)|oastify\.com|interact\.sh|burpcollaborator\.net|webhook\.site|requestbin\.(net|com)|pipedream\.net|canarytokens\.com)$/i;
function aiTextSigns(t) {
  try { t = new TextDecoder().decode(Uint8Array.from(t, c => c.charCodeAt(0) & 255)); } catch (e) {} // bytes → UTF-8, so emoji are seen
  const hits = [];
  const steps = (t.match(/^\s*(#|\/\/|--|REM|')\s*Step \d+\s*[:.)-]/gim) || []).length;
  for (const [name, re, strong] of AI_TEXT) { if (name.startsWith('Numbered') && steps < 3) continue; const m = t.match(re); if (m) { const line = t.slice(Math.max(0, t.lastIndexOf('\n', m.index) + 1), t.indexOf('\n', m.index) < 0 ? t.length : t.indexOf('\n', m.index)).trim(); hits.push({ name, strong, line: line.length > 110 ? line.slice(0, 110) + '…' : line }); } }
  return hits;
}
// the body of an HTTP message, across the packets that carry it
function httpBodyText(cap, i, max) {
  const r = cap.pk[i], s = r.s; if (s.st === undefined) return payloadText(cap, i, max);
  const st = cap.streams[s.st]; let out = '', on = false;
  for (const j of st.pk) { if (j === i) on = true; if (!on) continue; const q = cap.pk[j].s; if (j !== i && (q.http || q.dirA !== s.dirA)) { if (q.http) break; continue; } if (q.pll) out += payloadText(cap, j, max); if (out.length >= max) break; }
  const k = out.indexOf('\r\n\r\n'); return k >= 0 && /^(HTTP\/|[A-Z]+ \S+ HTTP\/)/.test(out) ? out.slice(k + 4) : out;
}
function aiAssess(cap, D, add) {
  const pk = cap.pk;
  // tools and payloads that read as if an AI wrote them (scripts downloaded, files uploaded)
  const aiTools = [];
  for (const r of pk) {
    const h = r.s.http; if (!h) continue;
    const upload = !h.resp && h.method === 'POST' && (h.body || '').length > 40;
    const download = h.resp && h.status === 200 && h.reqIdx !== undefined;
    if (!upload && !download) continue;
    const req = download ? pk[h.reqIdx].s.http : h, path = safeDecode((req.uri || '').split('?')[0]);
    const ct = (h.headers['content-type'] || '').toLowerCase();
    if (download && !(/\.(ps1|psm1|sh|py|js|vbs|bat|cmd|pl|rb|php|aspx?|go|c|cs)$/i.test(path) || /(script|powershell|x-sh|x-python|javascript|text\/plain)/.test(ct))) continue;
    const t = httpBodyText(cap, r.i, 65536);
    const hits = aiTextSigns(t);
    if (!hits.length || (!hits.some(x => x.strong) && hits.length < 2)) continue;
    const who = download ? r.s.dst : r.s.src, peer = download ? r.s.src : r.s.dst;
    aiTools.push({ who, peer, path, download, hits, ev: [h.reqIdx, r.i].filter(x => x !== undefined) });
  }
  const fw = new Map(), asst = new Map(), oast = new Map();
  for (const r of pk) {
    const s = r.s, h = s.http;
    if (h && !h.resp && h.ua) {
      const f = AI_FRAMEWORK_UA.find(([re]) => re.test(h.ua));
      if (f) { const fam = f[1].split(' (')[0], k = s.src + '|' + fam; let o = fw.get(k); if (!o) { o = { src: s.src, tool: fam, uas: new Set(), dsts: new Set(), ev: [] }; fw.set(k, o); } o.uas.add(h.ua); o.dsts.add(s.dst); o.ev.push(r.i); if (h.respIdx !== undefined) o.ev.push(h.respIdx); }
      const a2 = AI_ASSISTANT_UA.find(([re]) => re.test(h.ua));
      if (a2) { let o = asst.get(s.src); if (!o) { o = { tools: new Set(), uas: new Set(), ev: [] }; asst.set(s.src, o); } o.tools.add(a2[1]); o.uas.add(h.ua); o.ev.push(r.i); }
    }
    const nm = (s.sni || (s.dns && !s.dns.qr && s.dns.qs[0] ? s.dns.qs[0].name : '') || (h && !h.resp ? (h.host || '').split(':')[0] : '')).replace(/\.$/, '');
    if (nm && OAST.test(nm)) { let o = oast.get(s.src); if (!o) { o = { names: new Set(), ev: [] }; oast.set(s.src, o); } o.names.add(nm); o.ev.push(r.i); }
  }
  for (const o of fw.values()) add({ type: 'aiframework', title: 'AI attack framework: ' + o.tool, sev: 'critical', stage: 'resource', tech: 'T1588.007', techName: 'Obtain Capabilities: Artificial Intelligence', src: o.src, dst: [...o.dsts][0] + (o.dsts.size > 1 ? ' +' + (o.dsts.size - 1) : ''), count: o.ev.length,
    summary: o.src + ' sent requests with the User-Agent of ' + o.tool + ', an autonomous AI penetration-testing framework, to ' + [...o.dsts].slice(0, 4).join(', ') + (o.dsts.size > 4 ? ', …' : '') + '. The framework names itself, so this is a fingerprint, not a guess; whether the run was authorised is for you to check.',
    details: [['Framework', o.tool], ['User-Agents', [...o.uas].join('\n')], ['Targets', [...o.dsts].join(', ')], ['Requests', o.ev.length]], ev: o.ev.sort((x, y) => x - y) });
  for (const [src, o] of oast) if (o.names.size) add({ type: 'oast', title: 'Out-of-band callback service: ' + [...o.names][0], sev: 'medium', stage: 'c2', tech: 'T1102', techName: 'Web Service', src, dst: [...o.names][0], count: o.ev.length,
    summary: src + ' contacted ' + [...o.names].join(', ') + '. Scanners and AI agents use these callback services to confirm blind injection and SSRF; from a server, it often means an injected payload ran.',
    details: [['Names', [...o.names].join('\n')], ['Packets', o.ev.length]], ev: o.ev });
  for (const o of aiTools) add({ type: 'aitool', title: 'Tool written with AI: ' + o.path.split('/').pop(), sev: 'high', stage: 'resource', tech: 'T1588.007', techName: 'Obtain Capabilities: Artificial Intelligence', src: o.who, dst: o.peer, count: o.hits.length,
    summary: o.who + (o.download ? ' downloaded ' : ' uploaded ') + o.path + (o.download ? ' from ' : ' to ') + o.peer + '. The file reads as if an AI assistant wrote it: ' + o.hits.map(x => x.name.toLowerCase()).join(', ') + '.',
    details: o.hits.map(x => [x.name + (x.strong ? ' (strong)' : ''), x.line]), ev: o.ev });

  const reqs = new Map(); // src → [{i, t, dst, key, ua}]
  for (const r of pk) { const h = r.s.http; if (!h || h.resp) continue; let a = reqs.get(r.s.src); if (!a) { a = []; reqs.set(r.s.src, a); } a.push({ i: r.i, t: r.t, dst: r.s.dst, key: h.method + ' ' + (h.uri || ''), path: (h.uri || '').split('?')[0], ua: h.ua || '', h }); }
  // hosts that talk to AI model APIs (by TLS server name or DNS question)
  const llm = new Map(); cap.llmIps = new Map();
  for (const r of pk) { const s = r.s; const nm = s.sni || (s.dns && !s.dns.qr && s.dns.qs[0] ? s.dns.qs[0].name : ''); if (s.dns && s.dns.qr && s.dns.qs[0] && LLM_API.test(s.dns.qs[0].name.replace(/\.$/, ''))) (s.dns.ans || []).forEach(a => { if (a.type === 'A' || a.type === 'AAAA') cap.llmIps.set(a.val, s.dns.qs[0].name.replace(/\.$/, '')); }); if (nm && LLM_API.test(nm.replace(/\.$/, '')) && !(s.dns && s.dns.qr)) { if (s.sni) cap.llmIps.set(s.dst, nm); let o = llm.get(s.src); if (!o) { o = { names: new Set(), ev: [] }; llm.set(s.src, o); } o.names.add(nm.replace(/\.$/, '')); o.ev.push(r.i); } }
  // who to assess: every source of a detection that is not just a victim, plus anyone calling an AI API who is also in a detection
  const bySrc = new Map(); D.forEach(d => { if (!isIp(d.src)) return; (bySrc.get(d.src) || bySrc.set(d.src, []).get(d.src)).push(d); });
  const involved = new Set(D.flatMap(d => [d.src, d.dst, ...(d.targets || [])]));
  const cands = new Set([...bySrc.keys()].filter(ip => !isPrivate(ip) || bySrc.get(ip).some(d => ['lateral', 'hscan', 'ldaprecon', 'kerberoast', 'imds', 'exfil'].includes(d.type))));
  for (const ip of llm.keys()) if (involved.has(ip)) cands.add(ip);
  for (const o of fw.values()) cands.add(o.src);
  for (const ip of asst.keys()) if (involved.has(ip)) cands.add(ip);
  for (const o of aiTools) { if (involved.has(o.who) && cands.has(o.peer) === false && !isPrivate(o.peer)) cands.add(o.peer); }
  const mean = a => a.reduce((x, y) => x + y, 0) / a.length;
  const cvOf = a => { const m = mean(a); return m ? Math.sqrt(mean(a.map(x => (x - m) ** 2))) / m : 1; };
  const trim = a => { const b = a.slice().sort((x, y) => x - y), k = Math.floor(b.length * 0.1); return b.slice(k, b.length - k); }; // ignore the odd pause
  for (const src of cands) {
    const R = (reqs.get(src) || []).sort((a, b) => a.t - b.t);
    const signs = [];
    const sign = (key, name, weight, strong, detail, ev) => signs.push({ key, name, weight, strong, detail, ev: [...new Set(ev)].sort((a, b) => a - b) });
    // 1. machine-speed, metronome-regular requests (bursts of ≥20 with a tiny, even gap)
    let best = null;
    for (let a = 0; a < R.length; ) {
      let b = a; while (b + 1 < R.length && R[b + 1].t - R[b].t < 1.5) b++;
      if (b - a + 1 >= 20) { const gaps = trim(Array.from({ length: b - a }, (_, k) => R[a + k + 1].t - R[a + k].t)); const m = mean(gaps), cv = cvOf(gaps); if (cv < 0.6 && (!best || b - a > best.n)) best = { n: b - a + 1, m, cv, ev: R.slice(a, b + 1).map(x => x.i) }; }
      a = b + 1;
    }
    if (best) sign('speed', 'Machine-speed, evenly timed requests', 1, false, best.n + ' requests about every ' + fmtDur(best.m) + ' with ' + (best.cv * 100).toFixed(0) + '% variation in the gap. People click unevenly; agents and scripts do not.', best.ev);
    // 2. read a machine-readable map of the target first, then used what it listed
    const maps = R.filter(x => API_MAP.test(x.path) && x.h.status === 200);
    if (maps.length) {
      const listed = new Set(); maps.forEach(m => { if (m.h.respIdx === undefined) return; const body = payloadText(cap, m.h.respIdx, 65536); (body.match(/"(\/[\w\-./{}]+)"\s*:/g) || []).forEach(x => listed.add(x.slice(1, -2).replace(/\{[^}]+\}/g, ''))); (body.match(/^(?:dis)?allow:\s*(\/\S*)/gim) || []).forEach(x => listed.add(x.split(/:\s*/)[1])); });
      const used = R.filter(x => !API_MAP.test(x.path) && [...listed].some(l => l.length > 1 && x.path.startsWith(l.replace(/\/$/, ''))) && x.t > maps[0].t);
      if (used.length) sign('map', 'Read the target\'s API map, then used it', 2, true, 'Fetched ' + [...new Set(maps.map(m => m.path))].join(', ') + ' first, then went straight to ' + [...new Set(used.map(u => u.path))].slice(0, 4).join(', ') + '. AI agents read machine-readable maps to plan their next step.', maps.map(m => m.i).concat(maps.map(m => m.h.respIdx).filter(x => x !== undefined), used.slice(0, 20).map(u => u.i)));
    }
    // 3. the same multi-step sequence replayed identically later
    const W = 8, seen = new Map(); let rep = null;
    for (let k = 0; k + W <= R.length; k++) {
      const sig = R.slice(k, k + W).map(x => x.dst + ' ' + x.key).join('\n');
      const first = seen.get(sig);
      if (first === undefined) { seen.set(sig, k); continue; }
      if (R[k].t - R[first].t < 5) continue;
      let n = W; while (k + n < R.length && first + n < k && R[k + n].dst + R[k + n].key === R[first + n].dst + R[first + n].key) n++;
      if (!rep || n > rep.n) rep = { n, gap: R[k].t - R[first].t, a: first, b: k };
      k += n - 1;
    }
    if (rep) sign('replay', 'Replayed the same attack run', 3, true, 'A run of ' + rep.n + ' requests was repeated step for step ' + fmtDur(rep.gap) + ' later, in the same order. Agent frameworks re-run a plan when a step needs confirming.', R.slice(rep.a, rep.a + rep.n).concat(R.slice(rep.b, rep.b + rep.n)).map(x => x.i));
    // 4. a fixed-interval "recheck loop" on the same URL
    const byKey = new Map(); R.forEach(x => { const k = x.dst + ' ' + x.key; (byKey.get(k) || byKey.set(k, []).get(k)).push(x); });
    let loop = null;
    for (const [k, xs] of byKey) { if (xs.length < 5) continue; const gaps = []; for (let j = 1; j < xs.length; j++) gaps.push(xs[j].t - xs[j - 1].t); const m = mean(gaps), cv = cvOf(gaps); if (m >= 10 && cv < 0.05 && (!loop || xs.length > loop.n)) loop = { k, n: xs.length, m, cv, ev: xs.map(x => x.i) }; }
    if (loop) sign('loop', 'Recheck loop at a fixed interval', 2, true, loop.k.replace(/^\S+ /, '') + ' polled ' + loop.n + ' times every ' + fmtDur(loop.m) + ' (±' + (loop.cv * 100).toFixed(1) + '%). Public reports on ARTEX describe polling loops like this.', loop.ev);
    // 5. HTTP clients that agent frameworks use
    const uas = new Map(); R.forEach(x => { const m = x.ua.match(AGENT_UA); if (m) (uas.get(x.ua) || uas.set(x.ua, []).get(x.ua)).push(x.i); });
    if (uas.size) { const [ua, ev] = [...uas].sort((a, b) => b[1].length - a[1].length)[0]; sign('ua', 'Scripted client used by AI agent frameworks', 1, false, '"' + ua + '" on ' + ev.length + ' requests, a library agent frameworks drive, not a browser.', ev); }
    // 6. many ATT&CK stages within minutes of the first step
    const mine = D.filter(d => d.src === src || (d.dst === src && d.type === 'webshell'));
    const tactics = new Set(D.filter(d => d.src === src || involved.has(src) && (d.src === src)).map(d => d.stage));
    const t0 = Math.min(...mine.map(d => d.t0)), access = mine.filter(d => ['access', 'exec'].includes(d.stage)).map(d => d.t0);
    const firstAccess = access.length ? Math.min(...access) - t0 : Infinity;
    if (!isPrivate(src) && tactics.size >= 2 && firstAccess < 180) sign('pace', 'Kill chain at machine pace', 1, false, 'From first contact to ' + (mine.find(d => d.t0 - t0 === firstAccess)?.title.toLowerCase() || 'access') + ' in ' + fmtDur(firstAccess) + ', across ' + tactics.size + ' ATT&CK tactics.', mine.flatMap(d => d.ev.slice(0, 3)));
    // 7. talks to an AI model API itself
    const L = llm.get(src);
    if (L) sign('llm', 'Talks to an AI model API', 3, true, src + ' connected to ' + [...L.names].join(', ') + (isPrivate(src) ? ' while it was part of the attack: an agent may be running on it.' : '.'), L.ev);
    // 9. the framework named itself
    const F = [...fw.values()].filter(o => o.src === src);
    if (F.length) sign('framework', 'Identified itself as an AI attack framework', 5, true, F.map(o => o.tool + ' (' + [...o.uas].slice(0, 3).join(', ') + ')').join('; ') + '.', F.flatMap(o => o.ev));
    const AS = asst.get(src);
    if (AS && (involved.has(src) || F.length)) sign('assistant', 'AI coding agent running on this host', 2, true, [...AS.tools].join(', ') + ' (' + [...AS.uas].slice(0, 2).join(', ') + ') was active on a host that is part of the attack.', AS.ev);
    const OB = oast.get(src);
    if (OB) sign('oast', 'Used out-of-band callback services', 1, false, [...OB.names].slice(0, 4).join(', ') + ': how agents and scanners confirm blind vulnerabilities.', OB.ev);
    // 8. the tools themselves were written by an AI
    const T = aiTools.filter(o => o.who === src || o.peer === src);
    if (T.length) sign('aicode', 'Tools or payloads written by AI', 2, true, T.map(o => o.path.split('/').pop() + ': ' + o.hits.map(x => x.name.toLowerCase()).join(', ')).join('; ') + '.', T.flatMap(o => o.ev));
    const score = signs.reduce((a, x) => a + x.weight, 0), strong = signs.filter(x => x.strong).length;
    if (!strong || score < 3) continue;
    if (signs.length === 1 && signs[0].key === 'framework') continue; // the framework detection already says it all
    // Two separate questions: is AI involved, and is this host attacking anything?
    // Calling an AI service is normal; it only matters when the same host is part of the attack.
    const attacks = D.filter(d => d.src === src && !AI_TYPES.has(d.type));
    const malicious = attacks.length > 0 || F.length > 0;
    const onHost = isPrivate(src) && !!L;
    let conf = F.length ? 'confirmed' : score >= 5 && strong >= 2 ? 'likely' : 'possible';
    if (onHost && !F.length) {
      if (!attacks.length) {
        add({ type: 'aiuse', title: 'AI service used by ' + src, sev: 'low', stage: 'resource', tech: 'T1588.007', techName: 'Obtain Capabilities: Artificial Intelligence', src, dst: [...L.names].join(', '), count: L.ev.length,
          summary: src + ' called ' + [...L.names].join(', ') + '. On its own this is normal: apps and people use AI services every day. Nothing in this capture shows ' + src + ' attacking anything, so it is listed for context only.',
          details: [['AI services', [...L.names].join('\n')], ['Packets', L.ev.length], ['Malicious', 'Not shown: no attack comes from this host']], ev: L.ev });
        continue;
      }
      const w0 = Math.min(...attacks.map(d => d.t0)) - 120, w1 = Math.max(...attacks.map(d => d.t1)) + 120;
      const during = L.ev.some(i => pk[i].t >= w0 && pk[i].t <= w1);
      conf = during && strong >= 2 ? 'likely' : 'possible';
    }
    const sure = conf !== 'possible';
    const ev = [...new Set(signs.flatMap(x => x.ev))].sort((a, b) => a - b);
    const dst = onHost ? ([...cap.llmIps].find(([, n]) => L.names.has(n)) || [[...L.names][0]])[0] : mine.length ? [...new Set(mine.map(d => d.dst))].filter(isIp)[0] || mine[0].dst : '';
    const tools = F.map(o => o.tool).filter((v, i, a) => a.indexOf(v) === i).join(', ');
    const nsig = signs.length + ' sign' + (signs.length > 1 ? 's' : '');
    const title = conf === 'confirmed' ? 'AI-driven attack by ' + tools + ': ' + nsig : onHost ? 'AI agent ' + (conf === 'likely' ? 'likely' : 'possibly') + ' at work on ' + src : (conf === 'likely' ? 'Likely AI-driven attack: ' : 'Possible AI involvement: ') + nsig;
    const sev = conf === 'confirmed' ? 'critical' : conf === 'likely' ? (malicious ? (onHost ? 'high' : 'critical') : 'medium') : (malicious ? 'medium' : 'low');
    const atk = attacks.slice(0, 4).map(d => d.title);
    const confText = { confirmed: 'confirmed: the traffic names ' + tools, likely: 'likely: ' + strong + ' strong signs', possible: 'possible: ' + strong + ' strong sign' + (strong === 1 ? '' : 's') + ', which ordinary automation or legitimate AI use can also produce' }[conf];
    add({ type: 'ai', title, sev, stage: 'resource', tech: 'T1588.007', techName: 'Obtain Capabilities: Artificial Intelligence', src, dst, count: signs.length,
      ai: { score, strong, sure, conf, malicious, attacks: atk },
      t0: pk[ev[0]].t, t1: pk[ev[ev.length - 1]].t, signs,
      summary: 'AI involvement is ' + confText + '. ' + (malicious ? 'Malicious: yes, ' + src + ' is also behind ' + (atk.length ? atk.join(', ') : 'an AI attack framework') + (attacks.length > 4 ? ' and more' : '') + '.' : 'Malicious: not shown, no attack in this capture comes from ' + src + '.') + ' The signs: ' + signs.map(x => x.name[0].toLowerCase() + x.name.slice(1)).join('; ') + '. Each one is listed with its packets below.',
      details: [['AI involvement', conf[0].toUpperCase() + conf.slice(1)], ['Malicious', malicious ? 'Yes: ' + (atk.join('; ') || 'AI attack framework') : 'Not shown']].concat(signs.map(x => [x.name + (x.strong ? ' (strong)' : ''), x.detail]), [['Score', score + ' (' + strong + ' strong sign' + (strong === 1 ? '' : 's') + '; a verdict needs at least one strong sign)']]), ev });
  }
  // regular calls to an AI model API are AI use, not a C2 check-in; they only matter on a host that is attacking
  for (const d of D) if (d.type === 'beacon' && cap.llmIps.has(d.dst)) { const nm = cap.llmIps.get(d.dst), bad = D.some(x => x.src === d.src && !AI_TYPES.has(x.type) && x.type !== 'beacon'); d.type = 'llmcalls'; d.title = 'Regular calls to an AI model API (' + nm + ')'; d.sev = bad ? 'medium' : 'low'; d.stage = 'resource'; d.tech = 'T1588.007'; d.techName = 'Obtain Capabilities: Artificial Intelligence'; d.summary = d.src + ' called ' + nm + ' ' + d.count + ' times at a steady rhythm. ' + (bad ? 'The same host is part of the attack, so this may be an agent asking a model for its next step.' : 'On its own that is normal AI use; nothing shows this host attacking.'); }
}
/* ===================== Attack flow model ===================== */
function buildAttackFlow(cap, D) {
  if (!D.length) return null;
  const actors = new Map();
  const actor = (id, kind) => { if (!id) return; let a = actors.get(id); if (!a) { a = { id, roles: new Set(), first: Infinity, sev: 0 }; actors.set(id, a); } if (kind) a.roles.add(kind); return a; };
  const steps = [];
  const c2s = new Set();
  D.forEach(d => { if (['beacon', 'shell', 'badport', 'exfil'].includes(d.type) && isIp(d.dst) && !isPrivate(d.dst)) c2s.add(d.dst); });
  const malSrc = new Set(D.filter(d => d.type === 'download' && isIp(d.dst) && !isPrivate(d.dst) && !c2s.has(d.dst)).map(d => d.dst));
  for (const d of D) {
    if (d.type === 'cleartext' && SEV_RANK[d.sev] < 3) { /* still include */ }
    let src = d.src, dst = d.dst;
    if (d.type === 'synflood' && d.spoofed) src = 'Spoofed sources';
    if (d.type === 'dnstunnel') dst = d.dst;
    if (/hosts$/.test(dst)) dst = 'LAN hosts';
    const sa = actor(src), da = actor(dst);
    sa.first = Math.min(sa.first, d.t0); da.first = Math.min(da.first, d.t0);
    sa.sev = Math.max(sa.sev, SEV_RANK[d.sev]); da.sev = Math.max(da.sev, SEV_RANK[d.sev]);
    steps.push({ d, src, dst });
  }
  for (const [id, a] of actors) {
    const asSrc = steps.filter(s => s.src === id), asDst = steps.filter(s => s.dst === id);
    const mac = isMac(id), priv = mac || (isIp(id) && isPrivate(id));
    if (cap.llmIps && cap.llmIps.has(id)) a.role = 'AI model API';
    else if (c2s.has(id)) a.role = 'C2 server';
    else if (malSrc.has(id)) a.role = 'Malware host';
    else if (id === 'Spoofed sources') a.role = 'Botnet / spoofed';
    else if (id === 'LAN hosts') a.role = 'Internal network';
    else if (!mac && !isIp(id)) a.role = 'External domain';
    else if (!priv && asSrc.length) a.role = D.some(d => d.src === id && ((d.type === 'ai' && d.ai.sure) || d.type === 'aiframework')) ? 'AI-driven attacker' : 'Attacker';
    else if (priv && asSrc.some(s => ['lateral', 'beacon', 'shell', 'exfil', 'dnstunnel', 'sweep', 'hscan'].includes(s.d.type)) || (asSrc.some(s => s.d.type === 'download') && asSrc.length > 1 && asSrc.some(s => s.d.type !== 'download' && s.d.type !== 'cleartext'))) a.role = 'Compromised host';
    else if (priv && asSrc.some(s => s.d.type === 'download')) a.role = 'At-risk host';
    else if (priv && asSrc.some(s => s.d.type === 'arpspoof')) a.role = 'Rogue insider';
    else if (asDst.length && priv) a.role = 'Victim';
    else if (asSrc.length && asSrc.every(s => s.d.type === 'cleartext')) a.role = 'Internal client';
    else a.role = priv ? 'Internal host' : 'External host';
  }
  const order = { 'AI model API': 9.7, 'At-risk host': 4.5, 'Malware host': 9.5, 'AI-driven attacker': 0, 'Attacker': 0, 'Botnet / spoofed': 1, 'Rogue insider': 2, 'Internal client': 3, 'Compromised host': 4, 'Victim': 5, 'Internal network': 6, 'Internal host': 7, 'External host': 8, 'External domain': 9, 'C2 server': 10 };
  const lanes = [...actors.values()].sort((a, b) => order[a.role] - order[b.role] || a.first - b.first);
  const stages = STAGES.map(s => { const ds = D.filter(d => d.stage === s.k); return { ...s, n: ds.length, t0: ds.length ? Math.min(...ds.map(d => d.t0)) : null, sev: ds.reduce((m, d) => Math.max(m, SEV_RANK[d.sev]), 0) }; });
  // narrative
  const att = lanes.filter(l => l.role === 'Attacker' || l.role === 'AI-driven attacker').map(l => l.id);
  const aiAtt = lanes.filter(l => l.role === 'AI-driven attacker').map(l => l.id);
  const comp = lanes.filter(l => l.role === 'Compromised host').map(l => l.id);
  const c2 = lanes.filter(l => l.role === 'C2 server').map(l => l.id);
  let story = '';
  const seen = stages.filter(s => s.n);
  if (att.length) story += 'Activity from ' + (aiAtt.length === att.length ? 'AI-driven ' : '') + 'external attacker' + (att.length > 1 ? 's ' : ' ') + att.join(', ') + ' ';
  if (seen.length) story += (att.length ? 'spans ' : 'Activity spans ') + seen.length + ' ATT&CK tactic' + (seen.length > 1 ? 's' : '') + ' (' + seen.map(s => s.name).join(' → ') + ').';
  if (comp.length) story += ' ' + comp.join(', ') + (comp.length > 1 ? ' appear' : ' appears') + ' compromised';
  if (comp.length && c2.length) story += ' and talks to C2 ' + c2.join(', ');
  if (comp.length) story += '.';
  const ai = lanes.filter(l => l.role === 'AI model API').map(l => cap.llmIps.get(l.id) || l.id);
  if (ai.length) story += ' An AI agent appears to be steering the attack through ' + ai.join(', ') + '.';
  return { lanes, steps, stages, story };
}

/* ===================== Formatting ===================== */
function fmtBytes(b) { if (b < 1024) return b + ' B'; const u = ['KB', 'MB', 'GB', 'TB']; let i = -1; do { b /= 1024; i++; } while (b >= 1024 && i < u.length - 1); return (b < 10 ? b.toFixed(2) : b < 100 ? b.toFixed(1) : b.toFixed(0)) + ' ' + u[i]; }
function fmtBits(b) { const u = ['bps', 'Kbps', 'Mbps', 'Gbps']; let i = 0; while (b >= 1000 && i < u.length - 1) { b /= 1000; i++; } return (b < 10 ? b.toFixed(2) : b < 100 ? b.toFixed(1) : b.toFixed(0)) + ' ' + u[i]; }
function fmtNum(n) { return n.toLocaleString('en-US'); }
function fmtDur(s) { if (s < 1e-3) return (s * 1e6).toFixed(0) + ' µs'; if (s < 1) return (s * 1000).toFixed(s < 0.01 ? 2 : 0) + ' ms'; if (s < 60) return s.toFixed(s < 10 ? 2 : 1) + ' s'; if (s < 3600) return Math.floor(s / 60) + 'm ' + Math.round(s % 60) + 's'; return Math.floor(s / 3600) + 'h ' + Math.round((s % 3600) / 60) + 'm'; }
