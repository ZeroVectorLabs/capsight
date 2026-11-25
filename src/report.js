/* ===================== Findings report: PDF, web page, Word and Markdown ===================== */
const utcStamp = t => new Date(t * 1000).toISOString().replace('T', ' ').replace(/\.\d+Z$/, ' UTC');
const maskSecret = s => { s = String(s ?? ''); return s.length <= 2 ? '••••' : s[0] + '•'.repeat(Math.min(8, s.length - 2)) + s[s.length - 1]; };

/* One model, four renderers: everything the report says comes from here. */
const RPT_COL = { crit: '#d9485f', high: '#e07b4f', med: '#c9962a', low: '#8a8f9c', 'line-2': '#c5d3e6', 'panel-2': '#f6f9fe', panel: '#ffffff', text: '#0b1b33', muted: '#5a6b85' };
const RPT_FONT = '-apple-system, BlinkMacSystemFont, Segoe UI, Helvetica, Arial, sans-serif';
const uniqList = a => [...new Set(a.filter(Boolean))];
const listText = (a, max = 4) => a.length <= max ? a.join(', ') : a.slice(0, max).join(', ') + ' and ' + (a.length - max) + ' more';

/* The network map, drawn off-screen with the app's own layout and exported as a light-theme SVG. */
const RPT_VARS = { crit: '#d9485f', high: '#e07b4f', med: '#c9962a', low: '#8a8f9c', panel: '#ffffff', 'panel-2': '#f6f9fe', 'line-2': '#c5d3e6', text: '#0b1b33', 'text-2': '#3d4f6b', muted: '#5a6b85', accent: '#1f5fd6', axis: '#9fb0c8', dot: '#d6e0ee', s1: '#2563eb', s3: '#4f46e5', s7: '#6d74e8', teal: '#0ea5e9' };
function reportMapSvg(cap) {
  const host = document.createElement('div');
  host.style.cssText = 'position:fixed;left:-30000px;top:0;width:1400px;height:1000px;visibility:hidden';
  document.body.appendChild(host);
  const prevA = S.A; let G = null;
  try {
    S.A = aggregate(cap, null);
    G = makeGraph(host);
    const svg = host.querySelector('svg'), vp = svg && svg.querySelector('#vp');
    if (!vp) return null;
    vp.removeAttribute('transform');
    const bb = vp.getBBox(), pad = 12;
    const x0 = Math.floor(bb.x - pad), y0 = Math.floor(bb.y - pad), W = Math.ceil(bb.width + pad * 2), H = Math.ceil(bb.height + pad * 2);
    const defs = svg.querySelector('defs').cloneNode(true); defs.querySelectorAll('pattern').forEach(n => n.remove());
    const fix = t => t.replace(/var\(--([\w-]+)\)/g, (_, k) => RPT_VARS[k] || '#5a6b85');
    return { svg: fix(`<svg xmlns="http://www.w3.org/2000/svg" width="${W}" height="${H}" viewBox="${x0} ${y0} ${W} ${H}" font-family="${RPT_FONT}"><rect x="${x0}" y="${y0}" width="${W}" height="${H}" fill="#ffffff"/>${defs.outerHTML}${vp.innerHTML}</svg>`), W, H };
  } catch (e) { console.warn('report map', e); return null; }
  finally { if (G) G.destroy(); S.A = prevA; host.remove(); }
}

async function reportModel(opts = {}) {
  const cap = S.cap;
  ensureArt(); if (cap.artP) await cap.artP;
  const A = cap.art || { files: [], creds: [], iocs: { ips: [], domains: [], urls: [] }, inv: [] };
  const D = cap.threats || [], F = cap.flow, ag = aggregate(cap, null);
  const sev = { critical: 0, high: 0, medium: 0, low: 0 }; D.forEach(d => sev[d.sev]++);
  const sevLine = Object.entries(sev).filter(([, n]) => n).map(([k, n]) => n + ' ' + k).join(', ');
  const stageName = k => (STAGES.find(s => s.k === k) || { name: k }).name;
  const lanes = F ? F.lanes : [];
  const role = r => lanes.filter(l => l.role === r).map(l => l.id);
  const attackers = role('Attacker').concat(role('AI-driven attacker')), spoofed = role('Botnet / spoofed').length > 0, insiders = role('Rogue insider');
  const compromised = role('Compromised host'), atRisk = role('At-risk host'), c2 = role('C2 server'), malware = role('Malware host');
  const creds = A.creds, files = A.files.filter(f => f.interesting && f.flags.length);
  /* the people in the story, one line each */
  const facts = [];
  if (attackers.length || spoofed) facts.push([role('AI-driven attacker').length ? 'AI-driven attacker' : 'Attacker', attackers.length ? listText(attackers) + (spoofed ? ', plus spoofed source addresses' : '') : 'Spoofed source addresses']);
  if (insiders.length) facts.push(['Rogue insider', listText(insiders)]);
  if (compromised.length) facts.push(['Compromised', listText(compromised)]);
  if (atRisk.length) facts.push(['At risk', listText(atRisk)]);
  if (c2.length) facts.push(['Command and control', listText(c2)]);
  if (malware.length) facts.push(['Malware host', listText(malware)]);
  facts.push(['Capture', cap.name + ', ' + fmtNum(cap.pk.length) + ' packets, ' + fmtBytes(cap.size)]);
  facts.push(['Time', utcStamp(cap.t0) + ', ' + fmtDur(cap.dur) + ' long']);
  /* what to do next, only what this capture supports */
  const actions = [];
  const blockIps = uniqList([...attackers, ...c2, ...malware]).filter(isIp);
  if (blockIps.length) actions.push('Block ' + listText(blockIps, 6) + ' at the firewall and look for the same addresses in other logs.');
  if (compromised.length) actions.push('Isolate ' + listText(compromised) + ' and investigate ' + (compromised.length > 1 ? 'them' : 'it') + ' for persistence: new accounts, scheduled tasks, unknown services.');
  if (atRisk.length) actions.push('Check ' + listText(atRisk) + ': ' + (atRisk.length > 1 ? 'they were' : 'it was') + ' targeted or exposed during the attack.');
  if (insiders.length) actions.push('Find the device behind ' + listText(insiders) + ' on the local network and remove it.');
  const badDomains = A.iocs.domains.filter(o => o.bad).map(o => o.v);
  if (badDomains.length) actions.push('Block the domain' + (badDomains.length > 1 ? 's ' : ' ') + listText(badDomains) + ' in DNS and the web proxy.');
  if (creds.length) {
    const users = uniqList(creds.map(c => c.user)), protos = uniqList(creds.map(c => c.proto.split(' ')[0]).filter(p => /^[A-Z0-9]{2,}$/.test(p) && p !== 'AWS'));
    actions.push('Reset the ' + creds.length + ' credential' + (creds.length > 1 ? 's' : '') + ' seen in clear text' + (users.length ? ' (' + listText(users, 5) + ')' : '') + (protos.length ? ', and move ' + listText(protos, 5) + ' to an encrypted alternative' : '') + '.');
  }
  const aiD = D.filter(d => d.type === 'ai' && d.ai.sure);
  if (aiD.length) actions.push('Treat this as an AI-driven attack: it moves at machine speed and will retry. Take down machine-readable maps of your apps (API specs, robots entries) that are not needed in public, require authentication on every endpoint, and alert on the signs listed under the AI detection.');
  if (D.some(d => d.type === 'imds')) actions.push('Revoke the cloud tokens the server took from the metadata service, rotate any storage keys listed with them, and limit what the server\'s managed identity can do.');
  if (D.some(d => d.type === 'kerberoast')) actions.push('Change the passwords of the service accounts that were kerberoasted, and turn off RC4 for Kerberos.');
  if (D.some(d => d.type === 'webshell')) actions.push('Remove the web shell, close the upload path it came through, and check the web server for other new script files.');
  if (files.length) actions.push('Look up the SHA-256 of the ' + files.length + ' suspicious file' + (files.length > 1 ? 's' : '') + ' below in your threat-intel tools and remove them from the hosts that received them.');
  let flow = null;
  if (F && D.length) { const r = seqSvg(cap, { col: k => RPT_COL[k] || RPT_COL.muted, avail: 1000, minLane: 98, compact: true, font: RPT_FONT, bg: '#ffffff' }); flow = r; }
  const map = reportMapSvg(cap);
  const flaggedIps = A.iocs.ips.filter(o => o.bad || hostRole(o.v)).map(o => [o.v, 'IP address', hostRole(o.v) || 'Seen in a detection']);
  return {
    title: 'Findings report',
    file: cap.name,
    generated: utcStamp(Date.now() / 1000),
    clean: !D.length,
    sev,
    verdict: D.length ? D.length + ' security detection' + (D.length > 1 ? 's' : '') + ': ' + sevLine : 'No attacks detected',
    summary: D.length ? (F && F.story) || '' : 'Capsight checked ' + fmtNum(cap.pk.length) + ' packets for port scans, host sweeps, brute force, web exploits, shells, beaconing, DNS tunnelling, exfiltration, ARP spoofing and floods, and found none. That does not prove the network is safe; it means nothing in this capture matched a known attack pattern.',
    facts, actions, flow, map,
    hosts: fmtNum(ag.hosts.size),
    steps: (F ? F.steps : D.map(d => ({ d, src: d.src, dst: d.dst }))).map((s, i) => ({
      n: i + 1, sev: s.d.sev, title: s.d.title, tactic: stageName(s.d.stage), tech: s.d.tech || '',
      src: String(s.src ?? ''), dst: String(s.dst ?? ''), rel: '+' + fmtRel(s.d.t0 - cap.t0, cap.dur), summary: s.d.summary || '' })),
    iocs: [...flaggedIps, ...A.iocs.domains.filter(o => o.bad).map(o => [o.v, 'Domain', 'Seen in a detection'])].slice(0, 40),
    files: files.map(f => [f.name, f.type.label + ', ' + fmtBytes(f.size), f.occ[0].src + ' → ' + f.occ[0].dst, f.flags.map(x => x.t).join('; '), f.sha256]),
    creds: creds.map(c => [c.proto, c.src + ' → ' + c.dst, c.user || '', opts.secrets ? String(c.pw ?? '') : maskSecret(c.pw)]),
    secrets: !!opts.secrets,
  };
}

const RPT_COLS = {
  steps: ['#', 'When', 'Severity', 'What happened', 'From → to', 'ATT&CK'],
  iocs: ['Indicator', 'Type', 'Why'],
  files: ['File', 'Type', 'From → to', 'Why it stands out', 'SHA-256'],
  creds: ['Protocol', 'Client → server', 'Username', 'Secret'],
};
/* the sections, in order, shared by every renderer */
function reportSections(m) {
  const out = [];
  out.push({ k: 'verdict' });
  out.push({ h: 'At a glance', kv: m.facts });
  if (!m.clean) out.push({ h: 'What happened', p: [m.summary] });
  if (m.actions.length) out.push({ h: 'What to do now', list: m.actions });
  if (m.flow) out.push({ h: 'Attack flow', p: ['Who did what to whom, in time order. The numbers match the timeline below.'], img: 'flow' });
  if (m.map) out.push({ h: 'Network map', p: [m.clean ? 'The hosts in this capture and who talked to whom. Thicker lines carried more traffic.' : 'The hosts in this capture and who talked to whom. Coloured arrows are attacks, labelled with their timeline numbers; thicker grey lines carried more traffic.'], img: 'map' });
  if (!m.clean) out.push({ h: 'Timeline', table: 'steps', rows: m.steps });
  if (m.iocs.length) out.push({ h: 'Indicators to block', table: 'iocs', rows: m.iocs });
  if (m.creds.length) out.push({ h: 'Passwords sent in clear text', p: [m.secrets ? 'Secrets are shown in full. Handle this report as sensitive.' : 'Secrets are masked. Capsight can include them in full when you make the report.'], table: 'creds', rows: m.creds });
  if (m.files.length) out.push({ h: 'Suspicious files', table: 'files', rows: m.files });
  return out;
}
const stepCells = s => [String(s.n), s.rel, SEV_LABEL[s.sev] || s.sev, s.title, s.src + (s.dst && s.dst !== s.src ? ' → ' + s.dst : ''), s.tactic + (s.tech ? ', ' + s.tech : '')];
const RPT_FOOT = 'Made with Capsight, which analysed this capture in the browser; nothing was uploaded. Detections are leads for an analyst to confirm, not proof.';

/* the diagram as PNG, for Word and Markdown */
async function svgToPng(svg, W, H, scale = 2) {
  const url = URL.createObjectURL(new Blob([svg], { type: 'image/svg+xml' }));
  try {
    const img = new Image(); img.src = url; await img.decode();
    const c = document.createElement('canvas'); c.width = Math.round(W * scale); c.height = Math.round(H * scale);
    const g = c.getContext('2d'); g.scale(scale, scale); g.drawImage(img, 0, 0, W, H);
    const blob = await new Promise(r => c.toBlob(r, 'image/png'));
    return new Uint8Array(await blob.arrayBuffer());
  } finally { URL.revokeObjectURL(url); }
}
const b64 = u8 => { let s = ''; for (let i = 0; i < u8.length; i += 0x8000) s += String.fromCharCode.apply(null, u8.subarray(i, i + 0x8000)); return btoa(s); };

/* ---------- Markdown ---------- */
async function reportMarkdown(m) {
  const cell = v => String(v ?? '').replace(/\|/g, '\\|').replace(/\n/g, ' ');
  const tbl = (key, rows) => '| ' + RPT_COLS[key].join(' | ') + ' |\n|' + RPT_COLS[key].map(() => '---').join('|') + '|\n' + rows.map(r => '| ' + r.map(cell).join(' | ') + ' |').join('\n') + '\n';
  let s = '# Capsight ' + m.title.toLowerCase() + ': ' + m.file + '\n\nGenerated ' + m.generated + '.\n\n';
  for (const x of reportSections(m)) {
    if (x.k === 'verdict') { s += '> **' + m.verdict + '**\n\n'; continue; }
    s += '## ' + x.h + '\n\n';
    if (x.kv) s += x.kv.map(([k, v]) => '- **' + k + ':** ' + v).join('\n') + '\n\n';
    (x.p || []).forEach(p => s += p + '\n\n');
    if (x.list) s += x.list.map((t, i) => (i + 1) + '. ' + t).join('\n') + '\n\n';
    if (x.img) s += '![' + x.h + '](data:image/png;base64,' + b64(await svgToPng(m[x.img].svg, m[x.img].W, m[x.img].H, 1.5)) + ')\n\n';
    if (x.table === 'steps') s += tbl('steps', m.steps.map(st => { const c = stepCells(st); c[3] = '**' + c[3] + '**' + (st.summary ? '<br>' + st.summary : ''); return c; })) + '\n';
    else if (x.table) s += tbl(x.table, x.rows) + '\n';
  }
  return s + '---\n\n' + RPT_FOOT + '\n';
}

/* ---------- web page (also the source of the PDF) ---------- */
function reportHtml(m) {
  const sevCls = v => ({ critical: 'c', high: 'h', medium: 'm', low: 'l' })[v] || '';
  const mono = /SHA|Indicator|→/;
  const arrow = v => String(v).includes(' → ') ? esc(v).split(' → ').map((p, i) => '<span class="nw">' + (i ? '→ ' : '') + p + '</span>').join('<br>') : esc(v);
  const tbl = (key, rows) => '<table class="t-' + key + '"><thead><tr>' + RPT_COLS[key].map(h => '<th>' + esc(h) + '</th>').join('') + '</tr></thead><tbody>'
    + rows.map(r => '<tr>' + r.map((v, i) => '<td' + (mono.test(RPT_COLS[key][i]) ? ' class="mono"' : '') + '>' + arrow(v) + '</td>').join('') + '</tr>').join('') + '</tbody></table>';
  const steps = '<table class="t-steps"><thead><tr>' + RPT_COLS.steps.map(h => '<th>' + esc(h) + '</th>').join('') + '</tr></thead><tbody>'
    + m.steps.map(st => { const c = stepCells(st); return `<tr><td class="n"><span class="dot ${sevCls(st.sev)}">${st.n}</span></td><td class="when">${esc(c[1])}</td><td><span class="sev ${sevCls(st.sev)}">${esc(c[2])}</span></td><td><b>${esc(c[3])}</b>${st.summary ? '<div class="sum">' + esc(st.summary) + '</div>' : ''}</td><td class="mono">${arrow(c[4])}</td><td class="att">${esc(c[5])}</td></tr>`; }).join('') + '</tbody></table>';
  const sevChips = Object.entries(m.sev).filter(([, n]) => n).map(([k, n]) => `<span class="sev ${sevCls(k)}">${n} ${esc(SEV_LABEL[k])}</span>`).join('');
  const sec = x => {
    if (x.k === 'verdict') return `<div class="verdict ${m.clean ? 'ok' : 'bad'}"><div class="big">${m.clean ? 'No attacks detected' : m.steps.length + ' detection' + (m.steps.length > 1 ? 's' : '')}</div><div class="chips">${sevChips}</div></div>`;
    return '<section' + (x.img ? ' class="figsec"' : '') + '><h2>' + esc(x.h) + '</h2>'
      + (x.kv ? '<dl class="facts">' + x.kv.map(([k, v]) => '<dt>' + esc(k) + '</dt><dd>' + esc(v) + '</dd>').join('') + '</dl>' : '')
      + (x.p || []).map(p => '<p>' + esc(p) + '</p>').join('')
      + (x.list ? '<ol class="todo">' + x.list.map(t => '<li>' + esc(t) + '</li>').join('') + '</ol>' : '')
      + (x.img ? '<figure class="fig">' + m[x.img].svg.replace('<svg ', '<svg role="img" aria-label="' + esc(x.h) + ' diagram" preserveAspectRatio="xMinYMin meet" style="width:100%;height:auto" ') + '</figure>' : '')
      + (x.table === 'steps' ? steps : x.table ? tbl(x.table, x.rows) : '') + '</section>';
  };
  const logo = ($('#brand img') || {}).src || '';
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Capsight ${esc(m.title.toLowerCase())}: ${esc(m.file)}</title><style>
@page{size:A4;margin:14mm 12mm}*{box-sizing:border-box}body{margin:0;background:#eef3fa;color:#0b1b33;font:13.5px/1.5 ${RPT_FONT}}
.page{max-width:980px;margin:0 auto;padding:40px 44px 48px;background:#fff}
header{display:flex;align-items:center;gap:14px;padding-bottom:16px;border-bottom:1px solid #dbe5f2}header img{width:38px;height:38px}
header h1{margin:0;font-size:22px;letter-spacing:-.02em}header p{margin:2px 0 0;color:#5a6b85;font-size:12.5px}
.verdict{margin:22px 0 4px;padding:16px 20px;border-radius:14px;display:flex;align-items:center;justify-content:space-between;gap:16px;flex-wrap:wrap}
.verdict.bad{background:#fdecef}.verdict.ok{background:#e8f6ee}.verdict .big{font-size:24px;font-weight:700;letter-spacing:-.02em}.verdict.bad .big{color:#a3233a}.verdict.ok .big{color:#17663e}
.chips{display:flex;gap:6px;flex-wrap:wrap}
h2{font-size:16px;margin:26px 0 8px;letter-spacing:-.01em}p{margin:0 0 8px;max-width:80ch}
dl.facts{display:grid;grid-template-columns:170px 1fr;gap:5px 14px;margin:0}dl.facts dt{color:#5a6b85}dl.facts dd{margin:0;font-weight:600;word-break:break-word}
ol.todo{margin:0;padding-left:20px}ol.todo li{margin:0 0 6px;padding-left:4px}
figure.fig{margin:6px 0 0;border:1px solid #dbe5f2;border-radius:12px;padding:8px;overflow:hidden}
table{width:100%;border-collapse:collapse;font-size:12px;margin:4px 0 0}th,td{text-align:left;padding:6px 7px;border-bottom:1px solid #e3ebf5;vertical-align:top}
thead th{color:#3d4f6b;font-weight:600;border-bottom:1.5px solid #c5d3e6;white-space:nowrap}.mono{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:11.5px;word-break:break-all}.nw{white-space:nowrap;word-break:normal}
.t-steps .sum{color:#5a6b85;font-size:11.5px;margin-top:2px}.t-steps .when{white-space:nowrap;color:#5a6b85;font-variant-numeric:tabular-nums}.t-steps .att{font-size:11.5px;color:#3d4f6b}
.dot{display:inline-flex;width:20px;height:20px;border-radius:50%;align-items:center;justify-content:center;font-size:10.5px;font-weight:700;color:#fff}.dot.c{background:#d9485f}.dot.h{background:#e07b4f}.dot.m{background:#c9962a;color:#111}.dot.l{background:#8a8f9c}
.sev{display:inline-block;padding:1px 8px;border-radius:999px;font-weight:600;font-size:11px;white-space:nowrap}.sev.c{background:#fdecef;color:#b42340}.sev.h{background:#fdf0e8;color:#a4481f}.sev.m{background:#fdf6e3;color:#8a6410}.sev.l{background:#eef1f6;color:#4a5568}
footer{margin-top:30px;border-top:1px solid #dbe5f2;padding-top:12px;color:#5a6b85;font-size:11.5px}
@media print{body{background:#fff}.page{padding:0;max-width:none}tr,li,figure{break-inside:avoid}h2{break-after:avoid}section.figsec{break-before:page}}
</style></head><body><div class="page"><header>${logo ? `<img src="${logo}" alt="">` : ''}<div><h1>Capsight ${esc(m.title.toLowerCase())}</h1><p>${esc(m.file)}, generated ${esc(m.generated)}</p></div></header>
${reportSections(m).map(sec).join('')}
<footer>${esc(RPT_FOOT)}</footer></div></body></html>`;
}

/* ---------- Word (.docx), written as plain WordprocessingML ---------- */
async function reportDocx(m) {
  const x = s => String(s ?? '').replace(/[&<>"]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
  const run = (t, o = {}) => '<w:r>' + (o.b || o.color || o.mono || o.sz ? '<w:rPr>' + (o.mono ? '<w:rFonts w:ascii="Consolas" w:hAnsi="Consolas"/>' : '') + (o.b ? '<w:b/>' : '') + (o.color ? '<w:color w:val="' + o.color + '"/>' : '') + (o.sz ? '<w:sz w:val="' + o.sz + '"/>' : '') + '</w:rPr>' : '') + '<w:t xml:space="preserve">' + x(t) + '</w:t></w:r>';
  const para = (t, style, o, ppr = '') => '<w:p>' + (style || ppr ? '<w:pPr>' + (style ? '<w:pStyle w:val="' + style + '"/>' : '') + ppr + '</w:pPr>' : '') + run(t, o) + '</w:p>';
  const sevColor = { critical: 'B42340', high: 'A4481F', medium: '8A6410', low: '4A5568' };
  const cell = (runs, w) => '<w:tc>' + (w ? '<w:tcPr><w:tcW w:w="' + w * 50 + '" w:type="pct"/></w:tcPr>' : '') + '<w:p><w:pPr><w:spacing w:before="20" w:after="20"/></w:pPr>' + runs + '</w:p></w:tc>';
  const grid = (key, rows, widths) => '<w:tbl><w:tblPr><w:tblStyle w:val="ReportTable"/><w:tblW w:w="5000" w:type="pct"/>' + (widths ? '<w:tblLayout w:type="fixed"/>' : '') + '</w:tblPr>' + (widths ? '<w:tblGrid>' + widths.map(w => '<w:gridCol w:w="' + Math.round(w * 101) + '"/>').join('') + '</w:tblGrid>' : '')
    + '<w:tr><w:trPr><w:tblHeader/></w:trPr>' + RPT_COLS[key].map((h, i) => cell(run(h, { b: true, sz: 17, color: '3D4F6B' }), widths && widths[i])).join('') + '</w:tr>'
    + rows.map(r => '<w:tr><w:trPr><w:cantSplit/></w:trPr>' + r.map((v, i) => cell(typeof v === 'object' ? v.runs : run(v, { sz: 17, mono: /SHA|Indicator/.test(RPT_COLS[key][i]) }), widths && widths[i])).join('') + '</w:tr>').join('')
    + '</w:tbl>' + para('');
  const imgs = {}; let pid = 0;
  for (const k of ['flow', 'map']) {
    if (!m[k]) continue;
    const g = m[k], maxW = 6.69 * 914400, maxH = 8.6 * 914400;
    let cx = maxW, cy = maxW * g.H / g.W; if (cy > maxH) { cx = cx * maxH / cy; cy = maxH; }
    imgs[k] = { id: ++pid, rid: 'rIdImg' + pid, file: (k === 'flow' ? 'attack-flow' : 'network-map') + '.png', data: await svgToPng(g.svg, g.W, g.H, 2), cx: Math.round(cx), cy: Math.round(cy) };
  }
  const drawing = (img, title) => '<w:p><w:pPr><w:spacing w:after="120"/></w:pPr><w:r><w:drawing><wp:inline distT="0" distB="0" distL="0" distR="0"><wp:extent cx="' + img.cx + '" cy="' + img.cy + '"/><wp:docPr id="' + img.id + '" name="' + x(title) + '" descr="' + x(title) + ' diagram"/>'
    + '<a:graphic xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main"><a:graphicData uri="http://schemas.openxmlformats.org/drawingml/2006/picture"><pic:pic xmlns:pic="http://schemas.openxmlformats.org/drawingml/2006/picture"><pic:nvPicPr><pic:cNvPr id="' + img.id + '" name="' + img.file + '"/><pic:cNvPicPr/></pic:nvPicPr><pic:blipFill><a:blip r:embed="' + img.rid + '"/><a:stretch><a:fillRect/></a:stretch></pic:blipFill><pic:spPr><a:xfrm><a:off x="0" y="0"/><a:ext cx="' + img.cx + '" cy="' + img.cy + '"/></a:xfrm><a:prstGeom prst="rect"><a:avLst/></a:prstGeom></pic:spPr></pic:pic></a:graphicData></a:graphic></wp:inline></w:drawing></w:r></w:p>';
  const sec = s => {
    if (s.k === 'verdict') return para(m.verdict, null, { b: true, sz: 30, color: m.clean ? '17663E' : 'A3233A' }, '<w:spacing w:before="200" w:after="120"/>');
    let o = para(s.h, 'Heading1');
    if (s.kv) o += s.kv.map(([k, v]) => '<w:p><w:pPr><w:spacing w:after="40"/></w:pPr>' + run(k + ':  ', { color: '5A6B85' }) + run(v, { b: true }) + '</w:p>').join('');
    (s.p || []).forEach(p => o += para(p, null, {}, s.img ? '<w:keepNext/>' : ''));
    if (s.list) o += s.list.map((t, i) => '<w:p><w:pPr><w:spacing w:after="60"/><w:ind w:left="360" w:hanging="360"/></w:pPr>' + run((i + 1) + '.\t', { b: true }) + run(t) + '</w:p>').join('');
    if (s.img && imgs[s.img]) o += drawing(imgs[s.img], s.h);
    if (s.table === 'steps') o += grid('steps', m.steps.map(st => { const c = stepCells(st); return [c[0], c[1], { runs: run(c[2], { b: true, sz: 17, color: sevColor[st.sev] }) }, { runs: run(c[3], { b: true, sz: 17 }) + (st.summary ? '<w:r><w:br/></w:r>' + run(st.summary, { sz: 16, color: '5A6B85' }) : '') }, { runs: run(c[4], { sz: 16, mono: true }) }, { runs: run(c[5], { sz: 16 }) }]; }), [4, 7, 9, 48, 18, 14]);
    else if (s.table) o += grid(s.table, s.rows);
    return o;
  };
  const body = para('Capsight ' + m.title.toLowerCase(), 'Title') + para(m.file + ', generated ' + m.generated, null, { color: '5A6B85' })
    + reportSections(m).map(sec).join('') + para(RPT_FOOT, null, { color: '5A6B85', sz: 16 }, '<w:spacing w:before="240"/>');
  const W = 'xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships" xmlns:wp="http://schemas.openxmlformats.org/drawingml/2006/wordprocessingDrawing"';
  const doc = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><w:document ' + W + '><w:body>' + body
    + '<w:sectPr><w:pgSz w:w="11906" w:h="16838"/><w:pgMar w:top="1000" w:right="900" w:bottom="1000" w:left="900" w:header="500" w:footer="500" w:gutter="0"/></w:sectPr></w:body></w:document>';
  const st = (id, name, ppr, rpr, extra = '') => '<w:style w:type="paragraph" w:styleId="' + id + '"><w:name w:val="' + name + '"/><w:basedOn w:val="Normal"/><w:next w:val="Normal"/>' + extra + '<w:pPr>' + ppr + '</w:pPr><w:rPr>' + rpr + '</w:rPr></w:style>';
  const styles = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><w:styles xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
    + '<w:docDefaults><w:rPrDefault><w:rPr><w:rFonts w:ascii="Calibri" w:hAnsi="Calibri" w:cs="Calibri"/><w:sz w:val="21"/><w:color w:val="0B1B33"/></w:rPr></w:rPrDefault><w:pPrDefault><w:pPr><w:spacing w:after="100" w:line="264" w:lineRule="auto"/></w:pPr></w:pPrDefault></w:docDefaults>'
    + '<w:style w:type="paragraph" w:default="1" w:styleId="Normal"><w:name w:val="Normal"/></w:style>'
    + st('Title', 'Title', '<w:spacing w:after="40"/>', '<w:b/><w:sz w:val="40"/>')
    + st('Heading1', 'heading 1', '<w:keepNext/><w:spacing w:before="300" w:after="100"/><w:outlineLvl w:val="0"/>', '<w:b/><w:sz w:val="26"/><w:color w:val="0B2A55"/>', '<w:uiPriority w:val="9"/><w:qFormat/>')
    + '<w:style w:type="table" w:styleId="ReportTable"><w:name w:val="Report Table"/><w:tblPr><w:tblBorders><w:bottom w:val="single" w:sz="4" w:color="C5D3E6"/><w:insideH w:val="single" w:sz="4" w:color="E3EBF5"/></w:tblBorders><w:tblCellMar><w:left w:w="70" w:type="dxa"/><w:right w:w="70" w:type="dxa"/></w:tblCellMar></w:tblPr></w:style>'
    + '</w:styles>';
  const ct = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Default Extension="png" ContentType="image/png"/><Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/><Override PartName="/word/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.styles+xml"/><Override PartName="/docProps/core.xml" ContentType="application/vnd.openxmlformats-package.core-properties+xml"/></Types>';
  const rels = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/><Relationship Id="rId2" Type="http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties" Target="docProps/core.xml"/></Relationships>';
  const drels = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/>' + Object.values(imgs).map(i => '<Relationship Id="' + i.rid + '" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/image" Target="media/' + i.file + '"/>').join('') + '</Relationships>';
  const core = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:dcterms="http://purl.org/dc/terms/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"><dc:title>' + x('Capsight findings report: ' + m.file) + '</dc:title><dc:creator>Capsight</dc:creator><dcterms:created xsi:type="dcterms:W3CDTF">' + new Date().toISOString().replace(/\.\d+Z$/, 'Z') + '</dcterms:created></cp:coreProperties>';
  const enc = s => new TextEncoder().encode(s);
  const parts = [{ name: '[Content_Types].xml', data: enc(ct) }, { name: '_rels/.rels', data: enc(rels) }, { name: 'word/document.xml', data: enc(doc) }, { name: 'word/_rels/document.xml.rels', data: enc(drels) }, { name: 'word/styles.xml', data: enc(styles) }, { name: 'docProps/core.xml', data: enc(core) }];
  Object.values(imgs).forEach(i => parts.push({ name: 'word/media/' + i.file, data: i.data }));
  return makeZip(parts);
}

/* ---------- PDF: the web page, printed by the browser ---------- */
function printReport(html) {
  const f = document.createElement('iframe');
  f.setAttribute('aria-hidden', 'true'); f.style.cssText = 'position:fixed;right:0;bottom:0;width:0;height:0;border:0';
  document.body.appendChild(f);
  f.onload = () => { try { f.contentWindow.focus(); f.contentWindow.print(); } catch (e) { toast('Printing is blocked here. Download the web page and print it to PDF instead.'); } setTimeout(() => f.remove(), 60000); };
  f.srcdoc = html;
}

/* ---------- the dialog ---------- */
function openReport() {
  if (!S.cap) return;
  const cap = S.cap, base = cap.name.replace(/\.(pcapng|pcap|cap|gz)$/gi, '').replace(/[^\w.-]+/g, '_') || 'capture';
  const n = cap.threats.length;
  $('#mtitle').textContent = 'Download a findings report';
  $('#mbody').innerHTML = `<div class="rpt">
    <p class="rpt-lead">${n ? `A short write-up of this capture: the verdict, what to do now, the attack flow and network map diagrams, a timeline of all ${n} detection${n > 1 ? 's' : ''} with MITRE ATT&amp;CK, and the indicators, passwords and files that matter.` : 'A short write-up of this capture: what was checked, plus any cleartext passwords and suspicious files. No attacks were detected.'}</p>
    <div class="rpt-grid">
      <button class="rpt-opt" data-fmt="pdf"><b>PDF</b><span>Ready to email or print. Opens your browser’s print window: choose Save as PDF.</span></button>
      <button class="rpt-opt" data-fmt="html"><b>Web page</b><span>One .html file that opens in any browser and prints cleanly.</span></button>
      <button class="rpt-opt" data-fmt="docx"><b>Word</b><span>A .docx you can edit and add notes to.</span></button>
      <button class="rpt-opt" data-fmt="md"><b>Markdown</b><span>Plain text for tickets, GitHub or a wiki.</span></button>
    </div>
    <label class="rpt-secret"><input type="checkbox" id="rptSecrets"> Include passwords and secrets in full <span class="hint">They’re masked unless you tick this.</span></label>
  </div>`;
  $$('.rpt-opt', $('#mbody')).forEach(b => b.onclick = async () => {
    const fmt = b.dataset.fmt; b.disabled = true; const old = b.querySelector('b').textContent; b.querySelector('b').textContent = 'Preparing…';
    try {
      const m = await reportModel({ secrets: $('#rptSecrets').checked });
      const name = 'capsight_' + base + '_report';
      if (fmt === 'md') await offerSave(name + '.md', new Blob([await reportMarkdown(m)], { type: 'text/markdown' }));
      else if (fmt === 'html') await offerSave(name + '.html', new Blob([reportHtml(m)], { type: 'text/html' }));
      else if (fmt === 'docx') await offerSave(name + '.docx', new Blob([await reportDocx(m)], { type: 'application/vnd.openxmlformats-officedocument.wordprocessingml.document' }));
      else printReport(reportHtml(m));
      if ($('#modal').classList.contains('on') && fmt !== 'pdf') toast('Report saved as ' + name + '.' + fmt);
    } catch (e) { toast('Could not make the report: ' + e.message); }
    b.disabled = false; b.querySelector('b').textContent = old;
  });
  $('#modal').classList.add('on');
}
$('#reportBtn').onclick = openReport;
