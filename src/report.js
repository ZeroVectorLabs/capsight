/* ===================== Findings report: PDF, web page, Word and Markdown ===================== */
const utcStamp = t => new Date(t * 1000).toISOString().replace('T', ' ').replace(/\.\d+Z$/, ' UTC');
const maskSecret = s => { s = String(s ?? ''); return s.length <= 2 ? '••••' : s[0] + '•'.repeat(Math.min(8, s.length - 2)) + s[s.length - 1]; };

/* One model, four renderers: everything the report says comes from here. */
async function reportModel(opts = {}) {
  const cap = S.cap;
  ensureArt(); if (cap.artP) await cap.artP;
  const A = cap.art || { files: [], creds: [], iocs: { ips: [], domains: [], urls: [], uas: [], emails: [], hashes: [] }, inv: [] };
  const D = cap.threats || [], F = cap.flow, ag = aggregate(cap, null);
  const sev = { critical: 0, high: 0, medium: 0, low: 0 }; D.forEach(d => sev[d.sev]++);
  const sevLine = Object.entries(sev).filter(([, n]) => n).map(([k, n]) => n + ' ' + k).join(', ');
  const stageName = k => (STAGES.find(s => s.k === k) || { name: k }).name;
  return {
    title: 'Capsight findings report',
    generated: utcStamp(Date.now() / 1000),
    capture: [
      ['File', cap.name],
      ['Packets', fmtNum(cap.pk.length)],
      ['Size', fmtBytes(cap.size)],
      ['Time span', utcStamp(cap.t0) + ' to ' + utcStamp(cap.t1) + ' (' + fmtDur(cap.dur) + ')'],
      ['Hosts seen', fmtNum(ag.hosts.size)],
    ],
    clean: !D.length,
    verdict: D.length ? D.length + ' security detection' + (D.length > 1 ? 's' : '') + ': ' + sevLine + '.' : 'No attacks detected.',
    summary: D.length ? (F && F.story) || '' : 'Capsight checked ' + fmtNum(cap.pk.length) + ' packets for port scans, host sweeps, brute force, web exploits, shells, beaconing, DNS tunnelling, exfiltration, ARP spoofing and floods, and found none. This does not prove the network is safe; it means nothing in this capture matched a known attack pattern.',
    sev,
    tactics: F ? F.stages.filter(s => s.n).map(s => [s.ta, s.name, String(s.n)]) : [],
    steps: (F ? F.steps : D.map(d => ({ d, src: d.src, dst: d.dst }))).map((s, i) => ({
      n: i + 1, sev: s.d.sev, title: s.d.title, tactic: stageName(s.d.stage), tech: s.d.tech || '', techName: s.d.techName || '',
      src: String(s.src ?? ''), dst: String(s.dst ?? ''), rel: '+' + Math.max(0, s.d.t0 - cap.t0).toFixed(1) + 's', utc: utcStamp(s.d.t0), summary: s.d.summary || '' })),
    actors: F ? F.lanes.filter(l => !['Internal host', 'External host', 'Internal network'].includes(l.role)).map(l => [l.id, l.role]) : [],
    hosts: A.inv.filter(h => h.internal || hostRole(h.ip)).slice(0, 30).map(h => [h.ip, hostRole(h.ip) || (h.internal ? 'Local' : 'Internet'), h.names[0] || '', h.os || '', h.ports.slice(0, 6).join(', ')]),
    iocs: {
      ips: A.iocs.ips.slice(0, 40).map(o => [o.v, hostRole(o.v) || (o.bad ? 'Linked to a detection' : ''), fmtNum(o.n), fmtBytes(o.bytes)]),
      domains: A.iocs.domains.slice(0, 40).map(o => [o.v, o.bad ? 'Linked to a detection' : '', o.src || '']),
      urls: A.iocs.urls.slice(0, 40).map(o => [o.v, o.method || '', String(o.status || '')]),
    },
    files: A.files.filter(f => f.interesting).map(f => [f.name, f.type.label, fmtBytes(f.size), f.occ[0].src + ' → ' + f.occ[0].dst, f.flags.map(x => x.t).join('; '), f.sha256]),
    creds: A.creds.map(c => [utcStamp(c.t), c.proto, c.src + ' → ' + c.dst, c.user || '', opts.secrets ? String(c.pw ?? '') : maskSecret(c.pw), c.extra || '']),
    secrets: !!opts.secrets,
  };
}

const RPT_COLS = {
  capture: ['', ''],
  tactics: ['ID', 'Tactic', 'Detections'],
  steps: ['#', 'Severity', 'What happened', 'Tactic', 'Technique', 'From', 'To', 'When'],
  actors: ['Address', 'Role'],
  hosts: ['Address', 'Role', 'Name', 'Likely OS', 'Services'],
  ips: ['Address', 'Note', 'Packets', 'Bytes'],
  domains: ['Domain', 'Note', 'Seen in'],
  urls: ['URL', 'Method', 'Status'],
  files: ['File', 'Type', 'Size', 'From → to', 'Flags', 'SHA-256'],
  creds: ['Time', 'Protocol', 'Client → server', 'Username', 'Secret', 'Where'],
};
const stepRow = s => [String(s.n), SEV_LABEL[s.sev] || s.sev, s.title, s.tactic, s.tech, s.src, s.dst, s.rel];
/* the sections, in order, shared by every renderer */
function reportSections(m) {
  const out = [];
  out.push({ h: 'Summary', p: [m.verdict, m.summary].filter(Boolean) });
  out.push({ h: 'Capture', table: 'capture', rows: m.capture, kv: true });
  if (!m.clean) {
    out.push({ h: 'Attack steps', p: ['Every detection in the order it happened, mapped to MITRE ATT&CK. Times are from the start of the capture.'], table: 'steps', rows: m.steps.map(stepRow), details: m.steps });
    if (m.tactics.length) out.push({ h: 'ATT&CK tactics', table: 'tactics', rows: m.tactics });
    if (m.actors.length) out.push({ h: 'Who was involved', table: 'actors', rows: m.actors });
  }
  if (m.hosts.length) out.push({ h: 'Local and flagged hosts', table: 'hosts', rows: m.hosts });
  out.push({ h: 'Indicators', sub: [
    { h: 'External IP addresses', table: 'ips', rows: m.iocs.ips },
    { h: 'Domains', table: 'domains', rows: m.iocs.domains },
    { h: 'URLs', table: 'urls', rows: m.iocs.urls }] });
  out.push({ h: 'Recovered files', p: m.files.length ? ['Files carved from the traffic that are worth a closer look, with SHA-256 hashes for threat-intel lookups.'] : ['No notable files were recovered.'], table: 'files', rows: m.files });
  out.push({ h: 'Credentials seen in clear text', p: m.creds.length ? [m.secrets ? 'Secrets are shown in full. Handle this report as sensitive.' : 'Secrets are masked. Capsight can include them in full if you choose that option when you make the report.'] : ['No cleartext credentials were seen.'], table: 'creds', rows: m.creds });
  return out;
}

/* ---------- Markdown ---------- */
function reportMarkdown(m) {
  const cell = v => String(v ?? '').replace(/\|/g, '\\|').replace(/\n/g, ' ');
  const tbl = (key, rows, kv) => rows.length ? (kv ? '| | |\n|---|---|\n' + rows.map(r => '| **' + cell(r[0]) + '** | ' + cell(r[1]) + ' |').join('\n')
    : '| ' + RPT_COLS[key].join(' | ') + ' |\n|' + RPT_COLS[key].map(() => '---').join('|') + '|\n' + rows.map(r => '| ' + r.map(cell).join(' | ') + ' |').join('\n')) + '\n' : '_None found._\n';
  let s = '# ' + m.title + '\n\nGenerated ' + m.generated + ' by Capsight, which analysed the capture in the browser. Nothing was uploaded.\n\n';
  const sec = (x, lvl) => {
    s += '#'.repeat(lvl) + ' ' + x.h + '\n\n';
    (x.p || []).forEach(p => s += p + '\n\n');
    if (x.table) s += tbl(x.table, x.rows, x.kv) + '\n';
    if (x.details) x.details.filter(d => d.summary).forEach(d => s += '- **' + d.n + '. ' + d.title + '** (' + d.utc + '): ' + d.summary + '\n');
    if (x.details) s += '\n';
    (x.sub || []).forEach(y => sec(y, lvl + 1));
  };
  reportSections(m).forEach(x => sec(x, 2));
  return s;
}

/* ---------- web page (also the source of the PDF) ---------- */
function reportHtml(m) {
  const sevCls = v => ({ Critical: 'c', High: 'h', Medium: 'm', Low: 'l' })[v] || '';
  const tbl = (key, rows, kv) => !rows.length ? '<p class="none">None found.</p>' : kv
    ? '<table class="kv">' + rows.map(r => '<tr><th>' + esc(r[0]) + '</th><td>' + esc(r[1]) + '</td></tr>').join('') + '</table>'
    : '<table><thead><tr>' + RPT_COLS[key].map(h => '<th>' + esc(h) + '</th>').join('') + '</tr></thead><tbody>' + rows.map(r => '<tr>' + r.map((v, i) => key === 'steps' && i === 1 ? '<td><span class="sev ' + sevCls(v) + '">' + esc(v) + '</span></td>' : '<td' + (/sha|URL|Address|Domain/.test(RPT_COLS[key][i]) ? ' class="mono"' : '') + '>' + esc(v) + '</td>').join('') + '</tr>').join('') + '</tbody></table>';
  const sec = (x, lvl) => '<section><h' + lvl + '>' + esc(x.h) + '</h' + lvl + '>' + (x.p || []).map((p, i) => '<p' + (x.h === 'Summary' && !i ? ' class="verdict ' + (m.clean ? 'ok' : 'bad') + '"' : '') + '>' + esc(p) + '</p>').join('')
    + (x.table ? tbl(x.table, x.rows, x.kv) : '')
    + (x.details ? '<ol class="det">' + x.details.filter(d => d.summary).map(d => '<li value="' + d.n + '"><b>' + esc(d.title) + '</b> <span class="t">' + esc(d.utc) + '</span><br>' + esc(d.summary) + '</li>').join('') + '</ol>' : '')
    + (x.sub || []).map(y => sec(y, lvl + 1)).join('') + '</section>';
  const logo = ($('#brand img') || {}).src || '';
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${esc(m.title)} — ${esc(m.capture[0][1])}</title><style>
@page{margin:16mm 14mm}*{box-sizing:border-box}body{margin:0;background:#f2f7ff;color:#0b1b33;font:14px/1.55 -apple-system,BlinkMacSystemFont,"Segoe UI",Helvetica,Arial,sans-serif}
.page{max-width:1000px;margin:0 auto;padding:44px 40px 60px;background:#fff}header{display:flex;align-items:center;gap:14px;border-bottom:1px solid #dbe5f2;padding-bottom:18px}
header img{width:40px;height:40px}header h1{margin:0;font-size:26px;letter-spacing:-.02em}header p{margin:2px 0 0;color:#5a6b85;font-size:13px}
h2{font-size:19px;margin:34px 0 10px;letter-spacing:-.01em}h3{font-size:15px;margin:20px 0 8px}p{margin:0 0 10px;max-width:75ch}
.verdict{font-size:18px;font-weight:600;padding:12px 16px;border-radius:12px}.verdict.bad{background:#fdecef;color:#a3233a}.verdict.ok{background:#e8f6ee;color:#17663e}
table{width:100%;border-collapse:collapse;font-size:12.5px;margin:6px 0 12px}th,td{text-align:left;padding:6px 8px;border-bottom:1px solid #e3ebf5;vertical-align:top}
thead th{color:#3d4f6b;font-weight:600;border-bottom:1.5px solid #c5d3e6}.kv th{width:150px;color:#3d4f6b;font-weight:600}.mono{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:12px;word-break:break-all}
.sev{display:inline-block;padding:1px 8px;border-radius:999px;font-weight:600;font-size:11.5px}.sev.c{background:#fdecef;color:#b42340}.sev.h{background:#fdf0e8;color:#a4481f}.sev.m{background:#fdf6e3;color:#8a6410}.sev.l{background:#eef1f6;color:#4a5568}
ol.det{padding-left:22px;font-size:13px}ol.det li{margin:0 0 8px}ol.det .t{color:#5a6b85;font-size:12px}.none{color:#5a6b85}
footer{margin-top:40px;border-top:1px solid #dbe5f2;padding-top:14px;color:#5a6b85;font-size:12px}
@media print{body{background:#fff}.page{padding:0;max-width:none}section{break-inside:auto}tr,li{break-inside:avoid}h2,h3{break-after:avoid}}
</style></head><body><div class="page"><header>${logo ? `<img src="${logo}" alt="">` : ''}<div><h1>${esc(m.title)}</h1><p>${esc(m.capture[0][1])}, generated ${esc(m.generated)}</p></div></header>
${reportSections(m).map(x => sec(x, 2)).join('')}
<footer>Made with Capsight, which analysed this capture in the browser; nothing was uploaded. Detections are leads for an analyst to confirm, not proof.</footer></div></body></html>`;
}

/* ---------- Word (.docx), written as plain WordprocessingML ---------- */
function reportDocx(m) {
  const x = s => String(s ?? '').replace(/[&<>"]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
  const run = (t, o = {}) => '<w:r>' + (o.b || o.color || o.mono || o.sz ? '<w:rPr>' + (o.mono ? '<w:rFonts w:ascii="Consolas" w:hAnsi="Consolas"/>' : '') + (o.b ? '<w:b/>' : '') + (o.color ? '<w:color w:val="' + o.color + '"/>' : '') + (o.sz ? '<w:sz w:val="' + o.sz + '"/>' : '') + '</w:rPr>' : '') + '<w:t xml:space="preserve">' + x(t) + '</w:t></w:r>';
  const para = (t, style, o) => '<w:p>' + (style ? '<w:pPr><w:pStyle w:val="' + style + '"/></w:pPr>' : '') + run(t, o) + '</w:p>';
  const sevColor = { Critical: 'B42340', High: 'A4481F', Medium: '8A6410', Low: '4A5568' };
  const cellP = (v, o) => '<w:tc><w:p><w:pPr><w:spacing w:before="20" w:after="20"/></w:pPr>' + run(v, Object.assign({ sz: 17 }, o)) + '</w:p></w:tc>';
  const table = (key, rows, kv) => {
    if (!rows.length) return para('None found.', null, { color: '5A6B85' });
    const head = kv ? '' : '<w:tr><w:trPr><w:tblHeader/></w:trPr>' + RPT_COLS[key].map(h => cellP(h, { b: true })).join('') + '</w:tr>';
    const body = rows.map(r => '<w:tr><w:trPr><w:cantSplit/></w:trPr>' + r.map((v, i) => cellP(v, kv && !i ? { b: true } : key === 'steps' && i === 1 ? { b: true, color: sevColor[v] } : /SHA|URL/.test(RPT_COLS[key][i] || '') ? { mono: true } : {})).join('') + '</w:tr>').join('');
    return '<w:tbl><w:tblPr><w:tblStyle w:val="ReportTable"/><w:tblW w:w="5000" w:type="pct"/></w:tblPr>' + head + body + '</w:tbl>' + para('');
  };
  const sec = (s, lvl) => para(s.h, 'Heading' + lvl) + (s.p || []).map((p, i) => para(p, null, s.h === 'Summary' && !i ? { b: true, sz: 26, color: m.clean ? '17663E' : 'A3233A' } : {})).join('')
    + (s.table ? table(s.table, s.rows, s.kv) : '')
    + (s.details ? s.details.filter(d => d.summary).map(d => '<w:p><w:pPr><w:spacing w:after="80"/></w:pPr>' + run(d.n + '. ' + d.title, { b: true, sz: 19 }) + run('  ' + d.utc, { color: '5A6B85', sz: 17 }) + '<w:r><w:br/></w:r>' + run(d.summary, { sz: 19 }) + '</w:p>').join('') : '')
    + (s.sub || []).map(y => sec(y, lvl + 1)).join('');
  const body = para(m.title, 'Title') + para(m.capture[0][1] + ', generated ' + m.generated, null, { color: '5A6B85' })
    + reportSections(m).map(s => sec(s, 1)).join('')
    + para('Made with Capsight, which analysed this capture in the browser; nothing was uploaded. Detections are leads for an analyst to confirm, not proof.', null, { color: '5A6B85', sz: 17 });
  const W = 'xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"';
  const doc = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><w:document ' + W + '><w:body>' + body
    + '<w:sectPr><w:pgSz w:w="11906" w:h="16838"/><w:pgMar w:top="1000" w:right="900" w:bottom="1000" w:left="900" w:header="500" w:footer="500" w:gutter="0"/></w:sectPr></w:body></w:document>';
  const st = (id, name, ppr, rpr, extra = '') => '<w:style w:type="paragraph" w:styleId="' + id + '"><w:name w:val="' + name + '"/><w:basedOn w:val="Normal"/><w:next w:val="Normal"/>' + extra + '<w:pPr>' + ppr + '</w:pPr><w:rPr>' + rpr + '</w:rPr></w:style>';
  const styles = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><w:styles ' + W + '>'
    + '<w:docDefaults><w:rPrDefault><w:rPr><w:rFonts w:ascii="Calibri" w:hAnsi="Calibri" w:cs="Calibri"/><w:sz w:val="21"/><w:color w:val="0B1B33"/></w:rPr></w:rPrDefault><w:pPrDefault><w:pPr><w:spacing w:after="120" w:line="276" w:lineRule="auto"/></w:pPr></w:pPrDefault></w:docDefaults>'
    + '<w:style w:type="paragraph" w:default="1" w:styleId="Normal"><w:name w:val="Normal"/></w:style>'
    + st('Title', 'Title', '<w:spacing w:after="60"/>', '<w:b/><w:sz w:val="44"/>')
    + st('Heading1', 'heading 1', '<w:keepNext/><w:spacing w:before="360" w:after="120"/><w:outlineLvl w:val="0"/>', '<w:b/><w:sz w:val="30"/><w:color w:val="0B2A55"/>', '<w:uiPriority w:val="9"/><w:qFormat/>')
    + st('Heading2', 'heading 2', '<w:keepNext/><w:spacing w:before="240" w:after="80"/><w:outlineLvl w:val="1"/>', '<w:b/><w:sz w:val="24"/><w:color w:val="0B2A55"/>', '<w:uiPriority w:val="9"/><w:qFormat/>')
    + '<w:style w:type="table" w:styleId="ReportTable"><w:name w:val="Report Table"/><w:tblPr><w:tblBorders><w:bottom w:val="single" w:sz="4" w:color="C5D3E6"/><w:insideH w:val="single" w:sz="4" w:color="E3EBF5"/></w:tblBorders><w:tblCellMar><w:left w:w="80" w:type="dxa"/><w:right w:w="80" w:type="dxa"/></w:tblCellMar></w:tblPr></w:style>'
    + '</w:styles>';
  const ct = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/><Override PartName="/word/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.styles+xml"/><Override PartName="/docProps/core.xml" ContentType="application/vnd.openxmlformats-package.core-properties+xml"/></Types>';
  const rels = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/><Relationship Id="rId2" Type="http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties" Target="docProps/core.xml"/></Relationships>';
  const drels = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/></Relationships>';
  const core = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:dcterms="http://purl.org/dc/terms/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"><dc:title>' + x(m.title + ' — ' + m.capture[0][1]) + '</dc:title><dc:creator>Capsight</dc:creator><dcterms:created xsi:type="dcterms:W3CDTF">' + new Date().toISOString().replace(/\.\d+Z$/, 'Z') + '</dcterms:created></cp:coreProperties>';
  const enc = s => new TextEncoder().encode(s);
  return makeZip([{ name: '[Content_Types].xml', data: enc(ct) }, { name: '_rels/.rels', data: enc(rels) }, { name: 'word/document.xml', data: enc(doc) }, { name: 'word/_rels/document.xml.rels', data: enc(drels) }, { name: 'word/styles.xml', data: enc(styles) }, { name: 'docProps/core.xml', data: enc(core) }]);
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
    <p class="rpt-lead">${n ? `A write-up of this capture: the summary, all ${n} detection${n > 1 ? 's' : ''} in order with MITRE ATT&amp;CK, the hosts involved, indicators, recovered files and cleartext credentials.` : 'A write-up of this capture: what was checked, the hosts, indicators, recovered files and any cleartext credentials. No attacks were detected.'}</p>
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
      if (fmt === 'md') await offerSave(name + '.md', new Blob([reportMarkdown(m)], { type: 'text/markdown' }));
      else if (fmt === 'html') await offerSave(name + '.html', new Blob([reportHtml(m)], { type: 'text/html' }));
      else if (fmt === 'docx') await offerSave(name + '.docx', new Blob([reportDocx(m)], { type: 'application/vnd.openxmlformats-officedocument.wordprocessingml.document' }));
      else printReport(reportHtml(m));
      if ($('#modal').classList.contains('on') && fmt !== 'pdf') toast('Report saved as ' + name + '.' + fmt);
    } catch (e) { toast('Could not make the report: ' + e.message); }
    b.disabled = false; b.querySelector('b').textContent = old;
  });
  $('#modal').classList.add('on');
}
$('#reportBtn').onclick = openReport;
