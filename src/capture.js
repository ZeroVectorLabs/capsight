/* ===================== Capture page: record live traffic and keep captures in the browser ===================== */
/* Browsers cannot read a network port, so recording is done by Capsight Capture (capture/capsight_capture.py),
   a small helper running on this computer at 127.0.0.1:47115. This page is its whole interface: it checks the
   computer, picks the port, starts and stops, shows live counters, and saves finished captures in IndexedDB. */
const CAP_PORT = 47115, CAP_API = 'http://127.0.0.1:' + CAP_PORT;
const CAP_ZIP = 'https://zerovectorlabs.github.io/capsight/capsight-capture.zip';
const CAP_SRC = 'https://github.com/ZeroVectorLabs/capsight/tree/main/capture';
var CP = { on: false, helper: null, state: null, sel: null, timer: 0, spark: [], imported: new Set(), busy: false, lastErr: '', openChecks: false, prevHash: '' };

/* ---------- settings ---------- */
const cpGet = (k, d) => { try { const v = localStorage.getItem('capsight.' + k); return v === null ? d : JSON.parse(v); } catch (e) { return d; } };
const cpSet = (k, v) => { try { localStorage.setItem('capsight.' + k, JSON.stringify(v)); } catch (e) {} };

/* ---------- the small database: IndexedDB in this browser ---------- */
const capDB = (() => {
  let dbp = null;
  const open = () => dbp || (dbp = new Promise((res, rej) => {
    const r = indexedDB.open('capsight', 1);
    r.onupgradeneeded = () => { const db = r.result; if (!db.objectStoreNames.contains('captures')) db.createObjectStore('captures', { keyPath: 'id' }); };
    r.onsuccess = () => res(r.result); r.onerror = () => rej(r.error);
  }));
  const tx = async (mode, fn) => { const db = await open(); return new Promise((res, rej) => { const t = db.transaction('captures', mode), st = t.objectStore('captures'); const out = fn(st); t.oncomplete = () => res(out instanceof IDBRequest ? out.result : out); t.onerror = () => rej(t.error); t.onabort = () => rej(t.error || new Error('Storage aborted')); }); };
  return {
    put: rec => tx('readwrite', st => st.put(rec)),
    get: id => tx('readonly', st => st.get(id)),
    del: id => tx('readwrite', st => st.delete(id)),
    clear: () => tx('readwrite', st => st.clear()),
    list: async () => {
      const db = await open();
      return new Promise((res, rej) => {
        const out = [], t = db.transaction('captures'), c = t.objectStore('captures').openCursor();
        c.onsuccess = () => { const cur = c.result; if (cur) { const { bytes, ...meta } = cur.value; out.push(meta); cur.continue(); } };
        t.oncomplete = () => res(out.sort((a, b) => b.created - a.created)); t.onerror = () => rej(t.error);
      });
    },
  };
})();
async function capExpire() {
  const days = cpGet('keepDays', 7); if (!days) return;
  const cut = Date.now() - days * 864e5;
  for (const r of await capDB.list().catch(() => [])) if (r.created < cut) await capDB.del(r.id).catch(() => {});
}

/* ---------- talking to the helper ---------- */
async function capApi(path, body, binary) {
  const ac = new AbortController(), t = setTimeout(() => ac.abort(), binary ? 60000 : 4000);
  try {
    const r = await fetch(CAP_API + path, body ? { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body), signal: ac.signal, cache: 'no-store' } : { signal: ac.signal, cache: 'no-store' });
    if (binary && r.ok) return await r.arrayBuffer();
    const j = await r.json().catch(() => ({}));
    if (!r.ok) throw Object.assign(new Error(j.error || ('Helper answered ' + r.status)), { status: r.status });
    return j;
  } finally { clearTimeout(t); }
}
async function capPing() { try { return await capApi('/api/ping'); } catch (e) { return null; } }

/* ---------- page show / hide ---------- */
function openCapturePage() {
  if (location.hash !== '#capture') { try { history.pushState({ capture: 1 }, '', '#capture'); } catch (e) { location.hash = 'capture'; } }
  showCapturePage(true);
}
function showCapturePage(on) {
  if (on === CP.on) { if (on) capTick(true); return; }
  CP.on = on;
  $('#capture-page').classList.toggle('on', on);
  if (on) {
    $('#landing').classList.remove('on');
    $$('.view').forEach(x => x.classList.remove('on'));
    ['#filemeta', '#tabs', '#filterbar', '#openBtn2', '#reportBtn', '#strip'].forEach(s => $(s).classList.add('hidden'));
    $('#backBtn').classList.remove('hidden');
    $('#modal').classList.remove('on'); untip(); scrollTo(0, 0);
    capExpire().then(capRenderLib); capRender(); capTick(true);
  } else {
    clearTimeout(CP.timer);
    if (S.cap && !S.home) { showApp(true); route(S.view || 'overview'); } else showApp(false);
  }
}
function leaveCapturePage() {
  if (history.state && history.state.capture) history.back();
  else { try { history.pushState(null, '', location.pathname + location.search + (S.cap && !S.home ? '#' + (S.view || 'overview') : '')); } catch (e) {} showCapturePage(false); }
}

/* ---------- polling ---------- */
async function capTick(full) {
  clearTimeout(CP.timer);
  if (!CP.on) return;
  const ping = await capPing();
  const was = CP.helper;
  CP.helper = ping;
  if (ping) {
    try { CP.state = await capApi('/api/state' + (full || !was ? '?refresh=1' : '')); CP.lastErr = ''; }
    catch (e) { CP.lastErr = e.message; }
    await capImportFinished();
  } else CP.state = null;
  capRender();
  const running = CP.state && CP.state.session && CP.state.session.running;
  CP.timer = setTimeout(() => capTick(false), running ? 700 : ping ? 4000 : 2500);
}
/* a recording that stopped goes into the browser's capture library once */
async function capImportFinished() {
  const s = CP.state && CP.state.session;
  if (!s || s.running || !s.packets || CP.imported.has(s.name)) return;
  CP.imported.add(s.name);
  if (await capDB.get(s.name).catch(() => null)) return;
  try {
    const bytes = await capApi('/api/download?name=' + encodeURIComponent(s.name), null, true);
    await capDB.put({ id: s.name, name: s.name, iface: s.iface, filter: s.filter, created: Date.now() - s.elapsed * 1000, size: bytes.byteLength, packets: s.packets, protocols: s.protocols, bytes });
    if (!cpGet('keepDisk', false)) capApi('/api/delete', { name: s.name, trash: false }).catch(() => {});
    capRenderLib();
  } catch (e) { if (e.status !== 404) { CP.imported.delete(s.name); toast('Could not save the capture in the browser: ' + e.message); } }
}

/* ---------- rendering ---------- */
const capIfLabel = i => i ? (i.label || i.name) : '';
function capRender() {
  const el = $('#cp-main'); if (!el) return;
  const conn = $('#cp-conn');
  conn.className = 'cp-conn ' + (CP.helper ? 'ok' : '');
  conn.innerHTML = CP.helper ? `<i></i>Capsight Capture ${esc(CP.helper.version)} connected` : '<i></i>Looking for Capsight Capture…';
  if (!CP.helper) { el.innerHTML = capSetupHtml(); return; }
  if (!CP.state) { el.innerHTML = `<div class="card cp-card"><p class="cp-muted">${esc(CP.lastErr || 'Connecting…')}</p></div>`; return; }
  const s = CP.state.session;
  if (s && s.running) capRenderRun(el, s);
  else capRenderSetup(el, s);
}
function capSetupHtml() {
  const os = /Mac/i.test(navigator.userAgent) ? 'mac' : /Win/i.test(navigator.userAgent) ? 'win' : 'linux';
  const step = (k, html) => `<li class="${os === k ? 'me' : ''}">${html}</li>`;
  return `<div class="card cp-card"><h2>Start Capsight Capture on this computer</h2>
    <p class="cp-muted">A web page can’t read network ports, so a small open-source helper does the recording. Start it once; everything else happens on this page. Nothing is uploaded.</p>
    <ol class="cp-steps">
      <li><a class="pbtn fill sm" href="${CAP_ZIP}" download>Download Capsight Capture</a> <span class="cp-muted">Mac, Windows and Linux · <a href="${CAP_SRC}" target="_blank" rel="noopener">source on GitHub</a></span></li>
      <li>Unzip it and start it:<ul>
        ${step('mac', '<b>Mac:</b> open <b>Terminal</b>, type <code>bash </code> (with a space), drag <code>Capsight Capture.command</code> into the window, press Return and enter your Mac password.')}
        ${step('win', '<b>Windows:</b> install <a href="https://npcap.com" target="_blank" rel="noopener">Npcap</a>, then double-click <code>Capsight Capture.bat</code> and allow it to run as administrator.')}
        ${step('linux', '<b>Linux:</b> <code>pip install scapy</code>, then <code>sudo python3 capsight_capture.py</code>.')}
      </ul><span class="cp-muted">It needs Python 3 and keeps running in that window.</span></li>
      <li>This page connects on its own. If your browser asks to allow access to devices on your local network, allow it.</li>
    </ol></div>`;
}
function capRenderSetup(el, s) {
  const C = CP.state.capabilities, ifs = C.interfaces || [];
  if (!CP.sel || !ifs.some(i => i.name === CP.sel)) CP.sel = (ifs.find(i => i.default) || ifs.find(i => i.up && i.kind !== 'Loopback') || ifs[0] || {}).name;
  const bad = C.checks.filter(c => !c.ok), openChecks = CP.openChecks || !C.ready;
  const done = s && !s.running && (s.packets || s.error) ? s : null;
  el.innerHTML = `
  <div class="card cp-card cp-checks ${openChecks ? 'open' : ''}">
    <button class="cp-sum" id="cp-sum" aria-expanded="${openChecks}"><span class="cp-badge ${C.ready ? 'ok' : 'bad'}">${C.ready ? '✓' : '!'}</span>
      <span><b>${C.ready ? 'This computer is ready to capture' : 'This computer isn’t ready yet'}</b><span class="cp-muted">${C.checks.length - bad.length} of ${C.checks.length} checks passed${bad.length ? ' · fix the items marked ✕' : ''}</span></span>
      <span class="sp"></span><span class="cp-link" id="cp-recheck">Check again</span><svg class="chev" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M6 9l6 6 6-6"/></svg></button>
    <div class="cp-grid">${C.checks.map(c => `<div class="cp-chk"><i class="${c.ok ? 'y' : 'n'}">${c.ok ? '✓' : '✕'}</i><div><b>${esc(c.label)}</b><span>${esc(c.detail)}</span>${!c.ok && c.fix ? `<code>${esc(c.fix)}</code>` : ''}</div></div>`).join('')}</div>
  </div>
  ${done ? capDoneHtml(done) : ''}
  <div class="card cp-card">
    <h2>New capture</h2>
    <label class="cp-lbl" for="cp-port">Network port</label>
    <div class="cp-select" id="cp-select">
      <button class="cp-sel-btn" id="cp-port" aria-haspopup="listbox" aria-expanded="false">${capIfRow(ifs.find(i => i.name === CP.sel))}<svg class="chev" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M6 9l6 6 6-6"/></svg></button>
      <div class="cp-menu" id="cp-menu" role="listbox" tabindex="-1">${ifs.map(i => `<div class="cp-opt ${i.name === CP.sel ? 'on' : ''} ${i.up === false ? 'down' : ''}" role="option" data-n="${esc(i.name)}" aria-selected="${i.name === CP.sel}">${capIfRow(i, true)}</div>`).join('')}</div>
    </div>
    <div class="cp-row">
      <div class="cp-fld cp-grow"><label class="cp-lbl" for="cp-flt">Capture filter <span class="cp-muted">optional</span></label><input id="cp-flt" type="text" spellcheck="false" autocomplete="off" placeholder="${C.filters ? 'All traffic, or e.g. tcp port 443' : 'Filters need libpcap; records all traffic'}" ${C.filters ? '' : 'disabled'} value="${esc(cpGet('filter', ''))}">
        <div class="cp-chips">${[['All traffic', ''], ['Web', 'tcp port 80 or tcp port 443'], ['DNS', 'port 53'], ['Not SSH', 'not port 22'], ['ARP and ping', 'arp or icmp']].map(([l, f]) => `<button class="cp-chip" data-f="${esc(f)}" ${C.filters ? '' : 'disabled'}>${l}</button>`).join('')}</div></div>
      <div class="cp-fld"><label class="cp-lbl">Stop after</label><div class="cp-stop">
        <span><input id="cp-dur" type="number" min="0" placeholder="–" value="${cpGet('dur', '') || ''}"><em>sec</em></span>
        <span><input id="cp-cnt" type="number" min="0" placeholder="–" value="${cpGet('cnt', '') || ''}"><em>packets</em></span>
        <span><input id="cp-mb" type="number" min="0" placeholder="–" value="${cpGet('mb', '') || ''}"><em>MB</em></span></div>
        <div class="cp-muted cp-hint">Leave empty to stop by hand.</div></div>
    </div>
    <div class="cp-foot">
      <label class="cp-switch"><input type="checkbox" id="cp-promisc" ${cpGet('promisc', true) ? 'checked' : ''}><span></span>Promiscuous mode <em class="cp-muted">also see traffic for other devices</em></label>
      <span class="sp"></span>
      <button class="pbtn fill" id="cp-start" ${C.ready && CP.sel ? '' : 'disabled'}><svg viewBox="0 0 24 24" aria-hidden="true"><circle cx="12" cy="12" r="6" fill="currentColor"/></svg>Start capture</button>
    </div>
    <div class="cp-err ${CP.startErr ? '' : 'hidden'}" id="cp-err">${esc(CP.startErr || '')}</div>
  </div>`;
  $('#cp-sum').onclick = e => { if (e.target.id === 'cp-recheck') { capTick(true); return; } CP.openChecks = !$('.cp-checks').classList.contains('open'); $('.cp-checks').classList.toggle('open', CP.openChecks); };
  capWireSelect(ifs);
  $$('.cp-chip').forEach(c => c.onclick = () => { $('#cp-flt').value = c.dataset.f; cpSet('filter', c.dataset.f); });
  $('#cp-flt').oninput = e => cpSet('filter', e.target.value);
  [['#cp-dur', 'dur'], ['#cp-cnt', 'cnt'], ['#cp-mb', 'mb']].forEach(([s, k]) => $(s).oninput = e => cpSet(k, +e.target.value || ''));
  $('#cp-promisc').onchange = e => cpSet('promisc', e.target.checked);
  $('#cp-start').onclick = capStart;
  if (done) capWireDone(done);
}
function capIfRow(i, full) {
  if (!i) return '<span class="cp-muted">No network ports found</span>';
  const speed = i.speed ? (i.speed >= 1000 ? i.speed / 1000 + ' Gb/s' : i.speed + ' Mb/s') : '';
  return `<span class="cp-ifrow"><i class="dot ${i.up ? 'up' : i.up === false ? 'down' : ''}"></i><b>${esc(capIfLabel(i))}</b><span class="cp-tag k-${esc(i.kind)}">${esc(i.kind)}</span>${i.default ? '<span class="cp-tag def">internet</span>' : ''}
    <span class="cp-ifmeta">${esc(i.ipv4 || 'no IPv4')}${full ? ` · ${esc(i.mac || '')}${speed ? ' · ' + speed : ''}${i.traffic != null ? ' · ' + fmtBytes(i.traffic) + ' so far' : ''}` : ''}</span>
    ${full && i.description ? `<span class="cp-ifdesc">${esc(i.description)}</span>` : ''}</span>`;
}
function capWireSelect(ifs) {
  const wrap = $('#cp-select'), btn = $('#cp-port'), menu = $('#cp-menu');
  const open = on => { wrap.classList.toggle('open', on); btn.setAttribute('aria-expanded', on); if (on) { const cur = menu.querySelector('.cp-opt.on'); cur && cur.scrollIntoView({ block: 'nearest' }); menu.focus(); } };
  const pick = n => { CP.sel = n; btn.innerHTML = capIfRow(ifs.find(i => i.name === n)) + '<svg class="chev" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M6 9l6 6 6-6"/></svg>'; $$('.cp-opt', menu).forEach(o => { o.classList.toggle('on', o.dataset.n === n); o.setAttribute('aria-selected', o.dataset.n === n); }); open(false); btn.focus(); };
  btn.onclick = () => open(!wrap.classList.contains('open'));
  $$('.cp-opt', menu).forEach(o => o.onclick = () => pick(o.dataset.n));
  menu.onkeydown = e => {
    const opts = $$('.cp-opt', menu); let k = opts.findIndex(o => o.classList.contains('hi')); if (k < 0) k = opts.findIndex(o => o.classList.contains('on'));
    if (e.key === 'ArrowDown' || e.key === 'ArrowUp') { e.preventDefault(); k = Math.max(0, Math.min(opts.length - 1, k + (e.key === 'ArrowDown' ? 1 : -1))); opts.forEach((o, j) => o.classList.toggle('hi', j === k)); opts[k].scrollIntoView({ block: 'nearest' }); }
    else if (e.key === 'Enter' && opts[k]) { e.preventDefault(); pick(opts[k].dataset.n); }
    else if (e.key === 'Escape') { e.stopPropagation(); open(false); btn.focus(); }
  };
  document.addEventListener('click', e => { if (wrap.isConnected && !wrap.contains(e.target)) open(false); });
}
async function capStart() {
  const b = $('#cp-start'); b.disabled = true; CP.startErr = ''; CP.spark = [];
  try {
    await capApi('/api/start', { iface: CP.sel, filter: $('#cp-flt').value, duration: +$('#cp-dur').value || 0, count: +$('#cp-cnt').value || 0, maxMb: +$('#cp-mb').value || 0, promisc: $('#cp-promisc').checked });
    capTick(false);
  } catch (e) { CP.startErr = e.message; const er = $('#cp-err'); er.textContent = e.message; er.classList.remove('hidden'); b.disabled = false; }
}
function capRenderRun(el, s) {
  CP.spark.push(s.pps); if (CP.spark.length > 90) CP.spark.shift();
  if (!$('#cp-run')) {
    el.innerHTML = `<div class="card cp-card" id="cp-run">
      <div class="cp-runhead"><span class="cp-rec"><i></i>Recording</span><span class="cp-muted" id="cp-on"></span><span class="sp"></span><button class="pbtn stop" id="cp-stop"><svg viewBox="0 0 24 24" aria-hidden="true"><rect x="7" y="7" width="10" height="10" rx="2" fill="currentColor"/></svg>Stop and save</button></div>
      <div class="cp-stats"><div><small>Packets</small><b id="cp-p">0</b></div><div><small>Data</small><b id="cp-b">0 B</b></div><div><small>Rate</small><b id="cp-r">0</b></div><div><small>Time</small><b id="cp-t">0:00</b></div></div>
      <canvas id="cp-spark" height="70"></canvas>
      <div class="cp-bars"><div><h3>Protocols</h3><div id="cp-pr"></div></div><div><h3>Busiest addresses</h3><div id="cp-tk"></div></div></div></div>`;
    $('#cp-stop').onclick = async () => { $('#cp-stop').disabled = true; await capApi('/api/stop', {}).catch(e => toast(e.message)); capTick(false); };
  }
  const lim = s.limits || {};
  $('#cp-on').textContent = 'on ' + s.iface + (s.filter ? ' · ' + s.filter : '') + (lim.duration ? ' · stops after ' + lim.duration + ' s' : lim.count ? ' · stops after ' + fmtNum(lim.count) + ' packets' : lim.max_mb ? ' · stops at ' + lim.max_mb + ' MB' : '');
  $('#cp-p').textContent = fmtNum(s.packets); $('#cp-b').textContent = fmtBytes(s.bytes);
  $('#cp-r').textContent = fmtNum(Math.round(s.pps)) + '/s'; $('#cp-t').textContent = capClock(s.elapsed);
  const bars = (rows, f) => rows.length ? rows.map(([k, v]) => `<div class="cp-bar"><span title="${esc(k)}">${esc(k)}</span><i><u style="width:${Math.max(2, v / rows[0][1] * 100)}%"></u></i><em>${f(v)}</em></div>`).join('') : '<div class="cp-muted">Waiting for packets…</div>';
  $('#cp-pr').innerHTML = bars(s.protocols, fmtNum); $('#cp-tk').innerHTML = bars(s.talkers, fmtBytes);
  capDrawSpark();
}
function capDrawSpark() {
  const c = $('#cp-spark'); if (!c) return;
  const w = c.clientWidth, h = 70, dpr = devicePixelRatio || 1; c.width = w * dpr; c.height = h * dpr;
  const g = c.getContext('2d'); g.scale(dpr, dpr);
  const css = getComputedStyle(document.documentElement), line = css.getPropertyValue('--btn').trim() || '#1fa6dd', grid = css.getPropertyValue('--line').trim();
  g.strokeStyle = grid; g.lineWidth = 1; g.beginPath(); g.moveTo(0, h - .5); g.lineTo(w, h - .5); g.stroke();
  const d = CP.spark, max = Math.max(1, ...d); if (d.length < 2) return;
  const x = i => i / 89 * w, y = v => h - 4 - v / max * (h - 12);
  const grad = g.createLinearGradient(0, 0, 0, h); grad.addColorStop(0, line + '55'); grad.addColorStop(1, line + '00');
  g.beginPath(); g.moveTo(x(0), h); d.forEach((v, i) => g.lineTo(x(i), y(v))); g.lineTo(x(d.length - 1), h); g.closePath(); g.fillStyle = grad; g.fill();
  g.beginPath(); d.forEach((v, i) => i ? g.lineTo(x(i), y(v)) : g.moveTo(x(i), y(v))); g.strokeStyle = line; g.lineWidth = 2; g.stroke();
  g.fillStyle = css.getPropertyValue('--muted').trim(); g.font = '11px DM Sans, sans-serif'; g.textAlign = 'right'; g.fillText('peak ' + fmtNum(Math.round(max)) + ' pkt/s', w - 2, 11);
}
const capClock = s => { s = Math.floor(s || 0); return s >= 3600 ? Math.floor(s / 3600) + ':' + String(Math.floor(s / 60) % 60).padStart(2, '0') + ':' + String(s % 60).padStart(2, '0') : Math.floor(s / 60) + ':' + String(s % 60).padStart(2, '0'); };
function capDoneHtml(s) {
  return `<div class="card cp-card cp-done ${s.error && !s.packets ? 'bad' : ''}"><div class="cp-donehead"><span class="cp-badge ${s.packets ? 'ok' : 'bad'}">${s.packets ? '✓' : '!'}</span>
    <div><b>${esc(s.stop_reason || 'Stopped')}. ${s.packets ? fmtNum(s.packets) + ' packets, ' + fmtBytes(s.size || s.bytes) + ' on ' + esc(s.iface) + '.' : 'Nothing was recorded.'}</b>
    <span class="cp-muted">${s.error ? esc(s.error) : s.packets ? 'Saved in this browser under Saved captures.' : 'Try another port, or remove the filter.'}</span></div><span class="sp"></span>
    ${s.packets ? `<button class="pbtn fill sm" data-act="open" data-id="${esc(s.name)}">Open in Capsight</button><button class="pbtn line sm" data-act="dl" data-id="${esc(s.name)}">Download .pcap</button><button class="pbtn line sm danger" data-act="del" data-id="${esc(s.name)}">Delete</button>` : ''}</div></div>`;
}
function capWireDone() { $$('.cp-done [data-act]').forEach(b => b.onclick = () => capAction(b.dataset.act, b.dataset.id, b)); }

/* ---------- saved captures (the browser library) ---------- */
async function capRenderLib() {
  const el = $('#cp-lib'); if (!el) return;
  const list = await capDB.list().catch(e => { el.innerHTML = `<p class="cp-err">This browser won't let Capsight store captures: ${esc(e.message)}</p>`; return null; });
  if (!list) return;
  let used = '';
  try { const est = await navigator.storage.estimate(); used = fmtBytes(list.reduce((a, r) => a + (r.size || 0), 0)) + ' used'; void est; } catch (e) {}
  const days = cpGet('keepDays', 7);
  el.innerHTML = `<div class="cp-libhead"><h2>Saved captures</h2><span class="cp-muted">${list.length ? list.length + ' in this browser · ' + used : 'Nothing saved yet'}</span><span class="sp"></span>
    <label class="cp-muted cp-keep">Keep for <select id="cp-days">${[[1, '1 day'], [7, '7 days'], [30, '30 days'], [0, 'until I delete them']].map(([v, l]) => `<option value="${v}" ${v === days ? 'selected' : ''}>${l}</option>`).join('')}</select></label>
    <label class="cp-switch sm" title="Also keep each capture as a .pcap file in the helper's Captures folder"><input type="checkbox" id="cp-disk" ${cpGet('keepDisk', false) ? 'checked' : ''}><span></span>Keep a copy on disk</label>
    ${list.length ? '<button class="cp-link danger" id="cp-clear">Delete all</button>' : ''}</div>
    ${list.length ? `<div class="cp-list">${list.map(r => `<div class="cp-item" data-id="${esc(r.id)}">
      <div class="cp-iname"><b title="${esc(r.name)}">${esc(r.name.replace(/^capsight_/, '').replace(/\.pcap$/, ''))}</b><span class="cp-muted">${esc(r.iface || '')}${r.filter ? ' · ' + esc(r.filter) : ''}</span></div>
      <span class="cp-muted">${new Date(r.created).toLocaleString([], { dateStyle: 'medium', timeStyle: 'short' })}</span>
      <span class="cp-num">${fmtNum(r.packets || 0)} pkts</span><span class="cp-num">${fmtBytes(r.size)}</span>
      <span class="cp-acts"><button class="pbtn fill sm" data-act="open" data-id="${esc(r.id)}">Open</button><button class="cp-ico" data-act="dl" data-id="${esc(r.id)}" title="Download .pcap" aria-label="Download .pcap"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 4v11M7 10l5 5 5-5M5 20h14"/></svg></button><button class="cp-ico danger" data-act="del" data-id="${esc(r.id)}" title="Delete" aria-label="Delete"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M4 7h16M10 11v6M14 11v6M6 7l1 13h10l1-13M9 7V4h6v3"/></svg></button></span>
    </div>`).join('')}</div>` : '<p class="cp-muted cp-empty">Captures you record are kept here, in this browser only, so you can open them again.</p>'}`;
  $('#cp-days').onchange = e => { cpSet('keepDays', +e.target.value); capExpire().then(capRenderLib); };
  $('#cp-disk').onchange = e => cpSet('keepDisk', e.target.checked);
  if ($('#cp-clear')) $('#cp-clear').onclick = async () => { if (!confirm('Delete all ' + list.length + ' saved captures from this browser?')) return; await capDB.clear(); capRenderLib(); toast('Deleted all saved captures'); };
  $$('#cp-lib [data-act]').forEach(b => b.onclick = () => capAction(b.dataset.act, b.dataset.id, b));
}
async function capAction(act, id, btn) {
  const rec = await capDB.get(id).catch(() => null);
  if (act === 'del') {
    if (!confirm('Delete ' + id + '? It is removed from this browser' + (CP.helper ? ' and from the helper’s folder.' : '.'))) return;
    await capDB.del(id).catch(() => {});
    if (CP.helper) capApi('/api/delete', { name: id, trash: true }).catch(() => {});
    if (CP.state && CP.state.session && CP.state.session.name === id) { CP.state.session = null; capRender(); }
    capRenderLib(); toast('Deleted ' + id); return;
  }
  let bytes = rec && rec.bytes;
  if (!bytes && CP.helper) bytes = await capApi('/api/download?name=' + encodeURIComponent(id), null, true).catch(() => null);
  if (!bytes) { toast('That capture is not available any more.'); return; }
  if (act === 'dl') { await offerSave(id, new Blob([bytes], { type: 'application/vnd.tcpdump.pcap' })); return; }
  if (act === 'open') { if (btn) btn.disabled = true; capHideQuiet(); await openFile(new File([bytes], id)); }
}

/* called by the app when it shows the start page or a capture, so this page steps aside quietly */
function capHideQuiet() { if (CP && CP.on) { CP.on = false; $('#capture-page').classList.remove('on'); clearTimeout(CP.timer); } }

/* ---------- wiring ---------- */
$$('[data-capture]').forEach(b => b.onclick = openCapturePage);
window.addEventListener('hashchange', () => { if (location.hash === '#capture') showCapturePage(true); else if (CP.on) showCapturePage(false); });
window.addEventListener('resize', () => { if (CP.on) capDrawSpark(); });
if (location.hash === '#capture') setTimeout(() => showCapturePage(true), 0);
