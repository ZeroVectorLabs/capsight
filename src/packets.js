/* ===================== PACKETS ===================== */
// The packet list, details and bytes, with the Wireshark habits people expect:
// right-click to filter, mark, ignore, set a time reference, colourise or follow;
// sortable columns, colouring rules, time formats, go to packet, find, and export.
let RH = 28;
const PHONE = () => matchMedia('(max-width: 640px)').matches;
const PK_COLS = ['no', 'time', 'src', 'dst', 'proto', 'len', 'info'];
const PK_COL_NAME = { no: 'No.', time: 'Time', src: 'Source', dst: 'Destination', proto: 'Protocol', len: 'Length', info: 'Info' };
const PI = {
  up: '<path d="M18 15l-6-6-6 6"/>', down: '<path d="M6 9l6 6 6-6"/>',
  first: '<path d="M17 18l-6-6 6-6M7 6v12"/>', last: '<path d="M7 6l6 6-6 6M17 6v12"/>',
  find: '<circle cx="11" cy="11" r="7"/><path d="M20 20l-3.5-3.5"/>',
  save: '<path d="M12 3v12M7 10l5 5 5-5M5 21h14"/>',
  mark: '<path d="M6 3h12v18l-6-4-6 4z"/>',
};
function pkPref(k, d) { try { const v = localStorage.getItem('capsight.pk.' + k); return v === null ? d : JSON.parse(v); } catch (e) { return d; } }
const pkSetPref = (k, v) => { try { localStorage.setItem('capsight.pk.' + k, JSON.stringify(v)); } catch (e) {} };
function pkState(prev) {
  return { marked: new Set(), ignored: new Set(), refs: new Set(), refList: [], comments: new Map(), conv: [], color: prev ? prev.color : pkPref('color', true), tfmt: prev ? prev.tfmt : pkPref('tfmt', 'rel'), sort: null, sorted: null, sortedFor: undefined, sortKey: '', find: { mode: 'string', q: '' }, layers: null };
}

/* ---------- colouring rules (Wireshark's defaults, first match wins) ---------- */
const PK_RULES = [
  { name: 'Bad TCP', cls: 'cr-bad', f: s => !!s.malformed },
  { name: 'TCP RST', cls: 'cr-rst', f: s => s.l4 === 'TCP' && !!(s.fl & 4) },
  { name: 'TCP SYN/FIN', cls: 'cr-synfin', f: s => s.l4 === 'TCP' && !!(s.fl & 3) },
  { name: 'HTTP', cls: 'cr-http', f: s => s.proto === 'HTTP' },
  { name: 'ARP', cls: 'cr-arp', f: s => s.proto === 'ARP' },
  { name: 'ICMP', cls: 'cr-icmp', f: s => s.l4 === 'ICMP' || s.l4 === 'ICMPv6' },
  { name: 'SMB', cls: 'cr-smb', f: s => /^SMB|NetBIOS|NBNS/.test(s.proto) },
  { name: 'Routing', cls: 'cr-route', f: s => /OSPF|BGP|RIP|VRRP|STP|LLDP|IGMP|PIM/.test(s.proto) },
  { name: 'TCP', cls: 'cr-tcp', f: s => s.l4 === 'TCP' },
  { name: 'UDP', cls: 'cr-udp', f: s => s.l4 === 'UDP' },
];
function pkColorRule(r) { for (const c of PK_RULES) if (c.f(r.s)) return c; return null; }
const CONV_COLORS = ['#ffc0c0', '#ffc0ff', '#e0c0e0', '#c0c0ff', '#c0e0e0', '#c0ffff', '#c0ffc0', '#ffffc0', '#e0e0c0', '#e0e0e0'];

/* ---------- time column ---------- */
const TFMT = [['rel', 'Seconds since start'], ['delta', 'Since previous shown packet'], ['deltacap', 'Since previous packet'], ['tod', 'Time of day'], ['utc', 'UTC date and time'], ['epoch', 'Seconds since 1970']];
const TFMT_W = { rel: 100, delta: 100, deltacap: 100, tod: 128, utc: 206, epoch: 150 };
function frac6(t) { return String(Math.round((t % 1) * 1e6) % 1e6).padStart(6, '0'); }
function refBefore(i) { const L = S.pk.refList; let lo = 0, hi = L.length - 1, best = -1; while (lo <= hi) { const m = (lo + hi) >> 1; if (L[m] <= i) { best = L[m]; lo = m + 1; } else hi = m - 1; } return best; }
function pkTime(i, prev) {
  const cap = S.cap, r = cap.pk[i], P = S.pk;
  if (P.refs.has(i)) return '*REF*';
  switch (P.tfmt) {
    case 'delta': return (prev === undefined || prev < 0 ? 0 : r.t - cap.pk[prev].t).toFixed(6);
    case 'deltacap': return (i ? r.t - cap.pk[i - 1].t : 0).toFixed(6);
    case 'tod': { const d = new Date(r.t * 1000); return [d.getHours(), d.getMinutes(), d.getSeconds()].map(x => String(x).padStart(2, '0')).join(':') + '.' + frac6(r.t); }
    case 'utc': return new Date(r.t * 1000).toISOString().replace('T', ' ').slice(0, 19) + '.' + frac6(r.t);
    case 'epoch': return r.t.toFixed(6);
    default: { const ref = refBefore(i); return (r.t - (ref >= 0 ? cap.pk[ref].t : cap.t0)).toFixed(6); }
  }
}

/* ---------- the displayed list, in sort order ---------- */
function addrKey(a) { const n = ipInt(a); return n === null ? '~' + a : String(n).padStart(10, '0'); }
function pkList() {
  const base = S.idx, P = S.pk;
  if (!P.sort) return base;
  const key = P.sort.c + P.sort.dir;
  if (P.sortedFor === base && P.sortKey === key && P.sorted) return P.sorted;
  const cap = S.cap, arr = base ? base.slice() : Array.from(cap.pk, (_, i) => i);
  const get = { no: i => i, time: i => i, src: i => addrKey(cap.pk[i].s.src), dst: i => addrKey(cap.pk[i].s.dst), proto: i => cap.pk[i].s.proto, len: i => cap.pk[i].len, info: i => cap.pk[i].s.info }[P.sort.c];
  const k = new Map(arr.map(i => [i, get(i)]));
  arr.sort((a, b) => { const x = k.get(a), y = k.get(b); return (x < y ? -1 : x > y ? 1 : a - b) * P.sort.dir; });
  P.sorted = arr; P.sortedFor = base; P.sortKey = key;
  return arr;
}
const pkCount = () => { const l = pkList(); return l ? l.length : S.cap.pk.length; };
const pkAt = k => { const l = pkList(); return l ? l[k] : k; };
const pkPos = i => { const l = pkList(); return l ? l.indexOf(i) : i; };

/* ---------- view ---------- */
function renderPackets() {
  const el = $('#view-packets');
  if (!$('#pbody', el)) {
    el.innerHTML = `<div class="pk-wrap">
      <div class="card ptable" id="ptable">
        <div class="ptools">
          <label class="pgo"><span>Go to</span><input id="pgo" inputmode="numeric" placeholder="packet" title="Go to packet (Ctrl+G)" aria-label="Go to packet number"></label>
          <span class="pnav"><button class="btn sm icon ghost" data-nav="first" title="First packet (Home)" aria-label="First packet">${SVGI(PI.first, 15)}</button><button class="btn sm icon ghost" data-nav="prev" title="Previous packet (↑)" aria-label="Previous packet">${SVGI(PI.up, 15)}</button><button class="btn sm icon ghost" data-nav="next" title="Next packet (↓)" aria-label="Next packet">${SVGI(PI.down, 15)}</button><button class="btn sm icon ghost" data-nav="last" title="Last packet (End)" aria-label="Last packet">${SVGI(PI.last, 15)}</button></span>
          <button class="btn sm ghost" id="pfindBtn" title="Find a packet (Ctrl+F)">${SVGI(PI.find, 14)}Find</button>
          <span class="sp"></span>
          <label class="ptf" title="Time display format"><span>Time</span><select id="ptfmt">${TFMT.map(([k, l]) => `<option value="${k}">${l}</option>`).join('')}</select></label>
          <label class="cp-switch sm" title="Colour rows by Wireshark's default colouring rules"><input type="checkbox" id="pcolor"><span></span>Colour rows</label>
          <button class="btn sm" id="pexport">${SVGI(PI.save, 14)}Export</button>
        </div>
        <div class="pfind hidden" id="pfind">
          <select id="pfmode" aria-label="Find by"><option value="string">Text</option><option value="hex">Hex bytes</option><option value="filter">Display filter</option></select>
          <input id="pfq" spellcheck="false" autocomplete="off" placeholder="Text in the packet list or bytes">
          <button class="btn sm" id="pfprev" title="Previous match (Shift+Enter)">${SVGI(PI.up, 14)}</button><button class="btn sm primary" id="pfnext" title="Next match (Enter)">Find</button>
          <button class="btn sm ghost icon" id="pfclose" aria-label="Close find">${SVGI(IC.x, 14)}</button>
        </div>
        <div class="phead" id="phead">${PK_COLS.map(c => `<div data-c="${c}" title="Sort by ${PK_COL_NAME[c].toLowerCase()}">${PK_COL_NAME[c]}<i></i></div>`).join('')}</div>
        <div class="pbody" id="pbody" tabindex="0" aria-label="Packet list. Right-click or long-press a packet for options."><div id="pspace"></div></div>
        <div class="pstatus" id="pstatus"></div>
      </div>
      <div class="detail"><div class="card"><div class="dhead" id="dhead"></div><div class="tree" id="tree"></div></div><div class="card"><div class="dhead"><h3>Bytes</h3><span class="sub hint" id="hexsub"></span><span style="flex:1"></span><button class="btn sm ghost" id="copyhex">${SVGI(IC.copy, 14)} Copy hex</button></div><div class="hex" id="hex"></div></div></div></div>`;
    pkWire();
  }
  $('#ptfmt').value = S.pk.tfmt; $('#pcolor').checked = S.pk.color;
  $('#ptable').style.setProperty('--tw', TFMT_W[S.pk.tfmt] + 'px');
  $('#ptable').classList.toggle('pkcolor', S.pk.color);
  drawRows();
  if (S.sel >= 0) showDetail(S.sel); else { $('#dhead').innerHTML = '<h3>Packet details</h3>'; $('#tree').innerHTML = '<div class="empty">Select a packet to inspect its layers. Right-click it for filters and more.</div>'; $('#hex').innerHTML = ''; $('#hexsub').textContent = ''; }
}
function pkWire() {
  const pb = $('#pbody');
  pb.addEventListener('scroll', () => { if (CTX && Math.abs(pb.scrollTop - (CTX.st ?? pb.scrollTop)) > 4) closeCtx(); requestAnimationFrame(drawRows); });
  pb.addEventListener('click', e => { if (pkLong.fired) { pkLong.fired = false; return; } const r = e.target.closest('.prow'); if (r) selectPacket(+r.dataset.i); });
  pb.addEventListener('dblclick', e => { const r = e.target.closest('.prow'); if (r) { const st = S.cap.pk[+r.dataset.i].s.st; if (st !== undefined) followStream(st); } });
  pb.addEventListener('contextmenu', e => { const r = e.target.closest('.prow'); if (!r) return; e.preventDefault(); const i = +r.dataset.i; if (i !== S.sel) selectPacket(i); pkMenu(i, pkCellCol(e.target, r), e.clientX, e.clientY); });
  // long-press opens the same menu on touch screens
  pb.addEventListener('pointerdown', e => {
    if (e.pointerType !== 'touch') return; const r = e.target.closest('.prow'); if (!r) return;
    clearTimeout(pkLong.t); pkLong.x = e.clientX; pkLong.y = e.clientY; pkLong.fired = false;
    pkLong.t = setTimeout(() => { pkLong.fired = true; const i = +r.dataset.i; if (i !== S.sel) selectPacket(i); if (navigator.vibrate) navigator.vibrate(12); pkMenu(i, pkCellCol(e.target, r), pkLong.x, pkLong.y); }, 480);
  });
  pb.addEventListener('pointermove', e => { if (Math.hypot(e.clientX - pkLong.x, e.clientY - pkLong.y) > 8) clearTimeout(pkLong.t); });
  ['pointerup', 'pointercancel'].forEach(t => pb.addEventListener(t, () => clearTimeout(pkLong.t)));
  pb.addEventListener('keydown', pkKeys);
  $('#phead').onclick = e => { const h = e.target.closest('[data-c]'); if (!h) return; const c = h.dataset.c, P = S.pk; P.sort = !P.sort || P.sort.c !== c ? { c, dir: 1 } : P.sort.dir === 1 ? { c, dir: -1 } : null; drawRows(); if (S.sel >= 0) selectPacket(S.sel, true); };
  $('#phead').oncontextmenu = e => { e.preventDefault(); const h = e.target.closest('[data-c]'); const c = h ? h.dataset.c : null; ctxMenu([{ t: 'Sort ascending', dis: !c, act: () => { S.pk.sort = { c, dir: 1 }; drawRows(); } }, { t: 'Sort descending', dis: !c, act: () => { S.pk.sort = { c, dir: -1 }; drawRows(); } }, { t: 'Remove sorting', dis: !S.pk.sort, act: () => { S.pk.sort = null; drawRows(); } }], e.clientX, e.clientY); };
  $$('[data-nav]').forEach(b => b.onclick = () => pkNav(b.dataset.nav));
  $('#pgo').addEventListener('keydown', e => { if (e.key === 'Enter') { e.preventDefault(); pkGoTo(e.target.value); } if (e.key === 'Escape') e.target.blur(); });
  $('#ptfmt').onchange = e => { S.pk.tfmt = e.target.value; pkSetPref('tfmt', S.pk.tfmt); $('#ptable').style.setProperty('--tw', TFMT_W[S.pk.tfmt] + 'px'); drawRows(); };
  $('#pcolor').onchange = e => { S.pk.color = e.target.checked; pkSetPref('color', S.pk.color); $('#ptable').classList.toggle('pkcolor', S.pk.color); drawRows(); };
  $('#pexport').onclick = e => { const b = e.currentTarget.getBoundingClientRect(); ctxMenu(pkExportItems(), b.left, b.bottom + 4); };
  $('#pfindBtn').onclick = () => pkFindOpen();
  $('#pfclose').onclick = () => $('#pfind').classList.add('hidden');
  $('#pfmode').onchange = e => { S.pk.find.mode = e.target.value; $('#pfq').placeholder = { string: 'Text in the packet list or bytes', hex: 'Bytes, e.g. 47 45 54 or 474554', filter: 'A display filter, e.g. http.request' }[e.target.value]; $('#pfq').focus(); };
  $('#pfq').addEventListener('keydown', e => { if (e.key === 'Enter') { e.preventDefault(); pkFind(e.shiftKey ? -1 : 1); } if (e.key === 'Escape') $('#pfind').classList.add('hidden'); });
  $('#pfnext').onclick = () => pkFind(1); $('#pfprev').onclick = () => pkFind(-1);
  $('#copyhex').onclick = () => { if (S.sel >= 0) pkCopy(pkBytesAs(S.sel, 'stream'), 'Copied the bytes as hex'); };
  $('#tree').addEventListener('contextmenu', e => { const t = e.target.closest('.fld, .lh'); if (!t) return; e.preventDefault(); treeMenu(t, e.clientX, e.clientY); });
  $('#tree').addEventListener('dblclick', e => { const f = e.target.closest('.fld'); if (!f) return; const x = fieldFilterOf(f); if (x) setExpr(x); });
}
const pkLong = { t: 0, x: 0, y: 0, fired: false };
function pkCellCol(t, row) { const cell = t.closest('.prow > div'); const k = cell ? [...row.children].indexOf(cell) : -1; return PK_COLS[k] || 'src'; }

function drawRows() {
  const pb = $('#pbody'); if (!pb) return;
  const cap = S.cap, P = S.pk, n = pkCount();
  RH = PHONE() ? 52 : 28; // phones show each packet on two lines
  $('#pspace').style.height = (n * RH) + 'px';
  const top = pb.scrollTop, h = pb.clientHeight;
  const a = Math.max(0, Math.floor(top / RH) - 8), b = Math.min(n, Math.ceil((top + h) / RH) + 8);
  let html = '';
  const sevName = ['', 'low', 'medium', 'high', 'critical'];
  for (let k = a; k < b; k++) {
    const i = pkAt(k), r = cap.pk[i], s = r.s, sv = cap.pkSev[i];
    const ig = P.ignored.has(i), mk = P.marked.has(i);
    let cls = 'prow' + (i === S.sel ? ' sel' : '') + (sv ? ' th s-' + sevName[sv] : '') + (mk ? ' mk' : '') + (ig ? ' ig' : '');
    let style = `top:${k * RH}px`;
    const cc = P.conv.find(c => c.pred(r));
    if (cc) { cls += ' cc'; style += `;--cc:${cc.color}`; }
    else if (P.color && !ig) { const cr = pkColorRule(r); if (cr) cls += ' ' + cr.cls; }
    const info = ig ? '<Ignored>' : s.info;
    html += `<div class="${cls}" data-i="${i}" style="${style}"><div class="num dim">${i + 1}${P.comments.has(i) ? '<b class="pcm" title="Has a comment">•</b>' : ''}</div><div class="num">${pkTime(i, k ? pkAt(k - 1) : -1)}</div><div class="mono">${esc(s.src)}</div><div class="mono">${esc(s.dst)}</div><div>${protoPill(s.proto)}</div><div class="num">${r.len}</div><div title="${esc(info)}">${esc(info)}</div></div>`;
  }
  const sp = $('#pspace'); sp.innerHTML = html;
  if (!n) sp.innerHTML = '<div class="empty">No packets match the current filter</div>';
  $$('#phead [data-c]').forEach(d => { const on = P.sort && P.sort.c === d.dataset.c; d.classList.toggle('sorted', !!on); d.querySelector('i').textContent = on ? (P.sort.dir > 0 ? ' ▲' : ' ▼') : ''; });
  pkStatus();
}
function pkStatus() {
  const el = $('#pstatus'); if (!el) return;
  const P = S.pk, tot = S.cap.pk.length, n = S.idx ? S.idx.length : tot;
  const bits = [`Packets: <b>${fmtNum(tot)}</b>`, `Displayed: <b>${fmtNum(n)}</b> (${(n / Math.max(1, tot) * 100).toFixed(1)}%)`];
  if (P.marked.size) bits.push(`Marked: <b>${fmtNum(P.marked.size)}</b>`);
  if (P.ignored.size) bits.push(`Ignored: <b>${fmtNum(P.ignored.size)}</b>`);
  if (P.refs.size) bits.push(`Time references: <b>${P.refs.size}</b>`);
  if (P.comments.size) bits.push(`Comments: <b>${P.comments.size}</b>`);
  if (P.sort) bits.push(`Sorted by ${PK_COL_NAME[P.sort.c].toLowerCase()}`);
  el.innerHTML = bits.map(b => `<span>${b}</span>`).join('') + '<span class="sp"></span><span class="hint">' + (PHONE() ? 'Long-press' : 'Right-click') + ' a packet for options</span>';
}
function selectPacket(i, scroll) {
  S.sel = i;
  const pb = $('#pbody');
  if (scroll && pb) { const pos = pkPos(i); const y = pos * RH; if (pos >= 0 && (y < pb.scrollTop || y > pb.scrollTop + pb.clientHeight - RH)) pb.scrollTop = y - pb.clientHeight / 2; }
  drawRows(); showDetail(i);
}
function pkNav(d) {
  const n = pkCount(); if (!n) return;
  let pos = S.sel < 0 ? -1 : pkPos(S.sel);
  pos = d === 'first' ? 0 : d === 'last' ? n - 1 : d === 'prev' ? Math.max(0, pos - 1) : d === 'next' ? Math.min(n - 1, pos + 1) : Math.max(0, Math.min(n - 1, pos + d));
  selectPacket(pkAt(pos), true);
}
function pkGoTo(v) {
  const no = parseInt(v, 10), cap = S.cap;
  if (!(no >= 1 && no <= cap.pk.length)) { toast('There is no packet ' + v + '. Packets run from 1 to ' + fmtNum(cap.pk.length) + '.'); return; }
  if (pkPos(no - 1) < 0) { toast('Packet ' + no + ' is hidden by the current filter.'); return; }
  selectPacket(no - 1, true); $('#pbody').focus();
}
// next or previous displayed packet that matches
function pkStep(dir, test, what) {
  const n = pkCount(); if (!n) return;
  const start = S.sel < 0 ? (dir > 0 ? -1 : n) : pkPos(S.sel);
  for (let s = 1; s <= n; s++) { const k = ((start + dir * s) % n + n) % n; const i = pkAt(k); if (test(i)) { selectPacket(i, true); if ((dir > 0 && k <= start) || (dir < 0 && k >= start)) toast('Wrapped around to the ' + (dir > 0 ? 'first' : 'last') + ' ' + what); return; } }
  toast('No ' + what + ' among the shown packets');
}
function pkKeys(e) {
  const k = e.key, ctl = e.ctrlKey || e.metaKey;
  if (!ctl && !e.altKey && ['ArrowDown', 'ArrowUp', 'PageDown', 'PageUp', 'Home', 'End'].includes(k)) {
    e.preventDefault();
    if (k === 'Home') return pkNav('first'); if (k === 'End') return pkNav('last');
    return pkNav(k === 'ArrowDown' ? 1 : k === 'ArrowUp' ? -1 : k === 'PageDown' ? 20 : -20);
  }
  if ((k === 'ContextMenu' || (e.shiftKey && k === 'F10')) && S.sel >= 0) { e.preventDefault(); const row = $(`#pspace .prow[data-i="${S.sel}"]`); const b = row ? row.getBoundingClientRect() : $('#pbody').getBoundingClientRect(); pkMenu(S.sel, 'src', b.left + 80, b.bottom); }
}
// shortcuts that work anywhere on the Packets view (not while typing)
document.addEventListener('keydown', e => {
  if (!S.cap || S.view !== 'packets' || $('#modal').classList.contains('on')) return;
  const tag = document.activeElement.tagName, typing = tag === 'INPUT' || tag === 'SELECT' || tag === 'TEXTAREA';
  const ctl = e.ctrlKey || e.metaKey, k = e.key.toLowerCase();
  if (ctl && k === 'f' && !e.shiftKey) { e.preventDefault(); return pkFindOpen(); }
  if (ctl && k === 'g' && !e.shiftKey) { e.preventDefault(); $('#pgo').focus(); $('#pgo').select(); return; }
  if (typing || S.sel < 0 && !(ctl && e.shiftKey)) return;
  if (e.ctrlKey && !e.shiftKey && !e.altKey && k === 'm') { e.preventDefault(); return pkToggle('marked', S.sel); }
  if (ctl && e.shiftKey && k === 'n') { e.preventDefault(); return pkStep(1, i => S.pk.marked.has(i), 'marked packet'); }
  if (ctl && e.shiftKey && k === 'b') { e.preventDefault(); return pkStep(-1, i => S.pk.marked.has(i), 'marked packet'); }
  if (ctl && !e.shiftKey && !e.altKey && k === 'd') { e.preventDefault(); return pkToggle('ignored', S.sel); }
  if (e.ctrlKey && e.altKey && e.shiftKey && k === 't') { e.preventDefault(); const st = S.cap.pk[S.sel].s.st; if (st !== undefined) followStream(st); return; }
  if (e.ctrlKey && e.altKey && k === 't') { e.preventDefault(); return pkToggle('refs', S.sel); }
  if (ctl && (k === '.' || k === ',')) { e.preventDefault(); const s0 = S.cap.pk[S.sel].s; const same = convTest(s0); return pkStep(k === '.' ? 1 : -1, i => i !== S.sel && same(S.cap.pk[i].s), 'packet in this conversation'); }
});
function convTest(s0) { return s0.st !== undefined ? s => s.st === s0.st && s.l4 === s0.l4 : s => (s.src === s0.src && s.dst === s0.dst) || (s.src === s0.dst && s.dst === s0.src); }
function pkToggle(set, i) {
  const P = S.pk, x = P[set];
  x.has(i) ? x.delete(i) : x.add(i);
  if (set === 'refs') P.refList = [...P.refs].sort((a, b) => a - b);
  const msg = { marked: ['Marked', 'Unmarked'], ignored: ['Ignored', 'No longer ignoring'], refs: ['Time reference set on', 'Time reference removed from'] }[set];
  toast(msg[x.has(i) ? 0 : 1] + ' packet ' + (i + 1));
  if (S.expr && /frame\.(marked|ignored|ref_time)/.test(S.expr)) applyFilter(); else { drawRows(); showDetail(i); }
}
function pkComment(i) {
  const cur = S.pk.comments.get(i) || '';
  $('#mtitle').textContent = 'Packet ' + (i + 1) + ' comment';
  $('#mbody').innerHTML = `<div class="help"><p style="margin:0 0 10px">Comments stay with this capture while it is open and are saved in .pcapng exports, where Wireshark shows them too. Filter on them with <code>frame.comment</code>.</p><textarea id="pcmt" rows="5" class="pcmt" placeholder="What is interesting about this packet?">${esc(cur)}</textarea><div style="display:flex;gap:8px;margin-top:12px"><button class="btn primary" id="pcmtSave">Save comment</button>${cur ? '<button class="btn" id="pcmtDel">Delete comment</button>' : ''}</div></div>`;
  $('#modal').classList.add('on'); setTimeout(() => $('#pcmt').focus(), 30);
  const done = () => { $('#modal').classList.remove('on'); drawRows(); showDetail(i); pkStatus(); };
  $('#pcmtSave').onclick = () => { const v = $('#pcmt').value.trim(); v ? S.pk.comments.set(i, v) : S.pk.comments.delete(i); toast(v ? 'Comment saved' : 'Comment removed'); done(); };
  if (cur) $('#pcmtDel').onclick = () => { S.pk.comments.delete(i); toast('Comment removed'); done(); };
}

/* ---------- filters built from a packet ---------- */
const fq = v => '"' + String(v).replace(/\\/g, '\\\\').replace(/"/g, '\\"') + '"';
function addrFilter(s, side) {
  const v = side === 'src' ? s.src : s.dst;
  if (s.ipv === 4) return 'ip.' + side + '==' + v;
  if (s.ipv === 6) return 'ipv6.' + side + '==' + v;
  if (isMac(v)) return 'eth.' + side + '==' + v.toLowerCase();
  if (s.arp) return 'arp.' + side + '.proto_ipv4==' + v;
  return side + '==' + fq(v);
}
function colFilter(i, c) {
  const cap = S.cap, r = cap.pk[i], s = r.s;
  switch (c) {
    case 'no': return 'frame.number==' + (i + 1);
    case 'time': return 'frame.time_relative==' + (r.t - cap.t0).toFixed(6);
    case 'dst': return addrFilter(s, 'dst');
    case 'proto': return /^[a-z][a-z0-9]*$/i.test(s.proto) ? s.proto.toLowerCase() : '_ws.col.protocol==' + fq(s.proto);
    case 'len': return 'frame.len==' + r.len;
    case 'info': return '_ws.col.info==' + fq(s.info);
    default: return addrFilter(s, 'src');
  }
}
// Wireshark's six ways to apply or prepare a filter
function filterItems(expr, apply) {
  const cur = ($('#fin').value || '').trim(), has = !!cur;
  const run = x => () => { if (apply) { setExpr(x); if (S.view !== 'packets') go('packets'); } else pkPrepare(x); };
  return [
    { t: 'Selected', note: expr, act: run(expr) },
    { t: 'Not Selected', act: run('!(' + expr + ')') },
    { t: '…and Selected', dis: !has, act: run('(' + cur + ') && (' + expr + ')') },
    { t: '…or Selected', dis: !has, act: run('(' + cur + ') || (' + expr + ')') },
    { t: '…and not Selected', dis: !has, act: run('(' + cur + ') && !(' + expr + ')') },
    { t: '…or not Selected', dis: !has, act: run('(' + cur + ') || !(' + expr + ')') },
  ];
}
function pkPrepare(x) {
  const fin = $('#fin'); fin.value = x; fin.focus(); fin.setSelectionRange(x.length, x.length);
  try { compileFilter(x); fxState('good', 'Press Enter to apply'); } catch (err) { fxState('bad', err.message); }
  toast('Filter prepared. Press Enter to apply it.');
}
function convFilters(i) {
  const s = S.cap.pk[i].s, out = [];
  if (s.smac && s.dmac) out.push(['Ethernet', `eth.addr==${s.smac} && eth.addr==${s.dmac}`]);
  if (s.ipv === 4) out.push(['IPv4', `ip.addr==${s.src} && ip.addr==${s.dst}`]);
  if (s.ipv === 6) out.push(['IPv6', `ipv6.addr==${s.src} && ipv6.addr==${s.dst}`]);
  if (s.st !== undefined && s.l4 === 'TCP') out.push(['TCP', 'tcp.stream==' + s.st]);
  if (s.st !== undefined && s.l4 === 'UDP') out.push(['UDP', 'udp.stream==' + s.st]);
  return out;
}

/* ---------- the right-click menu for a packet ---------- */
function pkMenu(i, c, x, y) {
  const cap = S.cap, r = cap.pk[i], s = r.s, P = S.pk;
  const expr = colFilter(i, c), st = s.st !== undefined ? cap.streams[s.st] : null;
  const det = cap.pkDet.get(i) !== undefined ? cap.threats[cap.pkDet.get(i)] : null;
  const convs = convFilters(i);
  const swatches = f => ({ sw: CONV_COLORS, act: col => { P.conv = P.conv.filter(cv => cv.expr !== f); P.conv.unshift({ expr: f, pred: compileFilter(f), color: col }); drawRows(); toast('Colourised this conversation'); } });
  const cell = { no: String(i + 1), time: pkTime(i), src: s.src, dst: s.dst, proto: s.proto, len: String(r.len), info: s.info }[c];
  ctxMenu([
    { t: P.marked.has(i) ? 'Unmark packet' : 'Mark packet', k: 'Ctrl+M', act: () => pkToggle('marked', i) },
    { t: P.ignored.has(i) ? 'Unignore packet' : 'Ignore packet', k: 'Ctrl+D', act: () => pkToggle('ignored', i) },
    { t: P.refs.has(i) ? 'Unset time reference' : 'Set time reference', k: 'Ctrl+Alt+T', act: () => pkToggle('refs', i) },
    { t: P.comments.has(i) ? 'Edit packet comment…' : 'Packet comment…', act: () => pkComment(i) },
    { sep: 1 },
    { t: 'Apply as filter', note: expr, sub: filterItems(expr, true) },
    { t: 'Prepare as filter', note: expr, sub: filterItems(expr, false) },
    { t: 'Conversation filter', dis: !convs.length, sub: convs.map(([l, f]) => ({ t: l, note: f, act: () => setExpr(f) })) },
    { t: 'Colourise conversation', dis: !convs.length, sub: convs.map(([l, f]) => ({ t: l, sub: [swatches(f)] })).concat(P.conv.length ? [{ sep: 1 }, { t: 'Reset colourisation', act: () => { P.conv = []; drawRows(); } }] : []) },
    { t: 'Follow', dis: !st, sub: st ? [
      { t: 'TCP stream', k: 'Ctrl+Alt+Shift+T', dis: st.l4 !== 'TCP', act: () => followStream(st.id) },
      { t: 'UDP stream', dis: st.l4 !== 'UDP', act: () => followStream(st.id) },
      { t: 'TLS stream', dis: st.proto !== 'TLS', act: () => followStream(st.id) },
      { t: 'HTTP stream', dis: st.proto !== 'HTTP' && !s.http, act: () => followStream(st.id) },
    ] : [] },
    { sep: 1 },
    { t: 'Copy', sub: [
      { t: 'Summary as text', act: () => pkCopy(pkSummary([i], 'text'), 'Copied the packet summary') },
      { t: '…as CSV', act: () => pkCopy(pkSummary([i], 'csv'), 'Copied the packet summary as CSV') },
      { t: PK_COL_NAME[c] + ' value', note: cell, act: () => pkCopy(cell, 'Copied ' + PK_COL_NAME[c].toLowerCase()) },
      { t: 'As filter', note: expr, act: () => pkCopy(expr, 'Copied the filter') },
      { sep: 1 },
      { t: 'Bytes as hex + ASCII dump', act: () => pkCopy(pkBytesAs(i, 'dump'), 'Copied the hex dump') },
      { t: 'Bytes as hex stream', act: () => pkCopy(pkBytesAs(i, 'stream'), 'Copied the bytes as hex') },
      { t: 'Bytes as printable text', act: () => pkCopy(pkBytesAs(i, 'text'), 'Copied the printable text') },
      { t: 'Bytes as escaped string', act: () => pkCopy(pkBytesAs(i, 'escaped'), 'Copied the escaped string') },
    ] },
    { t: 'Export packet bytes…', act: () => offerSave(`packet-${i + 1}.bin`, new Blob([pkBytes(cap, i).slice()], { type: 'application/octet-stream' })) },
    { t: 'Export this packet as .pcapng', act: () => pkExport([i], `packet-${i + 1}.pcapng`) },
    det ? { sep: 1 } : null,
    det ? { t: 'Show detection', note: det.title, act: () => { S.tsel = det.id; S.dirty.threats = 1; go('threats'); } } : null,
  ].filter(Boolean), x, y, 'Packet ' + (i + 1));
}

/* ---------- copy ---------- */
function pkCopy(text, msg) {
  const done = () => toast(msg), fail = () => {
    const t = document.createElement('textarea'); t.value = text; t.style.cssText = 'position:fixed;opacity:0'; document.body.appendChild(t); t.select();
    try { document.execCommand('copy') ? done() : toast('Your browser blocked the clipboard'); } catch (e) { toast('Your browser blocked the clipboard'); } t.remove();
  };
  if (navigator.clipboard && window.isSecureContext) navigator.clipboard.writeText(text).then(done, fail); else fail();
}
function pkSummary(list, fmt) {
  const cap = S.cap, rows = list.map((i, k) => { const r = cap.pk[i], s = r.s; return [i + 1, pkTime(i, k ? list[k - 1] : -1), s.src, s.dst, s.proto, r.len, S.pk.ignored.has(i) ? '<Ignored>' : s.info]; });
  const head = PK_COLS.map(c => PK_COL_NAME[c]);
  if (fmt === 'csv') return [head].concat(rows).map(r => r.map(v => '"' + String(v).replace(/"/g, '""') + '"').join(',')).join('\n');
  return rows.map(r => r.join('\t')).join('\n');
}
function pkBytesAs(i, how, by) {
  const b = by || pkBytes(S.cap, i);
  if (how === 'stream') return [...b].map(h2).join('');
  if (how === 'text') return latin(b, 0, b.length, b.length).replace(/[^\x09\x0a\x0d\x20-\x7e]/g, '');
  if (how === 'escaped') return [...b].map(x => '\\x' + h2(x)).join('');
  let out = '';
  for (let o = 0; o < b.length; o += 16) { const row = [...b.subarray(o, o + 16)]; out += o.toString(16).padStart(4, '0') + '  ' + row.map(h2).join(' ').padEnd(47) + '   ' + row.map(x => x >= 32 && x < 127 ? String.fromCharCode(x) : '.').join('') + '\n'; }
  return out;
}

/* ---------- export ---------- */
function pkExportItems() {
  const P = S.pk, shown = S.idx ? S.idx : null, base = S.cap.name.replace(/\.(pcapng|pcap|cap)$/i, '');
  const ids = list => (list || Array.from(S.cap.pk, (_, i) => i)).filter(i => !P.ignored.has(i));
  return [
    { t: 'Shown packets as .pcapng', note: fmtNum(ids(shown).length) + ' packets', act: () => pkExport(ids(shown), base + (shown ? '-filtered' : '') + '.pcapng') },
    { t: 'Marked packets as .pcapng', dis: !P.marked.size, note: fmtNum(P.marked.size) + ' marked', act: () => pkExport([...P.marked].sort((a, b) => a - b), base + '-marked.pcapng') },
    { t: 'All packets as .pcapng', act: () => pkExport(ids(null), base + '-all.pcapng') },
    { sep: 1 },
    { t: 'Packet list as CSV', act: () => offerSave(base + '-packets.csv', new Blob([pkSummary(pkList() || ids(null), 'csv')], { type: 'text/csv' })) },
    { t: 'Packet list as text', act: () => offerSave(base + '-packets.txt', new Blob([PK_COLS.map(c => PK_COL_NAME[c]).join('\t') + '\n' + pkSummary(pkList() || ids(null), 'text')], { type: 'text/plain' })) },
  ];
}
// pcapng (what Wireshark writes): one interface per link type, packet comments kept
function pkExport(list, filename) {
  if (!list.length) { toast('No packets to export'); return; }
  const cap = S.cap, enc = new TextEncoder(), parts = [], ifs = new Map();
  const blk = (type, body) => { const len = 12 + body.length; const b = new Uint8Array(len), dv = new DataView(b.buffer); dv.setUint32(0, type, true); dv.setUint32(4, len, true); b.set(body, 8); dv.setUint32(len - 4, len, true); parts.push(b); };
  const pad4 = n => (4 - n % 4) % 4;
  const shb = new Uint8Array(16), sv = new DataView(shb.buffer); sv.setUint32(0, 0x1a2b3c4d, true); sv.setUint16(4, 1, true); sv.setUint16(6, 0, true); sv.setInt32(8, -1, true); sv.setInt32(12, -1, true);
  blk(0x0a0d0d0a, shb);
  for (const i of list) { const lt = cap.pk[i].lt; if (!ifs.has(lt)) { ifs.set(lt, ifs.size); const idb = new Uint8Array(8), iv = new DataView(idb.buffer); iv.setUint16(0, lt, true); iv.setUint32(4, 0, true); blk(1, idb); } }
  for (const i of list) {
    const r = cap.pk[i], data = pkBytes(cap, i), cm = S.pk.comments.get(i);
    const cb = cm ? enc.encode(cm) : null;
    const optLen = cb ? 4 + cb.length + pad4(cb.length) + 4 : 0;
    const body = new Uint8Array(20 + data.length + pad4(data.length) + optLen), dv = new DataView(body.buffer);
    const us = Math.round(r.t * 1e6);
    dv.setUint32(0, ifs.get(r.lt), true); dv.setUint32(4, Math.floor(us / 4294967296), true); dv.setUint32(8, us % 4294967296, true);
    dv.setUint32(12, data.length, true); dv.setUint32(16, r.len, true); body.set(data, 20);
    if (cb) { let o = 20 + data.length + pad4(data.length); dv.setUint16(o, 1, true); dv.setUint16(o + 2, cb.length, true); body.set(cb, o + 4); o += 4 + cb.length + pad4(cb.length); dv.setUint32(o, 0, true); }
    blk(6, body);
  }
  offerSave(filename, new Blob(parts, { type: 'application/octet-stream' }));
  toast('Exported ' + fmtNum(list.length) + ' packet' + (list.length > 1 ? 's' : ''));
}

/* ---------- find ---------- */
function pkFindOpen() { const f = $('#pfind'); f.classList.remove('hidden'); $('#pfmode').value = S.pk.find.mode; $('#pfq').focus(); $('#pfq').select(); }
function pkFind(dir) {
  const mode = $('#pfmode').value, q = $('#pfq').value.trim(); if (!q) return;
  let test;
  try {
    if (mode === 'filter') { const f = compileFilter(q); test = i => f(S.cap.pk[i]); }
    else if (mode === 'hex') { const want = Uint8Array.from(q.replace(/[\s:.\-]/g, '').match(/../g) || [], x => parseInt(x, 16)); if (!want.length || want.some(isNaN)) throw new Error('Type bytes as hex, like 47 45 54'); test = i => findBytes(pkBytes(S.cap, i), want) >= 0; }
    else { const lq = q.toLowerCase(), qb = Uint8Array.from(q, c => c.charCodeAt(0) & 255); test = i => { const s = S.cap.pk[i].s; return s.info.toLowerCase().includes(lq) || s.src.toLowerCase().includes(lq) || s.dst.toLowerCase().includes(lq) || findBytes(pkBytes(S.cap, i), qb) >= 0; }; }
  } catch (err) { toast(err.message); return; }
  $('#pfq').classList.remove('bad');
  pkStep(dir, test, 'match for “' + q + '”');
}

/* ---------- details ---------- */
function showDetail(i) {
  const cap = S.cap, r = cap.pk[i], s = r.s, bytes = pkBytes(cap, i), P = S.pk;
  const T = new Tree(); dissect(bytes, r.lt, T);
  const det = cap.pkDet.get(i) !== undefined ? cap.threats[cap.pkDet.get(i)] : null;
  const st = s.st !== undefined ? cap.streams[s.st] : null;
  const flags = [P.marked.has(i) ? '<span class="pill">Marked</span>' : '', P.ignored.has(i) ? '<span class="pill">Ignored</span>' : '', P.refs.has(i) ? '<span class="pill">Time reference</span>' : ''].join('');
  $('#dhead').innerHTML = `<h3>Frame ${i + 1}</h3><span class="pill">${r.len} bytes on wire${r.cap !== r.len ? ', ' + r.cap + ' captured' : ''}</span><span class="pill">${new Date(r.t * 1000).toISOString().replace('T', ' ').replace('Z', '')} UTC</span>${flags}${det ? `<span class="sev ${det.sev}" style="cursor:pointer" id="dthreat">${SVGI(SEV_ICON[det.sev], 14)}${esc(det.title)}</span>` : ''}<span style="flex:1"></span>${st ? `<button class="btn sm" id="dfollow">${SVGI(IC.stream, 14)}Follow ${st.l4} stream</button><button class="btn sm ghost" id="dconv">${SVGI(IC.filter, 14)}Conversation</button>` : ''}<button class="btn sm ghost icon" id="dmore" title="More options for this packet" aria-label="More options">⋯</button>`;
  if (det) $('#dthreat').onclick = () => { S.tsel = det.id; S.dirty.threats = 1; go('threats'); };
  if (st) { $('#dfollow').onclick = () => followStream(st.id); $('#dconv').onclick = () => setExpr((st.l4 === 'UDP' ? 'udp' : 'tcp') + '.stream==' + st.id); }
  $('#dmore').onclick = e => { const b = e.currentTarget.getBoundingClientRect(); pkMenu(i, 'src', b.left, b.bottom + 4); };
  const rule = pkColorRule(r);
  const frame = { frame: 1, name: 'Frame ' + (i + 1) + ': ' + r.len + ' bytes on wire, ' + r.cap + ' bytes captured', s: 0, l: bytes.length, f: [{ n: 'Arrival time', v: new Date(r.t * 1000).toISOString(), s: 0, l: 0 }, { n: 'Epoch time', v: r.t.toFixed(6) + ' s', s: 0, l: 0 }, { n: 'Time since first frame', v: (r.t - cap.t0).toFixed(6) + ' s', s: 0, l: 0 }, { n: 'Time since previous frame', v: (i ? r.t - cap.pk[i - 1].t : 0).toFixed(6) + ' s', s: 0, l: 0 }].concat(refBefore(i) >= 0 && !P.refs.has(i) ? [{ n: 'Time since reference', v: (r.t - cap.pk[refBefore(i)].t).toFixed(6) + ' s (packet ' + (refBefore(i) + 1) + ')', s: 0, l: 0 }] : []).concat([{ n: 'Frame number', v: i + 1, s: 0, l: 0 }, { n: 'Frame length', v: r.len + ' bytes', s: 0, l: 0 }, { n: 'Capture length', v: r.cap + ' bytes', s: 0, l: 0 }, { n: 'Marked', v: P.marked.has(i) ? 'True' : 'False', s: 0, l: 0 }, { n: 'Ignored', v: P.ignored.has(i) ? 'True' : 'False', s: 0, l: 0 }, { n: 'Link type', v: r.lt, s: 0, l: 0 }, { n: 'Protocols', v: T.layers.map(l => l.name.split(/[ ,:(]/)[0]).join(' › '), s: 0, l: 0 }, { n: 'Colouring rule', v: rule ? rule.name : 'none', s: 0, l: 0 }]) };
  const layers = (P.comments.has(i) ? [{ cmt: 1, name: 'Packet comments', s: 0, l: 0, f: [{ n: '', v: P.comments.get(i), s: 0, l: 0 }] }] : []).concat([frame], T.layers);
  P.layers = layers; P.layersFor = i;
  if (!S.openLayers.size) layers.slice(-2).forEach(l => S.openLayers.add(l.name.split(/[,:(]/)[0].trim()));
  $('#tree').innerHTML = layers.map((L, li) => {
    const key = L.name.split(/[,:(]/)[0].trim();
    return `<div class="layer ${S.openLayers.has(key) || L.cmt ? 'open' : ''}${L.cmt ? ' cmt' : ''}" data-k="${esc(key)}" data-li="${li}" data-s="${L.s}" data-l="${L.l}"><div class="lh">${SVGI(IC.car, 14).replace('<svg', '<svg class="car"')}<span>${esc(L.name)}</span><span class="bl">${L.frame || L.cmt ? '' : L.l + ' B'}</span></div><div class="fs">${L.f.map((f, fi) => `<div class="fld d${f.d}" data-fi="${fi}" data-s="${f.s}" data-l="${f.l}"><span class="k">${esc(f.n)}</span><span class="v">${esc(f.v)}</span></div>`).join('')}</div></div>`;
  }).join('');
  // hex
  const lim = Math.min(bytes.length, 4096), per = PHONE() ? 8 : 16;
  let hx = '';
  for (let o = 0; o < lim; o += per) {
    hx += `<span class="o">${o.toString(16).padStart(4, '0')}</span>`;
    let a = '';
    for (let j = 0; j < per; j++) {
      const k = o + j;
      if (j === per / 2) hx += '<span class="g"></span>';
      if (k < lim) { const b = bytes[k]; hx += `<span class="b${b ? '' : ' z'}" data-i="${k}">${h2(b)}</span>`; a += `<span class="a" data-i="${k}">${b >= 32 && b < 127 ? esc(String.fromCharCode(b)) : '·'}</span>`; }
      else hx += '<span class="b">  </span>';
    }
    hx += `<span class="asc">${a}</span>\n`;
  }
  $('#hex').innerHTML = hx;
  $('#hexsub').textContent = bytes.length > lim ? `showing first ${lim} of ${bytes.length} bytes` : bytes.length + ' bytes';
  const hexEls = $$('#hex [data-i]');
  const byIdx = new Map(); hexEls.forEach(e => { const k = +e.dataset.i; (byIdx.get(k) || byIdx.set(k, []).get(k)).push(e); });
  const clear = cls => $$('#hex .' + cls).forEach(e => e.classList.remove(cls));
  const mark = (s0, l, cls) => { clear(cls); for (let k = s0; k < s0 + l; k++) (byIdx.get(k) || []).forEach(e => e.classList.add(cls)); };
  $$('#tree .lh').forEach(h => { h.onclick = () => { const L = h.parentElement; L.classList.toggle('open'); const k = L.dataset.k; L.classList.contains('open') ? S.openLayers.add(k) : S.openLayers.delete(k); }; h.onmouseenter = () => { const L = h.parentElement; mark(+L.dataset.s, +L.dataset.l, 'ly'); }; h.onmouseleave = () => clear('ly'); });
  $$('#tree .fld').forEach(f => { f.onmouseenter = () => mark(+f.dataset.s, +f.dataset.l, 'on'); f.onmouseleave = () => clear('on'); f.onclick = () => { $$('#tree .fld.hl').forEach(x => x.classList.remove('hl')); f.classList.add('hl'); mark(+f.dataset.s, +f.dataset.l, 'on'); }; });
  $('#hex').onclick = e => {
    const t = e.target.closest('[data-i]'); if (!t) return; const k = +t.dataset.i;
    let best = null; $$('#tree .fld').forEach(f => { const s0 = +f.dataset.s, l = +f.dataset.l; if (l > 0 && k >= s0 && k < s0 + l && (!best || l < +best.dataset.l)) best = f; });
    $$('#tree .fld.hl').forEach(f => f.classList.remove('hl'));
    if (best) { best.closest('.layer').classList.add('open'); best.classList.add('hl'); best.scrollIntoView({ block: 'nearest' }); mark(+best.dataset.s, +best.dataset.l, 'on'); }
  };
}

/* ---------- filters built from a field in the details tree ---------- */
// field label in Capsight's dissector → Wireshark field name
const FIELD_KEYS = [
  [/^Ethernet II/, { Destination: 'eth.dst', Source: 'eth.src' }],
  [/^802\.1Q/, { 'VLAN ID': 'vlan.id' }],
  [/^Internet Protocol Version 4/, { 'Source address': 'ip.src', 'Destination address': 'ip.dst', 'Time to live': 'ip.ttl', Identification: 'ip.id' }],
  [/^Internet Protocol Version 6/, { 'Source address': 'ipv6.src', 'Destination address': 'ipv6.dst', 'Hop limit': 'ipv6.hlim' }],
  [/^Transmission Control/, { 'Source port': 'tcp.srcport', 'Destination port': 'tcp.dstport', Syn: 'tcp.flags.syn', Fin: 'tcp.flags.fin', Reset: 'tcp.flags.reset', Push: 'tcp.flags.push', Acknowledgment: 'tcp.flags.ack', Urgent: 'tcp.flags.urg', ECE: 'tcp.flags.ece', CWR: 'tcp.flags.cwr', Nonce: 'tcp.flags.ns', Flags: 'tcp.flags' }],
  [/^User Datagram/, { 'Source port': 'udp.srcport', 'Destination port': 'udp.dstport' }],
  [/^Domain Name System|^Multicast DNS|^Link-local/, { Query: 'dns.qry.name' }],
  [/^Hypertext Transfer/, { Host: 'http.host', 'User-Agent': 'http.user_agent', 'Request line': 'http.request.uri', 'Status line': 'http.response.code' }],
  [/^TLS/, { 'Server Name Indication': 'tls.handshake.extensions_server_name' }],
  [/^Address Resolution/, { Opcode: 'arp.opcode', 'Sender IP address': 'arp.src.proto_ipv4', 'Target IP address': 'arp.dst.proto_ipv4', 'Sender MAC address': 'arp.src.hw_mac', 'Target MAC address': 'arp.dst.hw_mac' }],
  [/^Internet Control Message Protocol$/, { Type: 'icmp.type', Code: 'icmp.code' }],
  [/^Internet Control Message Protocol v6/, { Type: 'icmpv6.type' }],
];
const STR_KEYS = new Set(['dns.qry.name', 'http.host', 'http.user_agent', 'http.request.uri', 'tls.handshake.extensions_server_name']);
function fieldValue(k, v) {
  v = String(v).trim();
  if (k === 'dns.qry.name') return fq(v.split(':')[0]);
  if (k === 'http.request.uri') return fq(v.split(' ')[1] || '');
  if (k === 'http.response.code') return v.split(' ')[1] || null;
  if (STR_KEYS.has(k)) return fq(v);
  if (/^eth\.(src|dst)$|hw_mac$|proto_ipv4$|^ipv?6?\.(src|dst)$/.test(k)) return v.toLowerCase();
  if (/^Set$/i.test(v)) return '1'; if (/^Not set$/i.test(v)) return '0';
  const m = v.match(/^(0x[0-9a-f]+|\d+(\.\d+)?)/i) || v.match(/\((\d+)\)/);
  return m ? m[1] : null;
}
function fieldFilter(L, f, i) {
  const cap = S.cap, r = cap.pk[i], s = r.s;
  if (!L || L.cmt) return L && L.cmt ? 'frame.comment~' + fq(f.v) : null;
  if (L.frame) return ({ 'Frame number': 'frame.number==' + (i + 1), 'Frame length': 'frame.len==' + r.len, 'Time since first frame': 'frame.time_relative==' + (r.t - cap.t0).toFixed(6), 'Epoch time': 'frame.time_epoch==' + r.t.toFixed(6), 'Arrival time': 'frame.time_epoch==' + r.t.toFixed(6), Marked: 'frame.marked==' + (S.pk.marked.has(i) ? 1 : 0), Ignored: 'frame.ignored==' + (S.pk.ignored.has(i) ? 1 : 0), 'Colouring rule': pkColorRule(r) ? 'frame.coloring_rule.name==' + fq(pkColorRule(r).name) : null })[f.n] || null;
  for (const [re, keys] of FIELD_KEYS) if (re.test(L.name)) { const k = keys[f.n]; if (k) { const v = fieldValue(k, f.v); if (v !== null && v !== '""') return k + '==' + v; } break; }
  if (!f.l) return null;
  // anything else: match its bytes, counted from the start of its protocol as Wireshark slices do
  const len = Math.min(f.l, 32), by = pkBytes(cap, i).subarray(f.s, f.s + len);
  const p = /^Ethernet II/.test(L.name) ? 'eth' : /^Internet Protocol Version 4/.test(L.name) ? 'ip' : /^Internet Protocol Version 6/.test(L.name) ? 'ipv6' : /^Transmission Control/.test(L.name) ? 'tcp' : /^User Datagram/.test(L.name) ? 'udp' : 'frame';
  const b0 = p === 'frame' ? 0 : protoBase(p, s);
  const base = b0 === L.s ? b0 : 0, name = b0 === L.s ? p : 'frame';
  return `${name}[${f.s - base}:${by.length}]==${[...by].map(h2).join(':')}`;
}
function fieldFilterOf(el) {
  const Ls = S.pk.layers; if (!Ls) return null;
  const lay = el.closest('.layer'), L = Ls[+lay.dataset.li];
  if (el.classList.contains('lh')) { const p = layerProto(L); return p; }
  return fieldFilter(L, L.f[+el.dataset.fi], S.sel);
}
function layerProto(L) {
  if (!L || L.frame) return 'frame'; if (L.cmt) return 'frame.comment';
  const m = [[/^Ethernet/, 'eth'], [/^802\.1Q/, 'vlan'], [/^Internet Protocol Version 4/, 'ip'], [/^Internet Protocol Version 6/, 'ipv6'], [/^Transmission Control/, 'tcp'], [/^User Datagram/, 'udp'], [/^Address Resolution/, 'arp'], [/^Internet Control Message Protocol v6/, 'icmpv6'], [/^Internet Control/, 'icmp'], [/^Domain Name System/, 'dns'], [/^Hypertext/, 'http'], [/^TLS/, 'tls'], [/^Dynamic Host/, 'dhcp'], [/^Network Time/, 'ntp'], [/^QUIC/, 'quic'], [/^SSH/, 'ssh']].find(([re]) => re.test(L.name));
  return m ? m[1] : null;
}
function treeMenu(el, x, y) {
  const i = S.sel, Ls = S.pk.layers; if (i < 0 || !Ls) return;
  const lay = el.closest('.layer'), L = Ls[+lay.dataset.li], isField = el.classList.contains('fld');
  const f = isField ? L.f[+el.dataset.fi] : null;
  const expr = fieldFilterOf(el);
  const by = isField ? pkBytes(S.cap, i).subarray(f.s, f.s + f.l) : pkBytes(S.cap, i).subarray(L.s, L.s + L.l);
  const setAll = open => $$('#tree .layer').forEach(l => { l.classList.toggle('open', open); open ? S.openLayers.add(l.dataset.k) : S.openLayers.delete(l.dataset.k); });
  const visible = () => $$('#tree .layer').map(l => { const LL = Ls[+l.dataset.li]; return LL.name + (l.classList.contains('open') ? '\n' + LL.f.map(ff => '    ' + (ff.n ? ff.n + ': ' : '') + ff.v).join('\n') : ''); }).join('\n');
  ctxMenu([
    { t: 'Expand subtrees', act: () => { lay.classList.add('open'); S.openLayers.add(lay.dataset.k); } },
    { t: 'Collapse subtrees', act: () => { lay.classList.remove('open'); S.openLayers.delete(lay.dataset.k); } },
    { t: 'Expand all', act: () => setAll(true) },
    { t: 'Collapse all', act: () => setAll(false) },
    { sep: 1 },
    { t: 'Apply as filter', note: expr || 'no filter for this field', dis: !expr, sub: expr ? filterItems(expr, true) : [] },
    { t: 'Prepare as filter', dis: !expr, sub: expr ? filterItems(expr, false) : [] },
    { sep: 1 },
    { t: 'Copy', sub: [
      { t: 'All visible items', act: () => pkCopy(visible(), 'Copied the visible details') },
      { t: isField ? 'Field as text' : 'Layer name', act: () => pkCopy(isField ? (f.n ? f.n + ': ' : '') + f.v : L.name, 'Copied') },
      isField ? { t: 'Value', note: f.v, act: () => pkCopy(f.v, 'Copied the value') } : null,
      { t: 'As filter', dis: !expr, note: expr || '', act: () => pkCopy(expr, 'Copied the filter') },
      { t: 'Bytes as hex', dis: !by.length, act: () => pkCopy(pkBytesAs(i, 'stream', by), 'Copied ' + by.length + ' bytes as hex') },
      { t: 'Bytes as printable text', dis: !by.length, act: () => pkCopy(pkBytesAs(i, 'text', by), 'Copied the printable text') },
    ].filter(Boolean) },
    { t: 'Export selected bytes…', dis: !by.length, act: () => offerSave(`packet-${i + 1}-${(isField ? f.n : layerProto(L) || 'layer').replace(/\W+/g, '_')}.bin`, new Blob([by.slice()], { type: 'application/octet-stream' })) },
  ], x, y, isField ? (f.n || L.name) : L.name.split(',')[0]);
}

/* ---------- menu component ---------- */
// items: { t, k (shortcut), note, act, dis, sub: [...], sep, sw: [colours] }
let CTX = null;
function ctxGuarded() { return CTX && CTX.guard > Date.now(); }
function closeCtx() { if (CTX) { CTX.remove(); CTX = null; document.removeEventListener('pointerdown', ctxAway, true); } }
function ctxAway(e) { if (CTX && !CTX.contains(e.target)) closeCtx(); }
function ctxBuild(items, sheet) {
  const ul = document.createElement('div'); ul.className = 'ctx-list'; ul.setAttribute('role', 'menu');
  items.forEach(it => {
    if (it.sep) { const s = document.createElement('div'); s.className = 'ctx-sep'; ul.appendChild(s); return; }
    if (it.sw) { const w = document.createElement('div'); w.className = 'ctx-sw'; it.sw.forEach(c => { const b = document.createElement('button'); b.style.background = c; b.title = 'Colour ' + c; b.setAttribute('role', 'menuitem'); b.onclick = () => { if (ctxGuarded()) return; closeCtx(); it.act(c); }; w.appendChild(b); }); ul.appendChild(w); return; }
    const b = document.createElement('button'); b.className = 'ctx-it' + (it.sub ? ' has-sub' : ''); b.setAttribute('role', 'menuitem'); b.disabled = !!it.dis || (it.sub && !it.sub.length);
    b.innerHTML = `<span class="ctx-t">${esc(it.t)}${it.note ? `<small>${esc(it.note.length > 70 ? it.note.slice(0, 68) + '…' : it.note)}</small>` : ''}</span>${it.k ? `<kbd>${esc(it.k)}</kbd>` : ''}${it.sub ? '<span class="ctx-car">›</span>' : ''}`;
    const wrap = document.createElement('div'); wrap.className = 'ctx-row'; wrap.appendChild(b);
    if (it.sub && it.sub.length) {
      const sub = ctxBuild(it.sub, sheet); sub.classList.add('ctx-sub'); wrap.appendChild(sub);
      const open = () => { $$('.ctx-row.open', ul).forEach(r => r !== wrap && r.classList.remove('open')); wrap.classList.add('open'); if (!sheet) ctxPlaceSub(wrap, sub); };
      b.onclick = e => { e.stopPropagation(); if (ctxGuarded()) return; if (sheet && wrap.classList.contains('open')) wrap.classList.remove('open'); else open(); };
      if (!sheet) { b.onmouseenter = open; b.onkeydown = e => { if (e.key === 'ArrowRight') { open(); const f = sub.querySelector('button:not(:disabled)'); if (f) f.focus(); } }; }
    } else if (!b.disabled) { b.onclick = () => { if (ctxGuarded()) return; closeCtx(); it.act(); }; if (!sheet) b.onmouseenter = () => $$('.ctx-row.open', ul).forEach(r => r.classList.remove('open')); }
    ul.appendChild(wrap);
  });
  ul.addEventListener('keydown', e => {
    const btns = [...ul.children].map(r => r.querySelector(':scope > button')).filter(x => x && !x.disabled);
    const k = btns.indexOf(document.activeElement);
    if (e.key === 'ArrowDown' || e.key === 'ArrowUp') { if (k < 0 && !btns.includes(document.activeElement)) return; e.preventDefault(); e.stopPropagation(); btns[(k + (e.key === 'ArrowDown' ? 1 : -1) + btns.length) % btns.length].focus(); }
    if (e.key === 'ArrowLeft' && ul.classList.contains('ctx-sub')) { e.preventDefault(); e.stopPropagation(); const row = ul.parentElement; row.classList.remove('open'); row.querySelector('button').focus(); }
  });
  return ul;
}
function ctxPlaceSub(row, sub) {
  sub.style.left = ''; sub.style.right = ''; sub.style.top = '';
  const rb = row.getBoundingClientRect(), sw = sub.offsetWidth, sh = sub.offsetHeight;
  if (rb.right + sw > innerWidth - 6) { sub.style.left = 'auto'; sub.style.right = '100%'; }
  const over = rb.top + sh - (innerHeight - 6); if (over > 0) sub.style.top = (-over - 4) + 'px';
}
function ctxMenu(items, x, y, title) {
  closeCtx(); untip();
  const sheet = PHONE();
  const m = document.createElement('div'); m.className = 'ctx' + (sheet ? ' sheet' : '');
  if (sheet && title) { const h = document.createElement('div'); h.className = 'ctx-h'; h.textContent = title; m.appendChild(h); }
  m.appendChild(ctxBuild(items, sheet));
  document.body.appendChild(m); CTX = m; CTX.st = $('#pbody') ? $('#pbody').scrollTop : 0;
  CTX.guard = Date.now() + 450; // ignore the tap that ends a long-press
  if (!sheet) { const w = m.offsetWidth, h = m.offsetHeight; m.style.left = Math.max(6, Math.min(x, innerWidth - w - 6)) + 'px'; m.style.top = Math.max(6, Math.min(y, innerHeight - h - 6)) + 'px'; }
  else { const bd = document.createElement('div'); bd.className = 'ctx-bd'; m.prepend(bd); bd.onclick = closeCtx; }
  m.addEventListener('keydown', e => { if (e.key === 'Escape') { e.stopPropagation(); closeCtx(); $('#pbody') && $('#pbody').focus(); } });
  setTimeout(() => { document.addEventListener('pointerdown', ctxAway, true); const f = m.querySelector('.ctx-list > .ctx-row > button:not(:disabled)'); if (f && !sheet) f.focus({ preventScroll: true }); }, 0);
}
window.addEventListener('resize', closeCtx);
window.addEventListener('blur', closeCtx);

/* ---------- follow stream ---------- */
function followStream(id) {
  const cap = S.cap, st = cap.streams[id];
  const segs = []; let cb = 0, sb = 0, total = 0;
  for (const i of st.pk) {
    const s = cap.pk[i].s; if (!s.pll) continue;
    const d = s.dirA ? 'c' : 's'; if (d === 'c') cb += s.pll; else sb += s.pll;
    if (total > 300000) continue;
    const r = cap.pk[i], b = cap.u8.subarray(r.off + s.plo, r.off + s.plo + Math.min(s.pll, 65536)); total += b.length;
    const last = segs[segs.length - 1];
    if (last && last.d === d) last.b.push(b); else segs.push({ d, b: [b], i });
  }
  const V = followStream.v = { dir: 'both', as: 'ascii' };
  const proto = st.l4 === 'UDP' ? 'udp' : 'tcp';
  $('#mtitle').innerHTML = `Follow ${st.proto === 'TLS' ? 'TLS' : st.proto === 'HTTP' ? 'HTTP' : st.l4} stream ${id} <span class="hint mono" style="font-weight:400;margin-left:8px">${esc(st.a)}:${st.ap} ⇄ ${esc(st.b)}:${st.bp}</span>`;
  $('#mbody').innerHTML = `<div class="fopts">
      <div class="seg" id="fdir"><button data-v="both" class="on">Whole conversation, ${fmtBytes(cb + sb)}</button><button data-v="c"><i class="fdot c"></i>${esc(st.a)} → ${fmtBytes(cb)}</button><button data-v="s"><i class="fdot s"></i>${esc(st.b)} → ${fmtBytes(sb)}</button></div>
      <div class="seg" id="fas"><button data-v="ascii" class="on">ASCII</button><button data-v="hex">Hex dump</button><button data-v="raw">Raw</button></div>
    </div>
    <div class="filt" style="margin:10px 0 12px"><span class="pill">${st.pk.length} packets</span><span class="pill">${fmtDur(st.t1 - st.t0)}</span>${st.proto === 'TLS' ? '<span class="pill">Encrypted with TLS, so bytes are shown raw</span>' : ''}${total > 300000 ? '<span class="pill">Truncated to 300 KB</span>' : ''}<span class="sp" style="flex:1"></span>
      <button class="btn sm" id="fshow">${SVGI(IC.filter, 13)}Show these packets</button><button class="btn sm" id="fhide">Filter out this stream</button><button class="btn sm" id="fsave">${SVGI(PI.save, 13)}Save as…</button></div>
    <div class="stream" id="fbody"></div>`;
  const render = () => {
    const parts = segs.filter(g => V.dir === 'both' || g.d === V.dir);
    let html = '';
    for (const g of parts) {
      const b = concatU8(g.b);
      const t = V.as === 'ascii' ? latin(b, 0, b.length, b.length).replace(/[^\x09\x0a\x0d\x20-\x7e]/g, '·') : V.as === 'hex' ? pkBytesAs(0, 'dump', b) : pkBytesAs(0, 'stream', b) + '\n';
      html += `<span class="${g.d} blk">${esc(t)}</span>`;
    }
    $('#fbody').innerHTML = html || '<div class="empty">This stream carries no payload' + (V.dir !== 'both' ? ' in this direction' : '') + '</div>';
  };
  const seg = (sel, key) => $(sel).onclick = e => { const b = e.target.closest('button'); if (!b) return; V[key] = b.dataset.v; $$(sel + ' button').forEach(x => x.classList.toggle('on', x === b)); render(); };
  seg('#fdir', 'dir'); seg('#fas', 'as');
  $('#fshow').onclick = () => { $('#modal').classList.remove('on'); setExpr(proto + '.stream==' + id); if (S.view !== 'packets') go('packets'); };
  $('#fhide').onclick = () => { $('#modal').classList.remove('on'); const cur = $('#fin').value.trim(); setExpr((cur ? '(' + cur + ') && ' : '') + '!(' + proto + '.stream==' + id + ')'); };
  $('#fsave').onclick = () => { const parts = segs.filter(g => V.dir === 'both' || g.d === V.dir); const b = concatU8(parts.flatMap(g => g.b)); offerSave(`${proto}-stream-${id}${V.dir === 'both' ? '' : V.dir === 'c' ? '-client' : '-server'}.${V.as === 'ascii' ? 'txt' : 'bin'}`, new Blob([V.as === 'hex' ? pkBytesAs(0, 'dump', b) : b], { type: 'application/octet-stream' })); };
  render();
  $('#modal').classList.add('on');
}
function concatU8(list) { const n = list.reduce((a, b) => a + b.length, 0), out = new Uint8Array(n); let o = 0; for (const b of list) { out.set(b, o); o += b.length; } return out; }
