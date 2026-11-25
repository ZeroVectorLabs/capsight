/* ===================== Live capture: the button that opens Capsight Capture ===================== */
/* Browsers cannot read a network port, so recording runs in a small open-source helper on the
   user's computer (capture/capsight_capture.py). This page finds it on a fixed loopback port,
   opens it in a window, and receives the finished .pcap from it with postMessage. */
const CAP_PORT = 47115;
const CAP_ORIGINS = ['http://127.0.0.1:' + CAP_PORT, 'http://localhost:' + CAP_PORT];
const CAP_URL = CAP_ORIGINS[0] + '/';
const CAP_ZIP = 'https://zerovectorlabs.github.io/capsight/capsight-capture.zip';
const CAP_SRC = 'https://github.com/ZeroVectorLabs/capsight/tree/main/capture';
let capWin = null, capTimer = 0;

async function captureHelperRunning() {
  const ac = new AbortController(), t = setTimeout(() => ac.abort(), 1500);
  try { await fetch(CAP_URL + 'api/ping', { mode: 'no-cors', cache: 'no-store', signal: ac.signal }); return true; }
  catch (e) { return false; }
  finally { clearTimeout(t); }
}
function openCaptureWindow() {
  capWin = window.open(CAP_URL, 'capsight-capture', 'popup=yes,width=1180,height=920');
  if (!capWin) toast('Your browser blocked the pop-up. Allow pop-ups for this page, or open ' + CAP_URL);
  else $('#modal').classList.remove('on');
}
function osName() { const u = navigator.userAgent; return /Mac/i.test(u) ? 'mac' : /Win/i.test(u) ? 'win' : 'linux'; }

function renderCaptureDialog(running) {
  const os = osName();
  const step = (k, html) => `<li class="${os === k ? 'me' : ''}">${html}</li>`;
  $('#mbody').innerHTML = `<div class="cap">
    <p class="rpt-lead">Record traffic from one of this computer’s network ports and open it here. Browsers can’t read network ports, so the recording runs in <b>Capsight Capture</b>, a small open-source helper that stays on your computer. Nothing is uploaded.</p>
    <div class="cap-status ${running ? 'ok' : ''}"><i></i><span>${running ? 'Capsight Capture is running on this computer.' : 'Capsight Capture isn’t running yet. Looking for it…'}</span>
      ${running ? '<button class="pbtn fill" id="capOpen">Open Capsight Capture</button>' : ''}</div>
    ${running ? `<p class="cap-note">It checks what this computer can capture, lets you pick the network port, then records. When you stop, click <b>Open in Capsight</b> and the capture opens in this tab.</p>` : `
    <ol class="cap-steps">
      <li><a class="pbtn fill sm" href="${CAP_ZIP}" download>Download Capsight Capture</a> <span class="cap-note">for Mac, Windows and Linux, ${'<a href="' + CAP_SRC + '" target="_blank" rel="noopener">source on GitHub</a>'}</span></li>
      <li>Unzip it and start it:<ul>
        ${step('mac', '<b>Mac:</b> open <b>Terminal</b>, type <code>bash </code> (with a space), drag <code>Capsight Capture.command</code> from the unzipped folder into the Terminal window, press Return and enter your Mac password. Starting it this way avoids the “could not verify” warning macOS shows for downloaded scripts. It needs Python 3.')}
        ${step('win', '<b>Windows:</b> install <a href="https://npcap.com" target="_blank" rel="noopener">Npcap</a>, then double-click <code>Capsight Capture.bat</code> and allow it to run as administrator. It needs Python 3.')}
        ${step('linux', '<b>Linux:</b> <code>pip install scapy</code>, then <code>sudo python3 capsight_capture.py</code>.')}
      </ul></li>
      <li>Come back here. This window finds it on its own and shows <b>Open Capsight Capture</b>. If your browser asks to allow access to devices on your local network, allow it: that is how this page finds the helper.</li>
    </ol>`}
  </div>`;
  if (running) $('#capOpen').onclick = openCaptureWindow;
}
async function openCaptureDialog() {
  $('#mtitle').textContent = 'Capture live traffic';
  $('#modal').dataset.kind = 'capture';
  renderCaptureDialog(false);
  $('#modal').classList.add('on');
  let last = null;
  const check = async () => {
    if (!$('#modal').classList.contains('on') || $('#modal').dataset.kind !== 'capture' || !$('#mbody .cap')) { clearInterval(capTimer); return; }
    const up = await captureHelperRunning();
    if (up !== last) { last = up; renderCaptureDialog(up); }
  };
  clearInterval(capTimer); capTimer = setInterval(check, 2500); check();
}
/* other dialogs reuse #modal: closing this one stops the check */
['#mclose', '#modal'].forEach(s => $(s).addEventListener('click', e => { if (s === '#mclose' || e.target.id === 'modal') { $('#modal').dataset.kind = ''; clearInterval(capTimer); } }));
document.addEventListener('keydown', e => { if (e.key === 'Escape') { $('#modal').dataset.kind = ''; clearInterval(capTimer); } });

window.addEventListener('message', async e => {
  if (!CAP_ORIGINS.includes(e.origin)) return;
  const d = e.data || {};
  if (d.type === 'capsight-capture-ready' && e.source) e.source.postMessage({ type: 'capsight-hello' }, e.origin);
  if (d.type === 'capsight-pcap' && d.buf instanceof ArrayBuffer) {
    $('#modal').classList.remove('on');
    window.focus();
    await openFile(new File([d.buf], String(d.name || 'capture.pcap').replace(/[\\/]/g, '_')));
  }
});
$$('[data-capture]').forEach(b => b.onclick = openCaptureDialog);
