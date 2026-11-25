/* ===================== STORY ===================== */
// The attack told as a story anyone can follow: the short version, who's who,
// chapters in the order things happened, how it ended and what to do.
const STORY_CHAPTER = {
  recon: 'Scouting the target', resource: 'The attacker\'s tools', access: 'Breaking in', exec: 'Taking control',
  cred: 'Stealing the keys', disc: 'Looking around inside', lateral: 'Moving to other machines',
  c2: 'Calling home', exfil: 'Taking the data', impact: 'Causing damage',
};
const STORY_VERB = {
  recon: 'scouted your network for a way in', resource: 'brought automated tools', access: 'broke in', exec: 'took control of a machine',
  cred: 'stole passwords and keys', disc: 'explored your network from the inside', lateral: 'tried to reach other machines',
  c2: 'set up a hidden line back to its own server', exfil: 'carried data out of your network', impact: 'tried to knock a service offline',
};
const STORY_ROLE = {
  'Attacker': 'A computer on the internet that started the attack.',
  'AI-driven attacker': 'A computer on the internet that started the attack. It behaved like an AI agent, not a person at a keyboard.',
  'Compromised host': 'One of your machines. The attacker got in and used it for the next steps.',
  'At-risk host': 'One of your machines that downloaded something dangerous.',
  'Victim': 'One of your machines that was targeted.',
  'Internal client': 'One of your machines whose passwords crossed the network unprotected.',
  'C2 server': 'The attacker\'s own server, where commands came from and stolen data went.',
  'Malware host': 'A server that handed out malicious files.',
  'Rogue insider': 'A device inside your network pretending to be something it is not.',
  'Botnet / spoofed': 'Thousands of fake addresses used to flood a target.',
  'AI model API': 'An AI service the attack\'s agent asked what to do next.',
  'External domain': 'A web address used to smuggle data or receive signals.',
  'Internal network': 'Many machines on your own network.',
};
const CAST_LABEL = { 'Attacker': 'The attacker', 'AI-driven attacker': 'The attacker (AI)', 'Compromised host': 'Taken over', 'At-risk host': 'At risk', 'Victim': 'Targeted', 'Internal client': 'Exposed passwords', 'C2 server': 'The attacker\'s server', 'Malware host': 'Malware server', 'Rogue insider': 'Impostor device', 'Botnet / spoofed': 'Fake addresses', 'AI model API': 'AI service', 'External domain': 'Smuggling address' };
const SUCCESS_TYPES = new Set(['shell', 'webshell', 'exfil', 'dnstunnel', 'imds', 'beacon', 'llmcalls']);

function storyNames(cap) {
  const names = new Map(), served = new Map();
  for (const r of cap.pk) {
    const s = r.s;
    if (s.dhcp && s.dhcp.host && s.dhcp.yiaddr && s.dhcp.yiaddr !== '0.0.0.0') names.set(s.dhcp.yiaddr, s.dhcp.host);
    if (s.sni && !names.has(s.dst)) names.set(s.dst, s.sni);
    if (s.http && !s.http.resp && s.http.host && !/^\d/.test(s.http.host) && !names.has(s.dst)) names.set(s.dst, s.http.host.split(':')[0]);
  }
  for (const r of cap.pk) { const s = r.s; if (s.http && s.http.resp) { const set = served.get(s.src) || new Set(); set.add('web'); served.set(s.src, set); } if ((s.sp === 88 || s.sp === 389) && s.pll) { const set = served.get(s.src) || new Set(); set.add(s.sp); served.set(s.src, set); } }
  return { names, served };
}
function renderStory() {
  const el = $('#view-story'), cap = S.cap, D = cap.threats, F = cap.flow;
  const { names, served } = storyNames(cap);
  const role = ip => S.roles.get(ip);
  const kind = ip => { const p = served.get(ip) || new Set(); return p.has(88) && p.has(389) ? 'domain controller' : p.has('web') ? 'web server' : 'computer'; };
  const attackers = F ? F.lanes.filter(l => /attacker/i.test(l.role)).length : 0;
  const seen = new Set(); // after the first mention, a host is called by its plain name only
  // how a host is called in the story: plain words first, the address after
  const who = (ip, cap1) => {
    if (!ip) return 'someone';
    if (/hosts$/.test(ip)) return ip.replace(/ hosts$/, ' of your machines');
    if (/spoofed sources/.test(ip)) return 'thousands of fake addresses';
    const r = role(ip), nm = names.get(ip);
    let w;
    if (r === 'AI-driven attacker') w = attackers > 1 ? 'an AI-driven attacker' : 'the AI-driven attacker';
    else if (r === 'Attacker') w = attackers > 1 ? 'an attacker' : 'the attacker';
    else if (r === 'C2 server') w = 'the attacker\'s server';
    else if (r === 'Malware host') w = 'a malware server';
    else if (r === 'AI model API') w = 'the AI service ' + (cap.llmIps && cap.llmIps.get(ip) || nm || '');
    else if (r === 'Rogue insider') w = 'an impostor device';
    else if (isIp(ip) && isPrivate(ip)) w = 'your ' + kind(ip);
    else if (!isIp(ip) && !isMac(ip)) return '<b>' + esc(ip) + '</b>';
    else w = 'a computer on the internet';
    if (cap1) w = w[0].toUpperCase() + w.slice(1);
    if (seen.has(ip) && (attackers < 2 || !/attacker/.test(w))) return `<b title="${esc(ip)}">${esc(w.trim())}</b>`;
    seen.add(ip);
    return `<b>${esc(w.trim())}</b> <span class="st-ip">${esc(ip)}${nm && r !== 'AI model API' && !/^[\d.]+$/.test(nm) ? ', ' + esc(nm) : ''}</span>`;
  };
  const det = (d, k) => (d.details.find(([x]) => x === k) || [])[1];
  const n = x => fmtNum(+x || 0);
  // one paragraph per finding, in words a non-specialist can follow
  const say = (d) => {
    const A = who(d.src, true), B = who(d.dst), t = d.title;
    switch (d.type) {
      case 'portscan': { const open = det(d, 'Open ports'); return `${A} tried ${n(d.count)} of the network "doors" (ports) on ${B}, one after another, to see which ones would open.${open && open !== '—' ? ` It found ${open.split(', ').length} open: ${esc(open)}.` : ' None opened.'}`; }
      case 'udpscan': return `${A} quietly probed ${n(d.count)} more doors on ${B} using a different kind of message.`;
      case 'hscan': { const ports = [d].concat(d.more || []).map(x => (det(x, 'Port') || '').replace(/ \((.+)\)/, ' ($1)')); return `${A} knocked on the same door${ports.length > 1 ? 's' : ''} (${esc(ports.join(', '))}) of ${esc(d.dst.replace(/ hosts$/, ''))} other machines at once, looking for more ways in.`; }
      case 'sweep': case 'arpsweep': return `${A} called out to ${n(d.count)} addresses to find out which machines were switched on.`;
      case 'tool': return `${A} used ${esc(t.replace('Attack tool fingerprint: ', ''))}, a well-known hacking tool, against ${B}.`;
      case 'dirbrute': return `${A} guessed ${n(d.count)} hidden page addresses on ${B}'s website, looking for forgotten admin pages, backups and test files.`;
      case 'web-sqli': return `${A} typed database commands into ${B}'s website instead of normal text (SQL injection)${/success/.test(t) ? ', and the site answered with database errors: the trick worked.' : ', hoping the database would obey.'}`;
      case 'web-lfi': return `${A} tried to trick ${B}'s website into showing its private system files${/success/.test(t) ? ', and got the server\'s list of user accounts back.' : '.'}`;
      case 'web-cmdi': return `${A} slipped system commands into ${B}'s website so the server would run them${/success/.test(t) ? ', and the server did.' : '.'}`;
      case 'web-xss': return `${A} planted script code in ${B}'s website that would run inside visitors' browsers${/success/.test(t) ? ', and the site showed it back unfiltered.' : '.'}`;
      case 'web-log4j': return `${A} sent ${B} a booby-trapped line of text (Log4Shell) that makes vulnerable servers download and run the attacker's code.`;
      case 'web-shellshock': return `${A} hid commands inside a web request header (Shellshock) that old servers execute by mistake.`;
      case 'webshell': { const c = (det(d, 'Commands') || '').split('\n').filter(Boolean).slice(0, 4); return `${A} uploaded a tiny hidden control page (a "web shell") to ${B} and used it like a remote keyboard${c.length ? ', typing commands such as ' + c.map(x => '<code>' + esc(x) + '</code>').join(', ') : ''}.`; }
      case 'download': { const f = (det(d, 'URL') || '').split('?')[0].split('/').pop(); return `${A} downloaded ${f ? '<code>' + esc(f) + '</code>' : 'a program'} from ${B}${/disguised/.test(t) ? ', dressed up as an ordinary picture to slip past filters' : ''}${/stager/.test(t) ? '. It was built to open a secret connection back to the attacker' : ''}.`; }
      case 'shell': return `${A} opened a hidden command line to ${B}. From then on the attacker could type commands on your machine as if sitting in front of it.`;
      case 'badport': return `${A} talked with ${B} on port ${d.dport}, a port that hacking tools like to use.`;
      case 'beacon': return `${A} checked in with ${B} every ${esc(det(d, 'Mean interval') || '')}, like a phone calling home for new orders.`;
      case 'llmcalls': return `${A} kept calling ${B} at a steady rhythm, ${n(d.count)} times.`;
      case 'bruteforce': return `${A} tried to guess the password of ${B} over and over: ${n(d.count)} attempts.`;
      case 'cleartext': return `${A} sent the password of "${esc(det(d, 'Username') || '?')}" to ${B} without any encryption, so anyone listening on the network could read it.`;
      case 'imds': return `Working from ${who(d.src)}, the attacker asked the cloud for that server's own access keys${det(d, 'Token returned') === 'Yes' ? ' and got them' : ''}. With those keys it can act as the server inside your cloud account.`;
      case 'ldaprecon': return `${A} questioned ${B} about your user accounts, administrators and service accounts: drawing a map of who's who and who has power.`;
      case 'kerberoast': return `${A} asked ${B} for login tickets for ${n(d.count)} service accounts. These tickets can be cracked at leisure, offline, to reveal those accounts' passwords.`;
      case 'lateral': return `${A} tried to log in remotely to ${n(d.count)} other machines (${esc((det(d, 'Services') || '').replace(/\d+\//g, ''))}).`;
      case 'dnstunnel': return `${A} hid data inside ${n(d.count)} look-ups for ${esc(d.dst)} names, smuggling roughly ${esc(det(d, 'Est. data encoded') || 'some data')} out through the internet's address book.`;
      case 'dga': return `${A} looked up ${n(d.count)} made-up web addresses, a typical sign of malware searching for its controller.`;
      case 'exfil': return `${A} sent ${esc(det(d, 'Uploaded') || 'a lot of data')} to ${B}, far more than it received back. That is your data leaving the network.`;
      case 'arpspoof': return `A device with the hardware address ${esc(d.srcMac || '')} claimed to be ${who(d.dst)}, so traffic meant for it went to the impostor instead.`;
      case 'rogue-dhcp': return 'A second device started handing out network settings, which can quietly redirect everyone\'s traffic.';
      case 'dhcp-starve': return `Someone asked for network addresses ${n(d.count)} times with made-up identities, trying to use them all up.`;
      case 'synflood': case 'icmpflood': return `${who(d.src, true)} flooded ${B} with ${n(d.count)} requests in a few seconds to knock it offline.`;
      case 'icmptunnel': return `${A} hid data inside ping messages to ${B}.`;
      case 'heartbleed': return `${A} used the Heartbleed bug to read pieces of ${B}'s memory, where passwords and keys can sit.`;
      case 'oast': return `${A} contacted ${esc(d.dst)}, a service attackers use to confirm that a hidden weakness really worked.`;
      case 'aiframework': return `${A} announced itself as ${esc(t.replace('AI attack framework: ', ''))}, an AI system that carries out attacks on its own once it is given a target.`;
      case 'aitool': { const l = det(d, 'Chat-style preamble (strong)') || det(d, 'Credits an AI (strong)'); return `The file ${esc(t.replace('Tool written with AI: ', ''))} that ${who(d.src)} fetched reads as if an AI assistant wrote it${l ? ', down to the line <code>' + esc(l) + '</code>' : ''}.`; }
      case 'ai': {
        const a = d.ai, sg = d.signs.map(g => g.name[0].toLowerCase() + g.name.slice(1));
        if (/^AI agent/.test(t)) return `An AI agent ${a.conf === 'likely' ? 'was probably' : 'may have been'} running on ${who(d.src)}, asking ${who(d.dst)} what to do next while the attack went on.`;
        if (a.conf === 'possible') return `${A} showed a sign of AI help (${esc(sg.join(', '))}). It may be an AI agent, or just ordinary automation.`;
        return `${A} was not a person typing. It behaved like an AI agent: it ${esc(sg.slice(0, 4).join('; '))}${sg.length > 4 ? ', and more' : ''}.`;
      }
      default: return esc(d.summary);
    }
  };
  const when = d => `<span class="st-when">${esc(clock(d.t0).slice(0, 8))}<small>${esc(fmtRel(d.t0 - cap.t0, cap.dur))} in</small></span>`;
  const head = `<header class="st-head"><h1>What happened, in plain words</h1><p class="st-meta">${esc(cap.name)} · ${esc(new Date(cap.t0 * 1000).toLocaleString([], { dateStyle: 'long', timeStyle: 'short' }))} · ${esc(fmtDur(cap.dur))} of traffic</p></header>`;

  if (!D.length || !F) {
    el.innerHTML = `<article class="story">${head}<section class="st-short"><h2>The short version</h2><p>Nothing in this capture looks like an attack. ${fmtNum(cap.pk.length)} packets went back and forth between ${fmtNum(S.A.hosts.size)} computers, mostly ${esc(S.order.slice(0, 3).join(', '))}: the everyday traffic of a working network.</p><p>Capsight checked for scanning, password guessing, break-in attempts, hidden command lines, data leaving the network, AI-driven tools and more, and found none of it.</p></section></article>`;
    return;
  }
  // chapters: one per stage of the attack, in the order the stages began; risks that are not
  // part of the attack (a colleague's password sent in the clear) are told separately at the end
  const bystander = d => d.type === 'aiuse' || (d.type === 'cleartext' && !/Attacker|Compromised/.test(role(d.src) || '') && !/Attacker/.test(role(d.dst) || ''));
  const order = F.steps.map(s => s.d).filter(d => !bystander(d));
  const aside = F.steps.map(s => s.d).filter(bystander);
  const byStage = new Map();
  for (const d of order) { if (!byStage.has(d.stage)) byStage.set(d.stage, { stage: d.stage, ds: [] }); byStage.get(d.stage).ds.push(d); }
  const chapters = [...byStage.values()].sort((a, b) => a.ds[0].t0 - b.ds[0].t0);
  // merge look-alike findings in a chapter (the same scan on three ports reads as one sentence)
  chapters.forEach(c => { const seen = new Map(); c.ds = c.ds.filter(d => { const k = d.type + '|' + d.src; if (['hscan', 'portscan', 'tool', 'aiframework', 'lateral'].includes(d.type) && seen.has(k)) { seen.get(k).more = (seen.get(k).more || []).concat(d); return false; } seen.set(k, d); return true; }); });
  // the short version
  const attackerIds = F.lanes.filter(l => /attacker/i.test(l.role)).map(l => l.id);
  const comp = F.lanes.filter(l => l.role === 'Compromised host').map(l => l.id);
  const stagesSeen = STAGES.filter(s => D.some(d => d.stage === s.k && d.type !== 'aiuse')).map(s => s.k);
  const aiMain = (cap.aiD || []).find(d => d.type === 'ai' && d.ai.sure) || (cap.aiD || []).find(d => d.type === 'aiframework');
  const span = Math.max(...D.map(d => d.t1 || d.t0)) - Math.min(...D.map(d => d.t0));
  const succeeded = D.some(d => SUCCESS_TYPES.has(d.type) || / \(likely successful\)/.test(d.title));
  const subject = attackerIds.length ? (attackerIds.length > 1 ? attackerIds.length + ' attackers on the internet' : (aiMain ? 'An AI-driven attacker' : 'An attacker') + ' on the internet') : 'Someone';
  const has = k => stagesSeen.includes(k);
  const way = list => list.length > 1 ? list.slice(0, -1).join(', ') + ' and ' + list[list.length - 1] : list[0];
  const target = comp[0] || (D.find(d => d.stage === 'access') || {}).dst;
  const beats = [];
  beats.push(`${subject}${attackerIds.length === 1 ? ' (' + esc(attackerIds[0]) + ')' : ''} went after your network.`);
  if (has('recon')) beats.push('First it scouted for a way in, testing doors and guessing hidden pages.');
  if (has('access') || has('exec')) beats.push(`Then it ${has('access') ? 'broke into' : 'got onto'} ${target && isIp(target) ? 'your ' + esc(kind(target)) + ' ' + esc(target) : 'one of your machines'}${has('exec') ? ' and took control of it' : ''}.`);
  const inside = [has('cred') && 'stole passwords and keys', has('disc') && 'explored your network', has('lateral') && 'tried to reach other machines'].filter(Boolean);
  if (inside.length) beats.push(`From there it ${way(inside)}.`);
  const out = [has('c2') && 'set up a hidden line to its own server', has('exfil') && 'carried data out of your network'].filter(Boolean);
  if (out.length) beats.push(`It ${way(out)}.`);
  if (has('impact')) beats.push('Finally, it tried to knock a service offline.');
  beats.push(`All of this happened within ${esc(fmtDur(Math.max(span, 1)))}.`);
  if (aiMain) beats.push('The pace and the pattern point to an AI agent doing the work, not a person.');
  if (!succeeded) beats.push('Nothing shows the attacker actually got in.');
  const short = beats.join(' ');
  const cast = F.lanes.filter(l => l.role !== 'Internal network' && l.role !== 'External host' && l.role !== 'Internal host');
  const castHtml = cast.map(l => `<li class="st-cast-${(ROLE_CLS[l.role] || 'r-none').slice(2)}"><b>${esc(CAST_LABEL[l.role] || l.role)}</b><span class="st-ip">${esc(l.id)}${names.get(l.id) && !/^[\d.]+$/.test(names.get(l.id)) ? ', ' + esc(names.get(l.id)) : ''}</span><p>${esc(STORY_ROLE[l.role] || '')}</p></li>`).join('');
  const chHtml = chapters.map((c, i) => `<section class="st-ch"><div class="st-rail"><i class="s-${c.ds.reduce((m, d) => SEV_RANK[d.sev] > SEV_RANK[m] ? d.sev : m, 'low')}"></i></div><div class="st-body">
      <p class="st-num">Chapter ${i + 1}${when(c.ds[0])}</p><h2>${esc(STORY_CHAPTER[c.stage] || c.stage)}</h2>
      ${c.ds.map(d => `<p class="st-p">${say(d)} <button class="st-show" data-sd="${d.id}" title="Open the packets behind this">Show me</button></p>`).join('')}
      <p class="st-terms">In security terms: ${esc(STAGES.find(s => s.k === c.stage)?.name || c.stage)}, ${[...new Set(c.ds.map(d => d.tech))].map(esc).join(', ')}</p></div></section>`).join('');
  // how it ended and what to do
  const last = order[order.length - 1];
  const ending = succeeded
    ? `By the end of the capture, ${comp.length ? who(comp[0]) + ' was under the attacker\'s control' : 'the attacker had what it came for'}${D.some(d => d.type === 'exfil' || d.type === 'dnstunnel') ? ' and data had left your network' : ''}. The last thing seen: ${say(last).replace(/^(<b[^>]*>)(\w)/, (m, t, c) => t + c.toLowerCase())}`
    : `The capture ends with ${say(last)} There is no sign that any of it worked, but the attempts show someone is actively looking for a way in.`;
  const todo = [];
  if (attackerIds.length) todo.push(`Block ${attackerIds.map(esc).join(', ')} at your firewall.`);
  if (comp.length) todo.push(`Disconnect ${comp.map(esc).join(', ')} from the network and have it checked: assume the attacker left a back door.`);
  if (D.some(d => d.type === 'cleartext' || d.type === 'kerberoast' || d.type === 'imds' || d.type === 'bruteforce')) todo.push('Change every password, key and token that appears in this story, starting with admin and service accounts.');
  if (D.some(d => d.type === 'webshell' || d.type.startsWith('web-'))) todo.push('Fix the website weakness that let the attacker in, and remove any files it uploaded.');
  if (D.some(d => d.type === 'exfil' || d.type === 'dnstunnel')) todo.push('Work out what data left the network: it may need to be reported.');
  if (aiMain) todo.push('Expect it to come back fast: AI-driven attacks retry in minutes. Remove public maps of your apps that nobody needs and require a login everywhere.');
  todo.push('Share this story, or the full report, with whoever looks after your security.');
  el.innerHTML = `<article class="story">${head}
    <section class="st-short"><h2>The short version</h2><p>${short}</p>${aiMain ? `<p class="st-ai"><span class="aibadge">AI</span>${esc(aiHeadline(cap))}.</p>` : ''}</section>
    <section class="st-cast"><h2>Who's who</h2><ul>${castHtml}</ul></section>
    <section class="st-chs"><h2 class="st-h2">What happened, step by step</h2>${chHtml}</section>
    ${aside.length ? `<section class="st-aside"><h2>Also noticed</h2><p>Not part of the attack itself, but worth fixing:</p>${aside.map(d => `<p class="st-p">${say(d)} <button class="st-show" data-sd="${d.id}">Show me</button></p>`).join('')}</section>` : ''}
    <section class="st-end"><h2>How it ended</h2><p>${ending}</p><h2>What to do now</h2><ol>${todo.map(x => `<li>${x}</li>`).join('')}</ol>
      <div class="st-acts"><button class="btn primary" id="stCopy">${SVGI(IC.copy, 15)}Copy the story</button><button class="btn" id="stReport">Download the full report</button></div></section>
  </article>`;
  $$('.st-show', el).forEach(b => b.onclick = () => { const d = cap.threats[+b.dataset.sd]; S.chips.ev = { set: new Set(d.ev), label: d.title }; S.chips.time = null; S.sel = d.ev[0]; applyFilter(); go('packets'); setTimeout(() => selectPacket(d.ev[0], true), 30); });
  $('#stCopy').onclick = () => { const txt = el.querySelector('.story').innerText.replace(/\s*Show me/g, '').replace(/Copy the story\s*Download the full report\s*$/, '').trim(); pkCopy(txt, 'Story copied. Paste it into an email or a ticket.'); };
  $('#stReport').onclick = () => $('#reportBtn').click();
}
