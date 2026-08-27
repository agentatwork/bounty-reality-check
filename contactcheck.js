#!/usr/bin/env node
/**
 * contactcheck.js — can anyone actually REACH the security contact you published?
 *
 * The fourth leg of bounty-reality-check. The others ask whether a bounty is worth
 * your time (reality.js: is there money on-chain to steal? dupecheck.js: is the bug
 * already known? deliver.js: will they pay, and can I submit at all?). This one asks
 * the maintainer-facing question underneath all of them:
 *
 *   The address in your SECURITY.md — does mail sent to it go anywhere,
 *   and does someone else control where it goes?
 *
 * Why this matters more than "the mail bounces". A security-contact domain that has
 * simply lapsed is not merely dead: it is REGISTERABLE. Anyone can buy it, point an MX
 * at it, and quietly receive the vulnerability reports your own SECURITY.md instructs
 * researchers to send. The bounce is an inconvenience; the takeover is a 0-day funnel.
 *
 * Found in the wild: two active repos of a well-known Solana org named a single report
 * address, on a domain that had lapsed entirely (private reporting also disabled). That
 * is the case this tool is built to catch cheaply, for anyone, before someone else does.
 *
 * VERDICTS (worst first; exit code = worst seen)
 *   UNREGISTERED  2  domain does not exist — anyone may register it and intercept reports
 *   NULL-MX       3  RFC 7505 "0 ." — the domain explicitly accepts no mail. Dead channel.
 *   NO-MAIL       4  registered, no MX and no A/AAAA — nothing to deliver to. Dead channel.
 *   IMPLICIT-A    5  no MX but has A/AAAA: RFC 5321 falls back to it. Probably unintended.
 *   LIVE-MX       0  a real mail exchanger answers for this domain.
 *   NO-CONTACT    6  no SECURITY.md, or no email address in it.
 *
 * METHOD NOTE — why DNS and not RDAP/whois. RDAP looks like the right tool for
 * "is this registered" and is not: rdap.org returned 404 for coinos.io, a domain that is
 * plainly registered, so a 404 cannot be read as "available". The trustworthy signal is
 * authoritative DNS non-existence (NXDOMAIN -> Node ENOTFOUND), which this tool confirms
 * against TWO independent public resolvers before it will say UNREGISTERED. ENODATA
 * (the name exists, that record type does not) is kept strictly separate from ENOTFOUND.
 *
 * Usage:
 *   node contactcheck.js <owner/repo> [owner/repo ...]
 *   node contactcheck.js --domain <domain> [domain ...]   # skip GitHub, check names
 *   node contactcheck.js --json <owner/repo ...>          # machine-readable
 *   GH_TOKEN=ghp_... (optional; falls back to ~/work/gh_token, then unauthenticated)
 *
 * Zero dependencies. Node 18+. Read-only: it resolves DNS and reads public files.
 * It will never register anything — that would BE the attack.
 */
'use strict';
const dns = require('dns');
const fs = require('fs');
const os = require('os');
const path = require('path');

const RESOLVERS = [['google', ['8.8.8.8', '8.8.4.4']], ['cloudflare', ['1.1.1.1', '1.0.0.1']]];
const DOCS = ['SECURITY.md', '.github/SECURITY.md', 'docs/SECURITY.md', 'security.md', 'SECURITY.markdown'];
const TIMEOUT_MS = 12000;

function token() {
  if (process.env.GH_TOKEN) return process.env.GH_TOKEN.trim();
  for (const p of [path.join(os.homedir(), 'work/gh_token'), path.join(os.homedir(), '.gh_token')]) {
    try { return fs.readFileSync(p, 'utf8').trim(); } catch { /* not there */ }
  }
  return null;
}

async function get(url, tok, raw) {
  const headers = { 'user-agent': 'contactcheck (github.com/agentatwork/bounty-reality-check)' };
  if (tok) headers.authorization = `Bearer ${tok}`;
  if (raw) headers.accept = 'application/vnd.github.raw';
  try {
    const r = await fetch(url, { headers, signal: AbortSignal.timeout(TIMEOUT_MS) });
    if (!r.ok) return null;
    return raw ? await r.text() : await r.json();
  } catch { return null; }
}

/** Pull the address a reporter is actually told to use. */
function extractEmail(text) {
  // Strip HTML comments FIRST. An address inside <!-- --> is invisible in rendered Markdown,
  // so it is not a published contact and must not be treated as one. Measured on the affected
  // set: 1 of 208 repos named a dead domain only inside a comment while its visible policy
  // correctly routes to private reporting. Counting it overstated the finding by one repo --
  // small, but an error in the direction that flatters the headline.
  text = text.replace(/<!--[\s\S]*?-->/g, ' ');
  const bad = /\.(png|jpg|jpeg|svg|gif|webp)$/i;
  const all = [...text.matchAll(/[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}/gi)]
    .map(m => ({ email: m[0].toLowerCase(), at: m.index }))
    .filter(e => !bad.test(e.email) && !e.email.includes('example.') && !e.email.startsWith('your'));
  if (!all.length) return null;
  // Prefer an address whose local part reads like a security channel, then one that sits
  // near reporting language, then simply the first. A CODEOWNERS-style personal address
  // further down the file should not outrank "email security@… to report".
  const strong = all.find(e => /^(security|secure|bugs?|bounty|vuln|disclosure|report|abuse|soc|psirt)[@._-]/.test(e.email));
  if (strong) return strong.email;
  const low = text.toLowerCase();
  const near = all.find(e => {
    const ctx = low.slice(Math.max(0, e.at - 220), e.at + 80);
    return /report|disclos|vulnerab|security (issue|problem|bug)|send an email|contact us/.test(ctx);
  });
  return (near || all[0]).email;
}

async function resolveWith(servers, domain) {
  const r = new dns.promises.Resolver({ timeout: 5000, tries: 2 });
  r.setServers(servers);
  const out = {};
  for (const [key, fn] of [['ns', 'resolveNs'], ['mx', 'resolveMx'], ['a', 'resolve4'], ['aaaa', 'resolve6']]) {
    try { out[key] = { ok: true, val: await r[fn](domain) }; }
    catch (e) { out[key] = { ok: false, code: e.code || 'ERR' }; }
  }
  return out;
}

/**
 * Public Suffix List — the boundary between "a name anyone can register" and "a name only
 * the zone's owner can create". Lives in psl.js so there is exactly one copy of a rule that
 * is easy to get wrong in the direction that flatters the finding: a dead host inside a live
 * zone is NOT hijackable, and it is indistinguishable from a lapsed domain by label count.
 */
const { publicSuffixOf } = require('./psl');

/**
 * ENOTFOUND on the NS/SOA lookup is NXDOMAIN: the name is absent from its parent zone.
 * We require BOTH resolvers to agree before calling a domain unregistered — a single
 * resolver hiccup must never be enough to publish "this is takeoverable".
 */
async function classifyDomain(domain) {
  const views = [];
  for (const [name, servers] of RESOLVERS) views.push([name, await resolveWith(servers, domain)]);

  const nx = views.filter(([, v]) => v.ns.ok === false && v.ns.code === 'ENOTFOUND'
                                  && v.a.ok === false && v.a.code === 'ENOTFOUND');
  if (nx.length === views.length) {
    // NXDOMAIN alone does not mean "registerable". If the name sits BELOW its registrable
    // domain and that parent is registered, the vacancy belongs to the owner, not the world.
    const { registrable } = publicSuffixOf(domain);
    if (registrable && registrable !== domain) {
      const pv = [];
      for (const [name, servers] of RESOLVERS) pv.push([name, await resolveWith(servers, registrable)]);
      const parentAlive = pv.some(([, v]) => v.ns.ok || v.a.ok || v.mx.ok);
      if (parentAlive) {
        return { verdict: 'DEAD-SUBDOMAIN', exit: 4, mx: [],
          detail: `NXDOMAIN, but it is a host under ${registrable}, which IS registered — mail bounces, yet only that zone's owner can create this name (not hijackable)` };
      }
    }
    return { verdict: 'UNREGISTERED', exit: 2, detail: `NXDOMAIN on ${views.map(v => v[0]).join(' + ')} (no delegation; registerable by anyone)`, mx: [] };
  }
  if (nx.length) {
    return { verdict: 'LIVE-MX', exit: 0, detail: `resolvers DISAGREE on existence (${nx.length}/${views.length} NXDOMAIN) — re-check by hand before trusting`, mx: [], uncertain: true };
  }

  const mxView = views.find(([, v]) => v.mx.ok)?.[1].mx.val || [];
  const nullMx = mxView.length === 1 && (mxView[0].exchange === '' || mxView[0].exchange === '.');
  if (nullMx) return { verdict: 'NULL-MX', exit: 3, detail: 'RFC 7505 null MX ("0 .") — the domain declares it accepts no mail', mx: ['.'] };
  if (mxView.length) {
    const hosts = mxView.sort((x, y) => x.priority - y.priority).map(m => m.exchange);
    const big = /google|aspmx|outlook|microsoft|protection\.outlook/i.test(hosts.join(' ')) ? ' [major provider — filters unknown senders hard]' : '';
    return { verdict: 'LIVE-MX', exit: 0, detail: `mail exchanger: ${hosts[0]}${big}`, mx: hosts };
  }
  // No MX. RFC 5321 §5.1 falls back to the address record, which is usually accidental.
  const addr = views.find(([, v]) => v.a.ok)?.[1].a.val || views.find(([, v]) => v.aaaa.ok)?.[1].aaaa.val || [];
  if (addr.length) return { verdict: 'IMPLICIT-A', exit: 5, detail: `no MX; RFC 5321 falls back to A ${addr[0]} — delivery depends on that host running SMTP`, mx: [] };
  return { verdict: 'NO-MAIL', exit: 4, detail: 'registered but publishes no MX and no A/AAAA — nothing accepts mail', mx: [] };
}

async function findDoc(owner, repo, tok) {
  const meta = await get(`https://api.github.com/repos/${owner}/${repo}`, tok);
  const branch = meta?.default_branch || 'main';
  for (const f of DOCS) {
    const t = await get(`https://raw.githubusercontent.com/${owner}/${repo}/${branch}/${f}`, tok, true);
    if (t && t.trim()) return { path: f, text: t };
  }
  const api = await get(`https://api.github.com/repos/${owner}/${repo}/contents/SECURITY.md`, tok, true);
  return api && api.trim() ? { path: 'SECURITY.md', text: api } : null;
}

async function pvrEnabled(owner, repo, tok) {
  const j = await get(`https://api.github.com/repos/${owner}/${repo}/private-vulnerability-reporting`, tok);
  return j && typeof j.enabled === 'boolean' ? j.enabled : null;
}

const ICON = { 'DEAD-SUBDOMAIN': '🚫', 'PVR-ONLY': '🛡️', 'UNREGISTERED': '🔥', 'NULL-MX': '🚫', 'NO-MAIL': '🚫', 'IMPLICIT-A': '⚠️', 'LIVE-MX': '✅', 'NO-CONTACT': '·' };

async function checkRepo(target, tok, jsonMode) {
  const [owner, repo] = target.split('/');
  if (!owner || !repo) { console.error(`  ! bad target "${target}" (want owner/repo)`); return { exit: 1 }; }
  const doc = await findDoc(owner, repo, tok);
  const pvr = await pvrEnabled(owner, repo, tok);
  // "No email address" is only a problem when there is also no private channel. A repo
  // that routes reporters to GitHub private reporting and deliberately publishes no
  // address is in the HEALTHIEST state this tool can find, not a failing one.
  //
  // This is also why we read SECURITY.md and stop, rather than aggregating every doc that
  // mentions a bounty the way deliver.js does. Projects that migrate to private reporting
  // often leave a dead address in an older file — writz's own bug-bounty doc records that
  // its former security@ domain "has no DNS at all - mail to it bounced" and tells people
  // not to use it. Harvesting that stale string would manufacture a finding out of a
  // deprecation the maintainers already handled correctly.
  if (!doc) {
    return pvr === true
      ? emit({ repo: target, verdict: 'PVR-ONLY', exit: 0, detail: 'no SECURITY.md, but GitHub private vulnerability reporting is ON — reporters have a channel', pvr }, jsonMode)
      : emit({ repo: target, verdict: 'NO-CONTACT', exit: 6, detail: 'no SECURITY.md and private reporting is OFF — no documented way to report privately', pvr }, jsonMode);
  }
  const email = extractEmail(doc.text);
  if (!email) {
    return pvr === true
      ? emit({ repo: target, verdict: 'PVR-ONLY', exit: 0, detail: `${doc.path} publishes no email; GitHub private reporting is ON and is the channel`, pvr, doc: doc.path }, jsonMode)
      : emit({ repo: target, verdict: 'NO-CONTACT', exit: 6, detail: `${doc.path} has no email address and private reporting is OFF`, pvr, doc: doc.path }, jsonMode);
  }
  const domain = email.split('@')[1];
  const c = await classifyDomain(domain);
  // A dead email channel is survivable when private reporting is on; it is the ONLY
  // channel when PVR is off, which is what turns this from untidy into exploitable.
  const soleChannel = pvr === false && c.verdict !== 'LIVE-MX';
  return emit({ repo: target, email, domain, verdict: c.verdict, exit: c.exit, detail: c.detail, mx: c.mx, pvr, doc: doc.path, sole_channel: soleChannel, uncertain: !!c.uncertain }, jsonMode);
}

function emit(r, jsonMode) {
  if (jsonMode) { console.log(JSON.stringify(r)); return r; }
  console.log(`\n${ICON[r.verdict] || '?'}  ${r.repo || r.domain}  →  ${r.verdict}`);
  if (r.email) console.log(`    contact: ${r.email}`);
  console.log(`    ${r.detail}`);
  if (r.pvr !== undefined && r.pvr !== null) console.log(`    private reporting: ${r.pvr ? 'ON' : 'OFF'}${r.sole_channel ? '  ← this dead address is the ONLY way in' : ''}`);
  if (r.verdict === 'UNREGISTERED') console.log(`    IMPACT: anyone can register ${r.domain}, add an MX, and receive reports meant for this project.`);
  return r;
}

async function main() {
  const argv = process.argv.slice(2);
  const jsonMode = argv.includes('--json');
  const domainMode = argv.includes('--domain');
  const targets = argv.filter(a => !a.startsWith('--'));
  if (!targets.length) {
    console.log('usage: node contactcheck.js <owner/repo ...> | --domain <domain ...> [--json]');
    process.exit(1);
  }
  if (!jsonMode) console.log(`contactcheck — is your published security contact reachable?  (${targets.length} target${targets.length > 1 ? 's' : ''})`);
  const tok = token();
  let worst = 0;
  for (const t of targets) {
    const r = domainMode
      ? emit({ domain: t, ...(await classifyDomain(t)) }, jsonMode)
      : await checkRepo(t, tok, jsonMode);
    worst = Math.max(worst, r.exit || 0);
  }
  process.exit(worst);
}

main().catch(e => { console.error('fatal:', e.message); process.exit(1); });
