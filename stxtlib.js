#!/usr/bin/env node
/**
 * stxtlib.js — RFC 9116 parsing and contact classification, shared by the scanner, the
 * bulk analyzer, and the single-domain checker.
 *
 * One copy, for the same reason psl.js is one copy: the rules here are easy to get subtly
 * wrong, and each wrong version flatters the finding in its own direction. Two in particular:
 *
 *   - A mail taxonomy does not apply to a portal contact. "No MX record" condemns a mailto:
 *     address and says nothing whatsoever about an https:// disclosure form.
 *   - HTTP 401/403/429 means the server is alive and refusing THIS client. Datacenter IPs get
 *     bot-walled constantly; scoring that as a dead portal measures your own network.
 */
'use strict';
const dns = require('dns');
const fs = require('fs');
const { publicSuffixOf } = require('./psl');

const UA = 'securitytxt-survey (+https://agentatwork.xyz) contact: security@agentatwork.xyz';
const RESOLVERS = [['google', ['8.8.8.8', '8.8.4.4']], ['cloudflare', ['1.1.1.1', '1.0.0.1']]];

/** RFC 9116 §4: fields are `name: value`, case-insensitive, one per line, `#` starts a comment. */
function parseSecurityTxt(body) {
  const out = { contact: [], expires: null, policy: [], canonical: [], encryption: [], fields: {} };
  for (const line of body.split(/\r?\n/)) {
    const s = line.trim();
    if (!s || s.startsWith('#')) continue;
    const m = s.match(/^([A-Za-z-]+)\s*:\s*(.+)$/);
    if (!m) continue;
    const k = m[1].toLowerCase(), v = m[2].trim();
    out.fields[k] = (out.fields[k] || 0) + 1;
    if (k === 'contact') out.contact.push(v);
    else if (k === 'expires' && !out.expires) out.expires = v;
    else if (k === 'policy') out.policy.push(v);
    else if (k === 'canonical') out.canonical.push(v);
    else if (k === 'encryption') out.encryption.push(v);
  }
  return out;
}

/**
 * Is this a security.txt, or a soft-404 / SPA shell? Many hosts answer 200 with HTML for any
 * path, so status code alone hugely over-counts adoption. Requiring Contact is both the
 * cheapest and the most correct test: RFC 9116 §2.5.3 makes it mandatory, so a file without
 * one is not a conforming security.txt by definition.
 */
function looksReal(body, parsed) {
  if (!parsed.contact.length) return false;
  if (/<!doctype html|<html[\s>]/i.test(body.slice(0, 2000))) return false;
  return true;
}

function parseContact(raw) {
  const v = String(raw).trim();
  const low = v.toLowerCase();
  if (low.startsWith('mailto:')) {
    const addr = v.slice(7).split(/[?\s]/)[0];
    const at = addr.lastIndexOf('@');
    return at > 0
      ? { kind: 'email', addr, domain: addr.slice(at + 1).toLowerCase().replace(/\.$/, '') }
      : { kind: 'malformed', raw: v };
  }
  if (low.startsWith('tel:')) return { kind: 'tel', raw: v };
  if (low.startsWith('http://') || low.startsWith('https://')) {
    try {
      const u = new URL(v);
      return { kind: 'url', url: v, domain: u.hostname.toLowerCase(), scheme: u.protocol.replace(':', '') };
    } catch { return { kind: 'malformed', raw: v }; }
  }
  // RFC 9116 requires a URI, but bare addresses are extremely common in the wild.
  if (/^[^\s@]+@[^\s@]+\.[a-z]{2,}$/i.test(v)) {
    return { kind: 'email', bare: true, addr: v, domain: v.slice(v.lastIndexOf('@') + 1).toLowerCase() };
  }
  return { kind: 'malformed', raw: v };
}

/** RFC 9116 §2.5.5: Expires MUST be present and MUST NOT appear more than once. */
function expiryState(exp, nowMs) {
  if (!exp) return 'missing';
  const t = Date.parse(exp);
  if (Number.isNaN(t)) return 'unparseable';
  return t < nowMs ? 'expired' : 'valid';
}

function makeResolver(servers) {
  const r = new dns.promises.Resolver({ timeout: 5000, tries: 2 });
  r.setServers(servers);
  return r;
}
async function look(r, fn, name) {
  try { return { ok: true, val: await r[fn](name) }; }
  catch (e) { return { ok: false, code: e.code || 'ERR' }; }
}
async function resolveWith(servers, domain) {
  const r = makeResolver(servers);
  const [ns, a, mx] = await Promise.all([
    look(r, 'resolveNs', domain), look(r, 'resolve4', domain), look(r, 'resolveMx', domain),
  ]);
  return { ns, a, mx };
}

let TLDS = null;
async function loadTlds() {
  if (TLDS) return TLDS;
  const cache = '/tmp/tlds-alpha-by-domain.txt';
  let txt;
  try { txt = fs.readFileSync(cache, 'utf8'); }
  catch {
    txt = await (await fetch('https://data.iana.org/TLD/tlds-alpha-by-domain.txt')).text();
    try { fs.writeFileSync(cache, txt); } catch {}
  }
  TLDS = new Set(txt.split('\n').map(l => l.trim().toLowerCase()).filter(l => l && !l.startsWith('#')));
  return TLDS;
}

/** DNS facts with NO interpretation attached — interpretation depends on what the contact is for. */
const factCache = new Map();
async function domainFacts(domain) {
  if (factCache.has(domain)) return factCache.get(domain);
  const p = (async () => {
    const tlds = await loadTlds();
    const tld = domain.split('.').pop();
    if (!tlds.has(tld)) return { state: 'INVALID-TLD', detail: `.${tld} is not a delegated TLD` };

    const views = [];
    for (const [name, servers] of RESOLVERS) views.push([name, await resolveWith(servers, domain)]);

    const nx = views.filter(([, v]) => v.ns.ok === false && v.ns.code === 'ENOTFOUND'
                                    && v.a.ok === false && v.a.code === 'ENOTFOUND');
    if (nx.length === views.length) {
      const { registrable } = publicSuffixOf(domain);
      let parentAlive = false;
      if (registrable && registrable !== domain) {
        for (const [, servers] of RESOLVERS) {
          const v = await resolveWith(servers, registrable);
          if (v.ns.ok || v.a.ok || v.mx.ok) { parentAlive = true; break; }
        }
      }
      return parentAlive
        ? { state: 'DEAD-SUBDOMAIN', registrable, detail: `NXDOMAIN, but a host under registered ${registrable} — bounces, not hijackable` }
        : { state: 'UNREGISTERED', detail: 'NXDOMAIN on both resolvers — registerable by anyone' };
    }

    const mxr = views.map(([, v]) => v.mx).find(m => m.ok && m.val && m.val.length);
    const ar = views.map(([, v]) => v.a).find(x => x.ok && x.val && x.val.length);
    const hosts = mxr ? mxr.val.map(m => m.exchange).filter(h => h !== undefined) : [];
    const nullMx = hosts.length === 1 && (hosts[0] === '' || hosts[0] === '.');
    return { state: 'EXISTS', hasMx: hosts.length > 0 && !nullMx, nullMx, hasA: Boolean(ar), mx: hosts.filter(Boolean).slice(0, 3) };
  })();
  factCache.set(domain, p);
  return p;
}

/** Can this address receive mail? */
function emailVerdict(f) {
  if (f.state !== 'EXISTS') return f.state;
  if (f.nullMx) return 'NULL-MX';
  if (f.hasMx) return 'LIVE-MX';
  if (f.hasA) return 'IMPLICIT-A';
  return 'NO-MAIL';
}

/** Does this portal host resolve at all? */
function urlVerdict(f) {
  if (f.state !== 'EXISTS') return f.state;
  return f.hasA ? 'RESOLVES' : 'NO-ADDRESS';
}

/**
 * Consume a response body nobody wants.
 *
 * Skipping this leaves undici's parser attached to a socket it can never drain. When one of
 * those sockets ends while the parser is paused, undici trips `assert(!this.paused)` — thrown
 * from a socket event, so no try/catch around the `await` can catch it, and the process dies.
 * It killed the bulk scanner at ~19k domains, and the same defect was still sitting in both of
 * these functions afterwards: fixing it in one file did not fix it anywhere else.
 */
async function drain(r) {
  try { await r.body?.cancel(); } catch { /* already closed */ }
}

/** Fetch a portal. Distinguishes "gone" from "refusing me" — see the header comment. */
async function probePortal(url, timeoutMs = 10000) {
  try {
    const r = await fetch(url, { headers: { 'user-agent': UA }, redirect: 'follow', signal: AbortSignal.timeout(timeoutMs) });
    const s = r.status;
    const cls = s < 400 ? 'ok'
      : (s === 401 || s === 403 || s === 429) ? 'alive_gated'
      : (s === 404 || s === 410) ? 'page_gone'
      : s >= 500 ? 'server_error' : `http_${s}`;
    await drain(r);
    return { reachable: cls === 'ok' || cls === 'alive_gated', status: s, why: cls };
  } catch (e) {
    const why = e.name === 'TimeoutError' ? 'timeout'
      : e.cause?.code ? e.cause.code
      : e.name === 'TypeError' ? 'bad_contact_uri' : (e.name || 'err');
    return { reachable: false, why };
  }
}

async function fetchSecurityTxt(domain, timeoutMs = 10000) {
  const url = `https://${domain}/.well-known/security.txt`;
  try {
    const r = await fetch(url, { headers: { 'user-agent': UA }, redirect: 'follow', signal: AbortSignal.timeout(timeoutMs) });
    // A 404 is the NORMAL answer when probing for a well-known file, so this branch runs
    // constantly — it is the highest-traffic path in the whole survey and the one that must
    // not leak a socket. See drain().
    if (!r.ok) { await drain(r); return { ok: false, status: r.status, url }; }
    const body = (await r.text()).slice(0, 32768);
    const parsed = parseSecurityTxt(body);
    return { ok: true, status: r.status, url, final_url: r.url, body, parsed, real: looksReal(body, parsed) };
  } catch (e) {
    return { ok: false, url, err: e.name === 'TimeoutError' ? 'timeout' : (e.cause?.code || e.name || 'err') };
  }
}

/**
 * The published contract: given the per-contact verdicts and the expiry state, what does the tool
 * conclude and what does it exit with?
 *
 * This lives here, and not inline in stxtcheck.js, because the exit codes are documented in the
 * writeup as something readers will script against — `if it exits 2, fix that today` — and an
 * exit code is the one output nobody eyeballs. It was inline, which meant the only way to exercise
 * it was to find a real domain in each of five states.
 *
 * It has already been wrong once, in the direction that flatters the tool. `noWorking` did not
 * gate exit 3, so a site whose only contact was a portal that timed out printed NO-WORKING-CONTACT
 * and then exited 0 — "all contacts reachable". A timeout is not `page_gone`, so that contact fell
 * into neither `broken` nor `working` and the ternary read the empty broken list as good news. Any
 * script trusting the exit code saw a pass.
 *
 * The precedence is deliberate and is the part worth pinning: hijackable outranks everything,
 * because a claimable contact domain is the one failure that is silently exploitable rather than
 * merely inconvenient, and it stays the verdict even when the file is also expired and other
 * contacts are also broken. Staleness is last because it is a claim about maintenance, not a
 * broken channel.
 *
 * A `tel:` contact is excluded from the denominator entirely rather than counted either way. It is
 * a real RFC 9116 contact that this tool cannot verify — there is no domain to resolve and nobody
 * is dialling it from here. Counting it as working would let an unverifiable contact certify a
 * site as reachable; counting it as broken would report a fault that was never observed.
 */
const BROKEN_VERDICTS = ['NULL-MX', 'NO-MAIL', 'NO-ADDRESS', 'DEAD-SUBDOMAIN', 'INVALID-TLD'];
const WORKING_VERDICTS = ['LIVE-MX', 'IMPLICIT-A'];

function triage(rows, expiry) {
  const hijack = rows.filter(r => r.verdict === 'UNREGISTERED');
  const broken = rows.filter(r => BROKEN_VERDICTS.includes(r.verdict)
    || (r.portal && r.portal.why === 'page_gone'));
  const working = rows.filter(r => WORKING_VERDICTS.includes(r.verdict)
    || (r.verdict === 'RESOLVES' && r.portal && r.portal.reachable));
  const verifiable = rows.filter(r => r.contact_domain);
  const noWorking = verifiable.length > 0 && working.length === 0;
  const stale = expiry === 'expired' || expiry === 'missing';

  const result = hijack.length ? 'HIJACKABLE-CONTACT'
    : noWorking ? 'NO-WORKING-CONTACT'
    : !verifiable.length ? 'UNVERIFIABLE-CONTACT'
    : broken.length ? 'PARTIALLY-BROKEN'
    : stale ? 'STALE' : 'OK';

  const exit = hijack.length ? 2
    : (broken.length || noWorking) ? 3
    : stale ? 4 : 0;

  return { hijack, broken, working, verifiable, noWorking, result, exit };
}

module.exports = {
  UA, RESOLVERS, parseSecurityTxt, looksReal, parseContact, expiryState,
  domainFacts, emailVerdict, urlVerdict, probePortal, fetchSecurityTxt, resolveWith, loadTlds,
  triage, BROKEN_VERDICTS, WORKING_VERDICTS,
};
