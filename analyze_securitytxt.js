#!/usr/bin/env node
/**
 * analyze_securitytxt.js — classify the CONTACTS found by scan_securitytxt.js.
 *
 *   node analyze_securitytxt.js <scan.jsonl> <out.json> [dnsConcurrency]
 *
 * The existing literature on security.txt stops at the regex. "63.5% of Contact emails were
 * valid" means the string had an @ in it — not that a mailbox exists, not that the domain
 * resolves, and certainly not that the domain is still owned by the people who published it.
 * This asks the question one step downstream: for each Contact, does the domain exist, and if
 * it does not, could a stranger register it and start receiving the reports?
 *
 * Three contact forms, three different failure modes:
 *   mailto:  — dead domain means mail bounces, or worse, is silently collected by a new owner.
 *   https:// — dead domain means the disclosure PORTAL is claimable. Arguably worse than the
 *              email case: an attacker who owns the domain can serve a form that looks right.
 *   tel:     — not checkable here; counted and set aside.
 *
 * Verdicts mirror contactcheck.js so the two surveys are directly comparable:
 *   LIVE-MX / IMPLICIT-A / NULL-MX / NO-MAIL / DEAD-SUBDOMAIN / UNREGISTERED / INVALID-TLD
 *
 * Read-only. Nothing is registered, ever, and no address is contacted.
 */
'use strict';
const fs = require('fs');
const dns = require('dns');
const { publicSuffixOf } = require('./psl');

const [, , inPath, outPath, concArg, rankArg] = process.argv;
if (!inPath || !outPath) {
  console.error('usage: node analyze_securitytxt.js <scan.jsonl> <out.json> [dnsConcurrency] [rank.csv]');
  process.exit(1);
}
const CONC = parseInt(concArg || '24', 10);
const RANK_CSV = rankArg || '/tmp/tranco200k.csv';

/**
 * Popularity buckets. A single pooled percentage over 200k domains is close to meaningless
 * here, because the population is not homogeneous: the top of the list is a few thousand
 * organisations with security teams, and the tail is everybody else. Published adoption
 * figures disagree wildly (0.7% of the top 1M vs 13% of the top 3k) for exactly this reason —
 * they are measuring different populations and quoting one number.
 *
 * It also decides the central question. If lapsed contacts cluster in the tail, the headline
 * is that security.txt rots where nobody is watching. If they are flat across rank, the
 * headline is that publishing the file is no evidence anyone maintains it. Either is a
 * finding; reporting one pooled average would hide both.
 */
const BUCKETS = [
  ['1-1k', 1, 1000], ['1k-10k', 1001, 10000], ['10k-50k', 10001, 50000],
  ['50k-100k', 50001, 100000], ['100k-200k', 100001, Infinity],
];
const bucketOf = (rank) => {
  if (!rank) return 'unranked';
  for (const [name, lo, hi] of BUCKETS) if (rank >= lo && rank <= hi) return name;
  return 'unranked';
};

function loadRanks() {
  const m = new Map();
  try {
    for (const line of fs.readFileSync(RANK_CSV, 'utf8').split('\n')) {
      const c = line.indexOf(',');
      if (c < 0) continue;
      const r = parseInt(line.slice(0, c), 10);
      if (r) m.set(line.slice(c + 1).trim().toLowerCase(), r);
    }
  } catch { console.log(`(no rank file at ${RANK_CSV} — rank analysis skipped)`); }
  return m;
}

const RESOLVERS = [['google', ['8.8.8.8', '8.8.4.4']], ['cloudflare', ['1.1.1.1', '1.0.0.1']]];

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

/** IANA root zone — a string in a TLD that does not exist is a typo nobody can register. */
let TLDS = null;
async function loadTlds() {
  if (TLDS) return TLDS;
  const cache = '/tmp/tlds-alpha-by-domain.txt';
  let txt;
  try { txt = fs.readFileSync(cache, 'utf8'); }
  catch {
    txt = await (await fetch('https://data.iana.org/TLD/tlds-alpha-by-domain.txt')).text();
    fs.writeFileSync(cache, txt);
  }
  TLDS = new Set(txt.split('\n').map(l => l.trim().toLowerCase()).filter(l => l && !l.startsWith('#')));
  return TLDS;
}

/**
 * DNS facts about a name, with NO interpretation attached. Interpretation depends on what the
 * contact is FOR: "no MX record" condemns a mailto: address and says nothing at all about an
 * https:// disclosure form. Mixing the two taxonomies makes every large company look broken,
 * because their Contact is a web portal and portals do not have MX records.
 */
const cache = new Map();
async function domainFacts(domain) {
  if (cache.has(domain)) return cache.get(domain);
  const p = (async () => {
    const tlds = await loadTlds();
    const tld = domain.split('.').pop();
    if (!tlds.has(tld)) return { state: 'INVALID-TLD', detail: `.${tld} is not in the IANA root zone` };

    const views = [];
    for (const [name, servers] of RESOLVERS) views.push([name, await resolveWith(servers, domain)]);

    const nx = views.filter(([, v]) => v.ns.ok === false && v.ns.code === 'ENOTFOUND'
                                    && v.a.ok === false && v.a.code === 'ENOTFOUND');
    if (nx.length === views.length) {
      // NXDOMAIN is not registerable. A name below its registrable domain can only be created
      // by that zone's owner — it bounces, but no outsider can intercept it.
      const { registrable } = publicSuffixOf(domain);
      let parentAlive = false;
      if (registrable && registrable !== domain) {
        for (const [, servers] of RESOLVERS) {
          const v = await resolveWith(servers, registrable);
          if (v.ns.ok || v.a.ok || v.mx.ok) { parentAlive = true; break; }
        }
      }
      return parentAlive
        ? { state: 'DEAD-SUBDOMAIN', registrable, detail: `NXDOMAIN, but a host under registered ${registrable} — not hijackable` }
        : { state: 'UNREGISTERED', detail: 'NXDOMAIN on both resolvers — registerable by anyone' };
    }

    const mxr = views.map(([, v]) => v.mx).find(m => m.ok && m.val && m.val.length);
    const ar = views.map(([, v]) => v.a).find(x => x.ok && x.val && x.val.length);
    const hosts = mxr ? mxr.val.map(m => m.exchange).filter(h => h !== undefined) : [];
    const nullMx = hosts.length === 1 && (hosts[0] === '' || hosts[0] === '.');
    return {
      state: 'EXISTS',
      hasMx: hosts.length > 0 && !nullMx, nullMx, hasA: Boolean(ar),
      mx: hosts.filter(Boolean).slice(0, 3),
    };
  })();
  cache.set(domain, p);
  return p;
}

/** Can this address receive mail? */
function emailVerdict(f) {
  if (f.state !== 'EXISTS') return f.state;
  if (f.nullMx) return 'NULL-MX';                 // RFC 7505: declares it accepts no mail
  if (f.hasMx) return 'LIVE-MX';
  if (f.hasA) return 'IMPLICIT-A';                // RFC 5321 implicit MX — deliverable, but fragile
  return 'NO-MAIL';
}

/** Can this portal be reached — and if not, can a stranger put one there? */
function urlVerdict(f) {
  if (f.state !== 'EXISTS') return f.state;
  return f.hasA ? 'RESOLVES' : 'NO-ADDRESS';
}

function parseContact(raw) {
  const v = String(raw).trim();
  const low = v.toLowerCase();
  if (low.startsWith('mailto:')) {
    const addr = v.slice(7).split(/[?\s]/)[0];
    const at = addr.lastIndexOf('@');
    return at > 0 ? { kind: 'email', domain: addr.slice(at + 1).toLowerCase().replace(/\.$/, '') } : { kind: 'malformed', raw: v };
  }
  if (low.startsWith('tel:')) return { kind: 'tel' };
  if (low.startsWith('http://') || low.startsWith('https://')) {
    try {
      const u = new URL(v);
      return { kind: 'url', url: v, domain: u.hostname.toLowerCase(), scheme: u.protocol.replace(':', '') };
    } catch { return { kind: 'malformed', raw: v }; }
  }
  // RFC 9116 requires a URI, but bare addresses are extremely common in the wild.
  if (/^[^\s@]+@[^\s@]+\.[a-z]{2,}$/i.test(v)) {
    return { kind: 'email', bare: true, domain: v.slice(v.lastIndexOf('@') + 1).toLowerCase() };
  }
  return { kind: 'malformed', raw: v };
}

/** RFC 9116 §2.5.5: Expires is mandatory and must be in the future. */
function expiryState(exp, nowMs) {
  if (!exp) return 'missing';
  const t = Date.parse(exp);
  if (Number.isNaN(t)) return 'unparseable';
  return t < nowMs ? 'expired' : 'valid';
}

async function main() {
  const NOW = Date.parse(process.env.SURVEY_NOW || '2026-08-27T00:00:00Z');
  const ranks = loadRanks();
  const lines = fs.readFileSync(inPath, 'utf8').split('\n').filter(Boolean);
  const files = [];
  // Adoption needs a denominator PER BUCKET, so count every scanned domain, not just the hits.
  const scannedByBucket = {}, foundByBucket = {};
  for (const l of lines) {
    let r; try { r = JSON.parse(l); } catch { continue; }
    const b = bucketOf(ranks.get(r.domain));
    scannedByBucket[b] = (scannedByBucket[b] || 0) + 1;
    if (r.is_security_txt) { r._rank = ranks.get(r.domain) || null; r._bucket = b; files.push(r); foundByBucket[b] = (foundByBucket[b] || 0) + 1; }
  }
  console.log(`${lines.length} scanned, ${files.length} real security.txt`);

  // Distinct contact domains, and the distinct portal URLs.
  const domainSet = new Set(), urlSet = new Set();
  const parsedBySite = new Map();
  for (const f of files) {
    const ps = f.contact.map(parseContact);
    parsedBySite.set(f.domain, ps);
    for (const p of ps) {
      if (p.domain) domainSet.add(p.domain);
      if (p.kind === 'url') urlSet.add(p.url);
    }
  }
  const domains = [...domainSet];
  console.log(`${domains.length} distinct contact domains, ${urlSet.size} distinct portal URLs`);

  const facts = new Map();
  let i = 0, done = 0;
  const t0 = Date.now();
  await Promise.all(Array.from({ length: CONC }, async () => {
    while (i < domains.length) {
      const d = domains[i++];
      facts.set(d, await domainFacts(d));
      if (++done % 500 === 0) {
        const rate = done / ((Date.now() - t0) / 1000);
        console.log(`  dns ${done}/${domains.length} ${rate.toFixed(1)}/s`);
      }
    }
  }));

  // Probe the portals. A resolving host is not a working disclosure form: the domain can be
  // parked, the path can 404, the vendor can have been cancelled. Nobody has measured this.
  const urls = [...urlSet];
  const portal = new Map();
  let j = 0, pdone = 0;
  const t1 = Date.now();
  await Promise.all(Array.from({ length: Math.min(CONC, 32) }, async () => {
    while (j < urls.length) {
      const u = urls[j++];
      let host = null;
      try { host = new URL(u).hostname.toLowerCase(); } catch {}
      const f = host ? facts.get(host) : null;
      if (f && f.state !== 'EXISTS') portal.set(u, { reachable: false, why: f.state });
      else {
        try {
          const r = await fetch(u, {
            headers: { 'user-agent': 'securitytxt-survey (+https://agentatwork.xyz) contact: security@agentatwork.xyz' },
            redirect: 'follow', signal: AbortSignal.timeout(10000),
          });
          // 401/403/429 mean the server is alive and answering — it is refusing THIS client.
          // This host is a datacenter IP and gets bot-walled routinely; calling that a dead
          // disclosure portal would inflate the finding with my own network's reputation.
          // 404/410 is the real signal: the server is fine and the report page is gone.
          const s = r.status;
          const cls = s < 400 ? 'ok'
            : (s === 401 || s === 403 || s === 429) ? 'alive_gated'
            : (s === 404 || s === 410) ? 'page_gone'
            : s >= 500 ? 'server_error' : `http_${s}`;
          portal.set(u, { reachable: cls === 'ok' || cls === 'alive_gated', status: s, why: cls });
        } catch (e) {
          portal.set(u, { reachable: false, why: e.name === 'TimeoutError' ? 'timeout' : (e.cause?.code || e.name || 'err') });
        }
      }
      if (++pdone % 250 === 0) {
        const rate = pdone / ((Date.now() - t1) / 1000);
        console.log(`  http ${pdone}/${urls.length} ${rate.toFixed(1)}/s`);
      }
    }
  }));

  const out = {
    generated_from: inPath, scanned: lines.length, security_txt: files.length,
    distinct_contact_domains: domains.length, distinct_portal_urls: urls.length,
    sites: [],
  };
  const bump = (k, v) => { out[k] = out[k] || {}; out[k][v] = (out[k][v] || 0) + 1; };
  const bumpB = (b, k) => {
    out.by_bucket = out.by_bucket || {};
    out.by_bucket[b] = out.by_bucket[b] || {};
    out.by_bucket[b][k] = (out.by_bucket[b][k] || 0) + 1;
  };
  out.adoption_by_bucket = {};
  for (const [name] of [...BUCKETS, ['unranked']]) {
    const s = scannedByBucket[name] || 0, f = foundByBucket[name] || 0;
    if (s) out.adoption_by_bucket[name] = { scanned: s, security_txt: f, pct: +(100 * f / s).toFixed(2) };
  }

  for (const f of files) {
    const ps = parsedBySite.get(f.domain);
    const kinds = {};
    for (const p of ps) kinds[p.kind] = (kinds[p.kind] || 0) + 1;
    const cvs = ps.filter(p => p.domain).map(p => {
      const fx = facts.get(p.domain);
      const verdict = p.kind === 'url' ? urlVerdict(fx) : emailVerdict(fx);
      const pr = p.kind === 'url' ? portal.get(p.url) : null;
      return { kind: p.kind, verdict, portal_ok: pr ? pr.reachable : null, portal_why: pr ? pr.why : null };
    });
    const exp = expiryState(f.expires, NOW);

    const emails = cvs.filter(c => c.kind === 'email');
    const portals = cvs.filter(c => c.kind === 'url');

    // A ranked site is alive by construction — it is in this list because it serves traffic.
    // So its OWN domain is never the lapse. The exposure hides in contacts that point somewhere
    // else: an acquired brand, a retired product domain, a security vendor that folded. Those
    // are not kept alive by the parent site's traffic and nothing about the site breaks when
    // they expire. Split the population on this, or the whole finding averages out to zero.
    const siteReg = publicSuffixOf(f.domain).registrable;
    for (const p of ps) {
      if (!p.domain) continue;
      const third = publicSuffixOf(p.domain).registrable !== siteReg;
      const v = p.kind === 'url' ? urlVerdict(facts.get(p.domain)) : emailVerdict(facts.get(p.domain));
      bump(third ? 'third_party_contact_verdicts' : 'same_domain_contact_verdicts', v);
      if (third) bump('third_party_contact_kinds', p.kind);
    }
    // "Can a report reach these people at all?" — true if ANY listed contact works.
    const anyEmailWorks = emails.some(c => c.verdict === 'LIVE-MX' || c.verdict === 'IMPLICIT-A');
    const anyPortalWorks = portals.some(c => c.portal_ok === true);
    const reachable = anyEmailWorks || anyPortalWorks;

    const hijE = emails.some(c => c.verdict === 'UNREGISTERED');
    const hijP = portals.some(c => c.verdict === 'UNREGISTERED');

    out.sites.push({
      site: f.domain, rank: f._rank, bucket: f._bucket, contacts: f.contact.length, kinds,
      contact_verdicts: cvs, expires: f.expires, expiry: exp, reachable,
      hijackable_email: hijE, hijackable_portal: hijP,
    });
    bump('expiry_distribution', exp);
    bump('reachability', reachable ? 'reachable' : 'NO-WORKING-CONTACT');

    // Same counts, split by popularity. Rates per bucket are computed at the end from
    // adoption_by_bucket's denominators — never eyeball a count across buckets of unequal size.
    bumpB(f._bucket, `expiry_${exp}`);
    bumpB(f._bucket, reachable ? 'reachable' : 'no_working_contact');
    if (hijE || hijP) bumpB(f._bucket, 'hijackable_site');
    if (ps.some(p => p.domain && publicSuffixOf(p.domain).registrable !== siteReg)) bumpB(f._bucket, 'has_third_party_contact');

    // §2.5.3: a web Contact URI "MUST begin with https://". A plaintext report form is both a
    // spec violation and a real exposure — the report is the sensitive thing being submitted.
    for (const p of ps) if (p.kind === 'url') bump('contact_url_scheme', p.scheme);

    // §2.5.2: "If the retrieved URI is not listed among the canonical URIs, the contents of the
    // file SHOULD NOT be trusted." A mismatch is usually a file copy-pasted from another org and
    // never edited — which means its Contact points at somebody else entirely.
    const canon = f.canonical || [];
    if (!canon.length) bump('canonical_state', 'absent');
    else {
      const fetched = f.final_url || `https://${f.domain}/.well-known/security.txt`;
      let fh = null; try { fh = new URL(fetched).hostname.toLowerCase().replace(/^www\./, ''); } catch {}
      const hosts = canon.map(c => { try { return new URL(c).hostname.toLowerCase().replace(/^www\./, ''); } catch { return null; } });
      if (canon.some(c => c.trim() === fetched)) bump('canonical_state', 'exact_match');
      else if (fh && hosts.includes(fh)) bump('canonical_state', 'host_match_path_differs');
      else bump('canonical_state', 'MISMATCH_untrusted_per_spec');
    }
    for (const c of emails) bump('email_contact_verdicts', c.verdict);
    for (const c of portals) bump('portal_contact_verdicts', c.verdict);
    for (const c of portals) if (c.portal_why) bump('portal_http', c.portal_why);
  }
  out.domain_states = {};
  for (const [, fx] of facts) out.domain_states[fx.state] = (out.domain_states[fx.state] || 0) + 1;
  out.sites_with_hijackable_email = out.sites.filter(s => s.hijackable_email).length;
  out.sites_with_hijackable_portal = out.sites.filter(s => s.hijackable_portal).length;
  out.sites_with_no_working_contact = out.sites.filter(s => !s.reachable).length;

  fs.writeFileSync(outPath, JSON.stringify(out, null, 1));
  console.log('\n--- contact domain states ---'); console.log(out.domain_states);
  console.log('--- email contact verdicts ---'); console.log(out.email_contact_verdicts);
  console.log('--- portal contact verdicts ---'); console.log(out.portal_contact_verdicts);
  console.log('--- portal HTTP ---'); console.log(out.portal_http);
  console.log('--- expiry (RFC 9116 makes it mandatory) ---'); console.log(out.expiry_distribution);
  console.log(`\nsites with a hijackable EMAIL contact:  ${out.sites_with_hijackable_email}`);
  console.log(`sites with a hijackable PORTAL contact: ${out.sites_with_hijackable_portal}`);
  console.log(`sites with NO working contact at all:   ${out.sites_with_no_working_contact} / ${files.length}`);

  // The rank table is the point of the whole 200k run: is a lapsed contact a tail phenomenon,
  // or does it happen at every level of the list? Rates, not counts — the buckets differ in
  // size by two orders of magnitude and raw counts would say nothing.
  console.log('\n--- by popularity bucket (rates over sites WITH a security.txt) ---');
  console.log('bucket        scanned  sec.txt  adopt%   expired%  noExpires%  3rdParty%  noContact%  hijack');
  for (const [name] of [...BUCKETS, ['unranked']]) {
    const a = out.adoption_by_bucket[name];
    if (!a) continue;
    const b = (out.by_bucket && out.by_bucket[name]) || {};
    const n = a.security_txt || 1;
    const pc = (x) => (100 * (x || 0) / n).toFixed(1).padStart(6);
    console.log(
      `${name.padEnd(12)} ${String(a.scanned).padStart(7)} ${String(a.security_txt).padStart(8)} ` +
      `${a.pct.toFixed(2).padStart(6)} ${pc(b.expiry_expired)}    ${pc(b.expiry_missing)}     ` +
      `${pc(b.has_third_party_contact)}    ${pc(b.no_working_contact)}      ${String(b.hijackable_site || 0).padStart(5)}`
    );
  }
  console.log(`ANALYZE_DONE -> ${outPath}`);
}

main();
