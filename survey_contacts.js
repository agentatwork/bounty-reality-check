#!/usr/bin/env node
/**
 * survey_contacts.js — measure, at scale, whether published security contacts are reachable.
 *
 *   node survey_contacts.js <repolist.txt> <out.json> [concurrency]
 *
 * Phased on purpose, because the naive shape (run the single-repo checker N times) costs
 * two REST calls per repo and re-resolves the same domain dozens of times:
 *
 *   1. Fetch SECURITY.md over raw.githubusercontent — this does NOT consume REST quota,
 *      so the widest part of the funnel is also the cheapest. Try main/ then master/.
 *   2. Extract the contact address, reduce to DISTINCT domains, and resolve each once.
 *      A cache matters more than it looks: shared infra domains recur across many repos.
 *   3. Spend REST quota on private-reporting status ONLY for repos whose contact is
 *      broken — that is the only place the answer changes the finding (a dead address
 *      with private reporting ON is untidy; with it OFF it is the only door, and locked).
 *
 * Publication rule: an UNREGISTERED contact domain is a live interception vector. The
 * dataset keeps the name so it can be re-verified and reported to the owner; anything
 * PUBLISHED must redact it until secured. See --redact.
 */
'use strict';
const fs = require('fs');
const os = require('os');
const path = require('path');
const dnsMod = require('dns');

const RESOLVERS = [['google', ['8.8.8.8', '8.8.4.4']], ['cloudflare', ['1.1.1.1', '1.0.0.1']]];
const RAW_PATHS = ['SECURITY.md', '.github/SECURITY.md', 'docs/SECURITY.md'];
// HEAD, not main/master. raw.githubusercontent resolves HEAD to the repo's DEFAULT branch,
// which is the file users and reporters actually see, and it costs no REST quota to learn.
// Guessing main/ is wrong in a way that corrupts results silently: mango-v4 defaults to
// `dev`, and its stale `main` SECURITY.md names a different, live address — reading it
// would have hidden the very finding this survey exists to count. Keep main/master as a
// fallback only for the rare repo where HEAD 404s.
const BRANCHES = ['HEAD', 'main', 'master'];

function token() {
  if (process.env.GH_TOKEN) return process.env.GH_TOKEN.trim();
  for (const p of [path.join(os.homedir(), 'work/gh_token'), path.join(os.homedir(), '.gh_token')]) {
    try { return fs.readFileSync(p, 'utf8').trim(); } catch { /* absent */ }
  }
  return null;
}
const TOK = token();

async function raw(url) {
  try {
    const r = await fetch(url, { headers: { 'user-agent': 'contactcheck-survey' }, signal: AbortSignal.timeout(12000) });
    return r.ok ? await r.text() : null;
  } catch { return null; }
}

async function fetchDoc(repo) {
  for (const b of BRANCHES) {
    for (const f of RAW_PATHS) {
      const t = await raw(`https://raw.githubusercontent.com/${repo}/${b}/${f}`);
      if (t && t.trim()) return { text: t, path: f, branch: b };
    }
  }
  return null;
}

function extractEmail(text) {
  const bad = /\.(png|jpg|jpeg|svg|gif|webp)$/i;
  const all = [...text.matchAll(/[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}/gi)]
    .map(m => ({ email: m[0].toLowerCase(), at: m.index }))
    .filter(e => !bad.test(e.email) && !e.email.includes('example.') && !e.email.startsWith('your'));
  if (!all.length) return null;
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
  const r = new dnsMod.promises.Resolver({ timeout: 5000, tries: 2 });
  r.setServers(servers);
  const out = {};
  for (const [key, fn] of [['ns', 'resolveNs'], ['mx', 'resolveMx'], ['a', 'resolve4']]) {
    try { out[key] = { ok: true, val: await r[fn](domain) }; }
    catch (e) { out[key] = { ok: false, code: e.code || 'ERR' }; }
  }
  return out;
}

const domainCache = new Map();
async function classifyDomain(domain) {
  if (domainCache.has(domain)) return domainCache.get(domain);
  const views = [];
  for (const [name, servers] of RESOLVERS) views.push([name, await resolveWith(servers, domain)]);

  let res;
  const nx = views.filter(([, v]) => v.ns.ok === false && v.ns.code === 'ENOTFOUND'
                                  && v.a.ok === false && v.a.code === 'ENOTFOUND');
  if (nx.length === views.length) {
    res = { verdict: 'UNREGISTERED', detail: 'NXDOMAIN on both resolvers — registerable by anyone' };
  } else if (nx.length) {
    res = { verdict: 'UNCERTAIN', detail: `resolvers disagree (${nx.length}/${views.length} NXDOMAIN) — needs a hand check` };
  } else {
    const mx = views.find(([, v]) => v.mx.ok)?.[1].mx.val || [];
    const nullMx = mx.length === 1 && (mx[0].exchange === '' || mx[0].exchange === '.');
    if (nullMx) res = { verdict: 'NULL-MX', detail: 'RFC 7505 null MX — accepts no mail' };
    else if (mx.length) {
      const hosts = mx.sort((x, y) => x.priority - y.priority).map(m => m.exchange);
      res = { verdict: 'LIVE-MX', detail: hosts[0], mx: hosts.slice(0, 2) };
    } else {
      const a = views.find(([, v]) => v.a.ok)?.[1].a.val || [];
      res = a.length
        ? { verdict: 'IMPLICIT-A', detail: `no MX; RFC 5321 A-fallback to ${a[0]}` }
        : { verdict: 'NO-MAIL', detail: 'registered, no MX and no A — nothing accepts mail' };
    }
  }
  domainCache.set(domain, res);
  return res;
}

async function pvrEnabled(repo) {
  if (!TOK) return null;
  try {
    const r = await fetch(`https://api.github.com/repos/${repo}/private-vulnerability-reporting`,
      { headers: { authorization: `Bearer ${TOK}`, 'user-agent': 'contactcheck-survey' }, signal: AbortSignal.timeout(12000) });
    if (!r.ok) return null;
    const j = await r.json();
    return typeof j.enabled === 'boolean' ? j.enabled : null;
  } catch { return null; }
}

async function pool(items, limit, fn, label) {
  const out = []; let i = 0, done = 0;
  await Promise.all(Array.from({ length: limit }, async () => {
    while (i < items.length) {
      const it = items[i++];
      out.push(await fn(it));
      if (++done % 100 === 0) console.log(`  ${label}: ${done}/${items.length}`);
    }
  }));
  return out;
}

async function main() {
  const [listFile, outFile, concArg] = process.argv.slice(2);
  if (!listFile || !outFile) { console.log('usage: node survey_contacts.js <repolist.txt> <out.json> [concurrency]'); process.exit(1); }
  const repos = fs.readFileSync(listFile, 'utf8').split('\n').map(s => s.trim()).filter(s => s.includes('/'));
  const limit = Math.max(1, parseInt(concArg || '8', 10));

  console.log(`phase 1: fetching SECURITY.md for ${repos.length} repos (concurrency ${limit}, no REST quota)`);
  const docs = await pool(repos, limit, async repo => {
    const d = await fetchDoc(repo);
    if (!d) return { repo, verdict: 'NO-DOC' };
    const email = extractEmail(d.text);
    if (!email) return { repo, verdict: 'NO-EMAIL', doc: d.path };
    return { repo, email, domain: email.split('@')[1], doc: d.path };
  }, 'docs');

  const withEmail = docs.filter(d => d.domain);
  const domains = [...new Set(withEmail.map(d => d.domain))];
  console.log(`phase 2: resolving ${domains.length} DISTINCT domains (from ${withEmail.length} repos with a contact)`);
  await pool(domains, limit, d => classifyDomain(d), 'dns');

  for (const d of withEmail) Object.assign(d, classifyDomain_sync(d.domain));
  function classifyDomain_sync(dom) { return domainCache.get(dom) || { verdict: 'UNCERTAIN', detail: 'unresolved' }; }

  // Check private reporting for every repo WITHOUT a working email channel — the broken
  // ones and the ones publishing no address at all. Without this, "no email" is ambiguous:
  // with private reporting ON it is the healthy modern setup, with it OFF there is no way
  // in at all. Repos with a LIVE-MX contact are skipped; they already have a channel.
  const noEmail = docs.filter(d => !d.domain);
  const broken = withEmail.filter(d => d.verdict !== 'LIVE-MX');
  const needPvr = [...broken, ...noEmail];
  console.log(`phase 3: private-reporting status for ${needPvr.length} repos lacking a working email channel (REST)`);
  await pool(needPvr, Math.min(limit, 5), async d => { d.pvr = await pvrEnabled(d.repo); return d; }, 'pvr');
  for (const d of broken) d.sole_channel = d.pvr === false;
  for (const d of noEmail) if (d.pvr === true) d.verdict = 'PVR-ONLY';

  const all = [...noEmail, ...withEmail];
  const summary = {};
  for (const r of all) summary[r.verdict] = (summary[r.verdict] || 0) + 1;

  const unregRepos = withEmail.filter(r => r.verdict === 'UNREGISTERED');
  const unregDomains = [...new Set(unregRepos.map(r => r.domain))];
  const noWayIn = broken.filter(r => r.sole_channel && (r.verdict === 'UNREGISTERED' || r.verdict === 'NULL-MX' || r.verdict === 'NO-MAIL'));

  const out = {
    generated: new Date().toISOString().slice(0, 10),
    tool: 'contactcheck.js / survey_contacts.js (github.com/agentatwork/bounty-reality-check)',
    method: 'GitHub code-search corpus of repos publishing a SECURITY.md contact -> extract the report address -> resolve its domain. Existence = NXDOMAIN agreement across two independent resolvers (Google + Cloudflare). RDAP deliberately NOT used: it returned a false 404 for a plainly-registered domain, so 404 cannot be read as "available".',
    corpus_size: repos.length,
    with_contact_email: withEmail.length,
    distinct_contact_domains: domains.length,
    summary,
    unregistered_repos: unregRepos.length,
    unregistered_domains_distinct: unregDomains.length,
    dead_contact_and_pvr_off: noWayIn.length,
    repos: all,
  };
  fs.writeFileSync(outFile, JSON.stringify(out, null, 1));

  console.log('\n=== SUMMARY ===');
  for (const [k, v] of Object.entries(summary).sort((a, b) => b[1] - a[1])) {
    console.log(`  ${k.padEnd(14)} ${String(v).padStart(5)}  ${(100 * v / all.length).toFixed(1)}%`);
  }
  console.log(`  repos with an UNREGISTERED contact domain: ${unregRepos.length}`);
  console.log(`  distinct unregistered domains:             ${unregDomains.length}`);
  console.log(`  broken contact AND private reporting OFF:  ${noWayIn.length}`);
  console.log(`wrote ${outFile}`);
}

main().catch(e => { console.error('fatal:', e.message); process.exit(1); });
