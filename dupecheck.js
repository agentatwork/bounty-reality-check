#!/usr/bin/env node
'use strict';
/*
 * dupecheck.js — the OTHER half of a bounty reality check.
 *
 * reality.js answers "is there money on-chain to steal?"  dupecheck answers the
 * question that wastes whole audit sessions if you ask it last instead of first:
 * "has this bug already been found, and does this program actually pay for it?"
 *
 * For a GitHub repo running a bug bounty it pulls, read-only:
 *   - every PUBLISHED GitHub Security Advisory (id, severity, one-line summary)
 *   - the repo's own duplicate ledger / eligibility docs, if present
 *       (SECURITY.md, security/advisory-history.md, security/known-non-eligible-findings.md, ...)
 *   - the reward structure lines
 * and, if you pass keywords for the area you're about to audit, flags any
 * advisory or ledger line that already touches it.
 *
 * Usage:
 *   node dupecheck.js <owner/repo> [keyword ...]
 *   GH_TOKEN=ghp_... node dupecheck.js 1Hive/gardens-v2 StreamingEscrow claim buffer
 *   (token optional: raises rate limits and reads private-if-you-can advisories.
 *    Falls back to ~/work/gh_token, then unauthenticated.)
 *
 * Exit code 2 if any keyword matched an existing advisory/ledger entry (likely duplicate).
 */

const fs = require('fs');
const os = require('os');
const path = require('path');

function token() {
  if (process.env.GH_TOKEN) return process.env.GH_TOKEN.trim();
  for (const p of [path.join(os.homedir(), 'work/gh_token'), path.join(os.homedir(), '.gh_token')]) {
    try { return fs.readFileSync(p, 'utf8').trim(); } catch { /* ignore */ }
  }
  return null;
}

async function gh(url, tok) {
  const headers = { 'Accept': 'application/vnd.github+json', 'User-Agent': 'dupecheck' };
  if (tok) headers['Authorization'] = 'Bearer ' + tok;
  const r = await fetch(url, { headers });
  if (!r.ok) return { _status: r.status, _body: await r.text().catch(() => '') };
  return r.json();
}

async function raw(owner, repo, branch, file) {
  const url = `https://raw.githubusercontent.com/${owner}/${repo}/${branch}/${file}`;
  const r = await fetch(url, { headers: { 'User-Agent': 'dupecheck' } });
  if (!r.ok) return null;
  return r.text();
}

// pull all published advisories (paginated)
async function advisories(owner, repo, tok) {
  const out = [];
  for (let page = 1; page <= 10; page++) {
    const u = `https://api.github.com/repos/${owner}/${repo}/security-advisories?per_page=100&state=published&page=${page}`;
    const j = await gh(u, tok);
    if (!Array.isArray(j)) {
      if (page === 1) console.error(`  (advisories API: ${j._status || 'error'} ${String(j._body || '').slice(0, 120)})`);
      break;
    }
    out.push(...j);
    if (j.length < 100) break;
  }
  return out;
}

// grep helper: return matching lines with 1 line of context stripped
function grepLines(text, kws) {
  if (!text) return [];
  const hits = [];
  const lines = text.split('\n');
  for (let i = 0; i < lines.length; i++) {
    const low = lines[i].toLowerCase();
    for (const kw of kws) {
      if (low.includes(kw.toLowerCase())) { hits.push({ n: i + 1, line: lines[i].trim(), kw }); break; }
    }
  }
  return hits;
}

// pull the funder/reward structure lines out of SECURITY.md
function rewardLines(security) {
  if (!security) return [];
  return security.split('\n')
    .filter(l => /(% of pool|reward|bounty pool|critical|high|medium)/i.test(l) && /\||%|pool|reward/i.test(l))
    .map(l => l.trim())
    .filter(l => l.length && !/^#/.test(l))
    .slice(0, 14);
}

(async () => {
  const [target, ...keywords] = process.argv.slice(2);
  if (!target || !target.includes('/')) {
    console.error('usage: node dupecheck.js <owner/repo> [keyword ...]');
    process.exit(1);
  }
  const [owner, repo] = target.split('/');
  const tok = token();
  console.log(`\n== dupecheck ${owner}/${repo} ==  ${tok ? '(authenticated)' : '(unauthenticated)'}`);

  // 1) repo basics + default branch
  const meta = await gh(`https://api.github.com/repos/${owner}/${repo}`, tok);
  const branch = (meta && meta.default_branch) || 'main';
  if (meta && meta.full_name) {
    console.log(`repo: ${meta.full_name} | archived: ${meta.archived} | pushed: ${meta.pushed_at} | branch: ${branch}`);
  } else {
    console.log(`(repo metadata unavailable: ${meta && meta._status})`);
  }

  // 2) published advisories
  const adv = await advisories(owner, repo, tok);
  console.log(`\n-- Published security advisories: ${adv.length} --`);
  const bySev = {};
  for (const a of adv) bySev[a.severity] = (bySev[a.severity] || 0) + 1;
  if (adv.length) console.log('   severity mix:', JSON.stringify(bySev));
  for (const a of adv) {
    console.log(`   [${(a.severity || '?').padEnd(8)}] ${a.ghsa_id}  ${a.summary || ''}`);
  }

  // 3) eligibility / duplicate ledgers
  const docPaths = [
    'SECURITY.md', '.github/SECURITY.md', 'docs/SECURITY.md',
    'security/advisory-history.md', 'security/known-non-eligible-findings.md',
    'security/final-merged-security-report.md',
  ];
  const docs = {};
  for (const d of docPaths) {
    const t = await raw(owner, repo, branch, d);
    if (t) docs[d] = t;
  }
  console.log(`\n-- Eligibility / duplicate ledgers present: ${Object.keys(docs).length ? Object.keys(docs).join(', ') : 'NONE'} --`);

  const security = docs['SECURITY.md'] || docs['.github/SECURITY.md'] || docs['docs/SECURITY.md'];
  const rl = rewardLines(security);
  if (rl.length) { console.log('\n-- Reward structure --'); rl.forEach(l => console.log('   ' + l)); }

  // 4) non-eligible category headers (### / ## under the known-non-eligible doc)
  const nonElig = docs['security/known-non-eligible-findings.md'];
  if (nonElig) {
    const cats = nonElig.split('\n').filter(l => /^#{2,3}\s+/.test(l)).map(l => l.replace(/^#+\s+/, '').trim());
    console.log(`\n-- Known NON-ELIGIBLE categories (${cats.length}) --`);
    cats.forEach(c => console.log('   • ' + c));
  }

  // 5) keyword duplicate scan
  let dup = false;
  if (keywords.length) {
    console.log(`\n== DUPLICATE SCAN for: ${keywords.join(', ')} ==`);
    const advBlob = adv.map(a => `${a.ghsa_id} ${a.severity} ${a.summary}`).join('\n');
    const advHits = grepLines(advBlob, keywords);
    if (advHits.length) {
      dup = true;
      console.log('\n  !! MATCH in published advisory summaries:');
      advHits.forEach(h => console.log(`     (${h.kw}) ${h.line}`));
    }
    for (const [name, text] of Object.entries(docs)) {
      const hits = grepLines(text, keywords);
      if (hits.length) {
        dup = true;
        console.log(`\n  !! MATCH in ${name}:`);
        hits.slice(0, 12).forEach(h => console.log(`     L${h.n} (${h.kw}) ${h.line.slice(0, 180)}`));
        if (hits.length > 12) console.log(`     ... +${hits.length - 12} more`);
      }
    }
    if (!dup) {
      console.log('\n  no keyword hit in advisories or ledgers — area looks unclaimed.');
      console.log('  (absence of a ledger hit is NOT proof of novelty: read the advisories that lack summaries,');
      console.log('   and remember same-root-cause counts as duplicate even under a different symptom.)');
    } else {
      console.log('\n  VERDICT: likely DUPLICATE / known. Read the matched entries in full before auditing further.');
    }
  }

  console.log('');
  process.exit(dup ? 2 : 0);
})().catch(e => { console.error('fatal:', e.message); process.exit(1); });
