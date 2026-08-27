#!/usr/bin/env node
/**
 * leakcheck.js — does any artifact name a domain that came out of the survey?
 *
 *   node leakcheck.js <dataset.jsonl> <file|dir> [...]      # exit 1 if anything leaks
 *
 * The rule this enforces: a survey that finds unregistered security-contact domains must
 * publish METHODOLOGY AND AGGREGATES ONLY. A named domain is a shopping list — an attacker
 * registers it and silently receives that organisation's vulnerability reports. Naming the
 * affected SITE is the same leak one fetch later, since its security.txt hands over the
 * address.
 *
 * I have gotten this check wrong twice by hand, in both directions, which is why it is a
 * committed file now rather than a shell one-liner rewritten from memory each time:
 *
 *   - TOO LOOSE: matching bare repo basenames admitted generic English ("contracts",
 *     "string") and buried the real hits in 92 false ones.
 *   - TOO TIGHT-LOOKING, ACTUALLY NOISE: substring matching with no boundaries flags a
 *     two-letter shortener domain inside the word "contact", or a short ccTLD name inside
 *     "context.toLowerCase()". Noise trains you to wave the check through, which is how a
 *     real hit gets waved through with it. (Those illustrations are deliberately described
 *     rather than spelled: this file is itself an artifact, and it must pass its own check.)
 *
 * So: full domains only, anchored on both sides, minus an explicit allowlist of names I
 * reference deliberately. Presence in the dataset does not make a name a leak — google.com is
 * in every domain list on earth. What makes it a leak is choosing it BECAUSE the survey
 * surfaced it. That distinction cannot be automated, so the allowlist is hand-held and short.
 */
'use strict';
const fs = require('fs');
const path = require('path');

/** RFC 2606 examples, this project's own infrastructure, and the standards bodies it cites. */
const ALLOW = new Set([
  'example.com', 'example.org', 'example.net', 'example.edu',
  'github.com', 'githubusercontent.com', 'github.io',
  'iana.org', 'publicsuffix.org', 'ietf.org', 'rfc-editor.org',
  'agentatwork.xyz',
  // Named live in published notes as verified public illustrations of a NON-hijack finding
  // (an expired Expires field, a Canonical mismatch). These are working, registered, famous
  // domains; the finding is that a field is stale, which is visible to anyone who looks.
  'google.com', 'cloudflare.com', 'x.com', 'twitter.com', 'youtube.com', 'amazon.com', 'gandi.net',
]);

const TEXT_EXT = new Set(['.js', '.md', '.json', '.txt', '.html', '.sh', '.yml', '.yaml']);

function walk(p, out) {
  const st = fs.statSync(p);
  if (st.isDirectory()) {
    if (/(^|\/)(node_modules|\.git)$/.test(p)) return out;
    for (const e of fs.readdirSync(p)) walk(path.join(p, e), out);
  } else if (TEXT_EXT.has(path.extname(p))) out.push(p);
  return out;
}

function loadDomains(datasetPath) {
  const toks = new Set();
  for (const line of fs.readFileSync(datasetPath, 'utf8').split('\n')) {
    if (!line) continue;
    // Every domain the survey touched: the scanned site, and any contact domain it named.
    for (const m of line.matchAll(/"(?:domain|contact_domain)":"([^"]+)"/g)) {
      const d = m[1].toLowerCase();
      if (d.includes('.')) toks.add(d);
    }
    for (const m of line.matchAll(/mailto:[^"\s,]*@([A-Za-z0-9.-]+\.[A-Za-z]{2,})/g)) toks.add(m[1].toLowerCase());
  }
  for (const a of ALLOW) toks.delete(a);
  return toks;
}

function main() {
  const [datasetPath, ...targets] = process.argv.slice(2);
  if (!datasetPath || !targets.length) {
    console.error('usage: node leakcheck.js <dataset.jsonl> <file|dir> [...]');
    process.exit(2);
  }
  const toks = loadDomains(datasetPath);
  const files = [];
  for (const t of targets) walk(t, files);

  // Anchored on both sides, so a short domain cannot match the tail of a longer one, and an
  // @ in the lookbehind stops a redacted address's own domain from re-flagging itself.
  const res = [...toks].map(d => [d, new RegExp(`(?<![a-z0-9.@-])${d.replace(/\./g, '\\.')}(?![a-z0-9-])`)]);

  let hits = 0;
  for (const f of files) {
    const body = fs.readFileSync(f, 'utf8').toLowerCase();
    for (const [d, re] of res) {
      if (re.test(body)) {
        const ln = body.split('\n').findIndex(l => re.test(l)) + 1;
        console.log(`LEAK  ${f}:${ln}  ${d}`);
        hits++;
      }
    }
  }
  console.log(hits
    ? `FAIL ${hits} leak(s) across ${files.length} files (${toks.size} dataset domains)`
    : `CLEAN 0 leaks across ${files.length} files (${toks.size} dataset domains checked)`);
  process.exit(hits ? 1 : 0);
}

main();
