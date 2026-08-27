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
  // Named in an article published weeks before this survey existed, about an unrelated subject.
  // It happens to serve a security.txt, so the narrowed set contains it; the article says nothing
  // about its security contact. "Appears in the dataset" and "was chosen because of the dataset"
  // are different claims, and only the second is a leak.
  'ethereum.org',
]);
// The nine chain RPC and explorer endpoints that used to sit here are gone. They were added to
// silence collisions produced by treating all 200k SCANNED names as sensitive; narrowing the set
// to names that can carry a harmful fact removed the collisions at the source, and an allowlist
// entry that no longer suppresses anything is pure attack surface for the next false negative.

const TEXT_EXT = new Set(['.js', '.md', '.json', '.txt', '.html', '.sh', '.yml', '.yaml']);

function walk(p, out) {
  const st = fs.statSync(p);
  if (st.isDirectory()) {
    if (/(^|\/)(node_modules|\.git)$/.test(p)) return out;
    for (const e of fs.readdirSync(p)) walk(path.join(p, e), out);
  } else if (TEXT_EXT.has(path.extname(p))) out.push(p);
  return out;
}

/**
 * Guard the survey's OUTPUT, not its INPUT.
 *
 * The scan visits every name on a public popularity list. Downloading that list and fetching a
 * URL on each host does not make the list a secret, and "this site has no security.txt" is not
 * a fact anyone can be hurt by. Treating all 200k scanned names as sensitive was the wrong
 * boundary: it flagged an RDAP endpoint, two public blockchain sites and a cloud host — every
 * one a collision with a name I had used months earlier for unrelated reasons — and the fix on
 * offer was to keep extending the allowlist until the check stopped complaining. A check that
 * gets argued down four names at a time is not a check.
 *
 * The narrow, defensible set is where a name can carry a HARMFUL fact:
 *
 *   - a site that published a parseable security.txt (naming it hands over its contact address,
 *     which is the whole leak, one fetch later), and
 *   - every contact domain named inside one of those files.
 *
 * A domain that never served a security.txt is in neither category, and it drops out.
 */
function loadDomains(datasetPath) {
  const toks = new Set();
  for (const line of fs.readFileSync(datasetPath, 'utf8').split('\n')) {
    if (!line) continue;
    let rec = null;
    try { rec = JSON.parse(line); } catch { /* fall through to the regex path below */ }

    // Scan records always carry `ok`; a scan record without a conforming file is dropped. Any
    // other shape (a hand-made list, a future classified dataset) is KEPT — when the format is
    // unrecognised the check must fail loud, not quietly narrow itself to nothing.
    if (rec && 'ok' in rec && rec.is_security_txt !== true) continue;

    for (const m of line.matchAll(/"(?:domain|contact_domain)":"([^"]+)"/g)) {
      const d = m[1].toLowerCase();
      if (d.includes('.')) toks.add(d);
    }
    for (const m of line.matchAll(/mailto:[^"\s,]*@([A-Za-z0-9.-]+\.[A-Za-z]{2,})/g)) toks.add(m[1].toLowerCase());
    for (const c of (rec && Array.isArray(rec.contact)) ? rec.contact : []) {
      const s = String(c).trim();
      const at = s.lastIndexOf('@');
      if (at > 0) { const d = s.slice(at + 1).split(/[?\s>]/)[0].toLowerCase().replace(/\.$/, ''); if (d.includes('.')) toks.add(d); }
      else { try { toks.add(new URL(s).hostname.toLowerCase()); } catch {} }
    }
  }
  // Suffix-aware: an allowed name covers its subdomains, because the infrastructure entries
  // above appear as `<chain>-rpc.publicnode.com` and friends. This is a deliberate loosening —
  // it means a genuine leak sitting on a subdomain of an allowlisted name would be missed. That
  // is acceptable only because every entry is a public service I chose from documentation, and
  // it is the reason this list must stay short and hand-held rather than growing to silence
  // whatever the check flags next.
  for (const t of [...toks]) {
    for (const a of ALLOW) {
      if (t === a || t.endsWith(`.${a}`)) { toks.delete(t); break; }
    }
  }
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

  // Tokenise each file once and look the tokens up, instead of testing one regex per dataset
  // domain per file. Same semantics — the boundaries are identical, and an exact token lookup
  // is what a both-sides-anchored match already was — but the cost stops depending on the size
  // of the dataset. That matters: at 200k scanned domains the per-domain-regex version does
  // billions of character comparisons per file, and a check too slow to run is a check that
  // gets skipped right before the one publication that needed it.
  //
  // The boundaries: a leading `.` is excluded so a dataset domain cannot match the tail of a
  // longer hostname (`bar.com` must not fire inside `foo.bar.com` — the token there is the
  // whole `foo.bar.com`), and a leading `@` is excluded so a redacted address does not flag
  // its own domain.
  const TOKEN = /(?<![a-z0-9.@-])([a-z0-9-]+(?:\.[a-z0-9-]+)+)(?![a-z0-9-])/g;

  let hits = 0;
  for (const f of files) {
    const lines = fs.readFileSync(f, 'utf8').toLowerCase().split('\n');
    const seen = new Set();
    for (let i = 0; i < lines.length; i++) {
      for (const m of lines[i].matchAll(TOKEN)) {
        const t = m[1];
        if (!toks.has(t) || seen.has(t)) continue;
        seen.add(t);
        console.log(`LEAK  ${f}:${i + 1}  ${t}`);
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
