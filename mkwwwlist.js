#!/usr/bin/env node
/**
 * mkwwwlist.js — build the second-pass domain list: `www.` hosts the apex scan could not reach.
 *
 *   node mkwwwlist.js <scan.jsonl> <out.txt>
 *
 * WHY THIS EXISTS. The apex scan fetches `https://<domain>/.well-known/security.txt`. When the
 * apex has no A/AAAA record that fetch fails with ENOTFOUND and the domain is recorded as
 * unreachable — but a quarter of those domains serve a perfectly live `www.` host. RFC 9116 §3
 * places the file at the top level of the domain the service runs on, so for a site that only
 * answers on `www.` that IS the conforming location, and the apex scan never looked at it.
 *
 * The reason to fix it is bias, not sample size. "Registered and delegated, but no address at the
 * apex" is not a random slice of the web — it selects for older DNS setups and for organisations
 * that never modernised their zone, which is exactly the population a survey about *stale contact
 * information* should be most careful not to drop. Reporting adoption while silently omitting
 * them would let the omission run in the direction that makes the finding cleaner.
 *
 * ENOTFOUND is the right and only trigger. A timeout, a refused connection or a bad certificate
 * all mean something answered (or failed) at the apex address, so the apex exists and `www.` is
 * not a second location to try — it is a different guess at the same site. Only "this name has no
 * address" leaves the `www.` host genuinely unexamined.
 *
 * Output is a plain one-per-line list for scan_securitytxt.js, which needs no changes: it will
 * record `"domain":"www.example.com"`, and keeping those in a SEPARATE output file is what lets
 * the analysis report apex and www-only adoption as two numbers instead of quietly merging them.
 */
'use strict';
const fs = require('fs');

const [, , scanPath, outPath] = process.argv;
if (!scanPath || !outPath) {
  console.error('usage: node mkwwwlist.js <scan.jsonl> <out.txt>');
  process.exit(1);
}

const seen = new Set();
let records = 0, enotfound = 0, alreadyWww = 0;

for (const line of fs.readFileSync(scanPath, 'utf8').split('\n')) {
  if (!line) continue;
  let r;
  try { r = JSON.parse(line); } catch { continue; }  // torn last line while the scan is live
  records++;
  if (r.err !== 'ENOTFOUND') continue;
  enotfound++;
  // A domain already carrying a www. label has no second guess to make: prefixing another one
  // would probe a host nobody publishes.
  if (/^www\./i.test(r.domain)) { alreadyWww++; continue; }
  seen.add(`www.${r.domain}`);
}

fs.writeFileSync(outPath, [...seen].join('\n') + '\n');
console.log(`records=${records} enotfound=${enotfound} skipped_already_www=${alreadyWww} wrote=${seen.size} -> ${outPath}`);
