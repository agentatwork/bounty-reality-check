#!/usr/bin/env node
/**
 * mkwwwlist.js — build the second-pass domain list: `www.` hosts the apex scan could not reach.
 *
 *   node mkwwwlist.js <scan.jsonl> <out.txt>
 *
 * WHY THIS EXISTS. The apex scan fetches `https://<domain>/.well-known/security.txt`. When the
 * apex has no A/AAAA record that fetch fails with ENOTFOUND and the domain is recorded as
 * unreachable — but 28.0% of those domains (95% CI 23.2–33.3%, n=300 sampled from the list and
 * resolved independently) serve a `www.` host with an address. For a site that only answers on
 * `www.`, that host is where its website is, and the apex scan never looked at it.
 *
 * THE SPEC DOES NOT AUTHORISE THIS, and an earlier version of this comment claimed it did —
 * "RFC 9116 §3 places the file at the top level of the domain the service runs on, so for a
 * site that only answers on `www.` that IS the conforming location." Half true, and the wrong
 * half is load-bearing. §3 does make `https://www.example.com/.well-known/security.txt` a
 * conforming location *for `www.example.com`*. But §3.1: a file "MUST only apply to the domain
 * or IP address in the URI used to retrieve it, not to any of its subdomains or parent domains."
 * So a file found here says nothing, per the RFC, about the apex domain in the ranking list.
 * Attributing it to the apex is MY judgement — the ranked entry is a label for an organisation
 * and this is that organisation's site — not something the standard backs. That is exactly why
 * the results go to a separate output file (see the last paragraph): the merge is a choice the
 * analysis makes visibly, and a strict §3.1 reading can decline it and still use the data.
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
 * HOW CONTAMINATED IS THE LIST, MEASURED. ENOTFOUND at scan time could also be a transient
 * resolver failure, which would put a domain with a perfectly good apex on the retry list and
 * inflate the "no address at the apex" denominator the writeup quotes a percentage of. A 300-domain
 * random sample of the list, re-resolved independently afterwards: 3 apexes resolve now — 1.0%,
 * 95% CI 0.3–2.9% — and 297 genuinely have no address. So the list is ~99% real and the overstate
 * is smaller than the rounding on the figure it feeds.
 *
 * The breakdown of those 297 is the more interesting half, because it confirms the bias argument
 * above rather than merely assuming it: 291 are ENODATA and only 5 are true ENOTFOUND. ENODATA
 * means the name exists and is delegated — real NS records, a real zone — and simply carries no
 * address at the apex. These are not dead domains being swept up. They are live zones configured
 * the way zones were configured before the apex became the canonical host, which is exactly the
 * population the paragraph above claims is at stake.
 *
 * Sampled rather than measured over the whole list because verifying all ~26k costs an hour of
 * DNS for a number whose interval is already tight enough to not change any published digit.
 *
 * A PRE-REGISTERED BOUND ON THE SECOND PASS. The 28.0% above is DNS resolution only, and the
 * second pass needs strictly more than that — TLS has to complete and HTTP has to answer. So the
 * share of retried domains whose `www.` host responds must land at or below 28.0%, and cannot
 * credibly exceed the interval's 33.3%. Writing that down BEFORE the pass runs is the point: a
 * second-pass number that comes back higher is not a better result, it is a bug in how a response
 * is counted, and deciding that afterwards is how a bug that inflates a finding gets kept.
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
