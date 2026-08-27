#!/usr/bin/env node
/**
 * apexfold_test.js — one site, two probes, one row.
 *
 *   node apexfold_test.js
 *
 * The scan runs twice over part of the list. The first pass fetches `https://<domain>/…`; when
 * the apex has no A record that fails outright, so a second pass retries those on `www.<domain>`,
 * which under RFC 9116 §3 is a legitimate place for the file to live. The analyzer then has to
 * fold two records into one site, and four published numbers depend on it getting that right:
 * the adoption denominator, how many domains the second pass retried, how many of those served a
 * live www host, and how many files it found that the first pass had missed.
 *
 * Every one of those can be wrong in a way that looks fine. Counting fetches instead of sites
 * inflates the denominator. Counting the retry pass over the FOLDED map rather than its own
 * records scores it on the survivors of a tie-break instead of on what it actually probed.
 *
 * The fixture, four apex-less domains, all expectations worked out by hand:
 *
 *   a  apex dead, www answers AND serves a real security.txt   -> the file the first pass missed
 *   b  apex dead, www answers 200 with no file                 -> live host, no file
 *   c  apex dead, www answers, and is probed TWICE             -> must count once, not twice
 *   d  apex dead, www dead too                                 -> retried, not live
 *
 *   => 4 sites from 9 fetch records; 1 security.txt, found only via www;
 *      4 domains retried, 3 of them live = 75.0%; 4 apexes with no address.
 *
 * That last one is the trap this file was written for. `apex_no_address` used to be counted over
 * the folded map, where site `a` keeps its www record because a hit beats a miss — so its dead
 * apex vanished from the total and the number read 3. It would have drifted quietly between the
 * apex-only run and the merged one, shrinking by exactly the cases that make the second pass
 * worth doing.
 */
'use strict';
const fs = require('fs');
const { execFileSync } = require('child_process');

const IN = '/tmp/apexfold_test.jsonl';
const RANK = '/tmp/apexfold_test_rank.csv';
const OUT = '/tmp/apexfold_test.json';

// The fold maps `www.x` back to `x` only for names on the rank list — that list is what defines
// a site here, so a www host with no ranked apex stays its own row rather than being guessed at.
fs.writeFileSync(RANK, '1,a.example\n2,b.example\n3,c.example\n4,d.example\n');

const dead = (d) => JSON.stringify({ domain: d, ok: false, err: 'ENOTFOUND' });
const live = (d, hasFile) => JSON.stringify({
  domain: d, ok: true, status: 200, is_security_txt: hasFile,
  contact: hasFile ? ['mailto:sec@vendor.example'] : [],
  expires: hasFile ? '2030-01-01T00:00:00Z' : null,
  policy: [], canonical: [], field_names: ['contact'], bytes: 50,
});

fs.writeFileSync(IN, [
  dead('a.example'), dead('b.example'), dead('c.example'), dead('d.example'),
  live('www.a.example', true),
  live('www.b.example', false),
  live('www.c.example', false), live('www.c.example', false),  // retried twice on purpose
  dead('www.d.example'),
].join('\n') + '\n');

execFileSync('node', [`${__dirname}/analyze_securitytxt.js`, IN, OUT, '2', RANK],
  { stdio: ['ignore', 'ignore', 'inherit'] });

const got = JSON.parse(fs.readFileSync(OUT, 'utf8'));
const EXPECTED = {
  scanned: 4,                 // sites, not fetches
  fetch_records: 9,
  security_txt: 1,
  found_only_via_www: 1,
  apex_no_address: 4,         // all four apexes were dead, including the one whose www served a file
  'www_pass.domains_retried': 4,
  'www_pass.www_host_responded': 3,   // c counted once despite two probes
  'www_pass.pct_www_alive': 75,
  'www_pass.security_txt_found_only_via_www': 1,
};

let bad = 0;
for (const [k, want] of Object.entries(EXPECTED)) {
  const have = k.split('.').reduce((o, p) => (o == null ? o : o[p]), got);
  const ok = have === want;
  if (!ok) bad++;
  console.log(`${ok ? 'ok  ' : 'FAIL'} ${k.padEnd(42)} got ${String(have).padStart(6)}  want ${want}`);
}
console.log(bad ? `\nAPEX FOLD WRONG — ${bad} mismatch(es)` : '\napex fold matches hand-computed values');
process.exit(bad ? 1 : 0);
