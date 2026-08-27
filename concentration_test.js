#!/usr/bin/env node
/**
 * concentration_test.js — check the contact-concentration arithmetic against known answers.
 *
 *   node concentration_test.js
 *
 * Six numbers from `contact_concentration` go straight into the writeup: how many distinct
 * third-party contact domains there are, how many site citations they carry, what share the
 * largest one and the top ten hold, how many domains are the security contact for ten or more
 * organisations, and the blast radius of the worst hijackable one. They were verified by reading
 * the code, which is the weakest kind of verification available and the one most likely to agree
 * with whatever the author already believed.
 *
 * So: a corpus whose distribution is known by construction, and expected values worked out by
 * hand rather than by running the thing and writing down what it said.
 *
 *   1 domain cited by 12 sites, 1 by exactly 10, 1 by 5, 1 by 3, and 10 cited once each
 *   => 14 distinct domains, 40 citations, top1 = 12/40 = 30.0%,
 *      top5 = (12+10+5+3+1)/40 = 77.5%, top10 = (12+10+5+3+6)/40 = 90.0%, top20 = 100.0%
 *      two domains serve >= 10 sites, covering 22; 10 singletons
 *
 * The domain cited by EXACTLY ten exists because a mutant survived without it. `>= 10` was
 * changed to `> 10` and every expected value still matched, since the largest group had twelve —
 * the boundary of `domains_serving_10plus_sites`, a number the article prints, was never tested.
 * Same escape as the `Expires` off-by-one in parity_test.js: a threshold with no value sitting
 * on it is a threshold nobody has checked.
 *
 * A second mutant survives and is EQUIVALENT: `singletons` counting `n <= 1` rather than `n === 1`
 * cannot differ, because a domain only enters the map when a site cites it, so `n` is never 0.
 * Argued, then checked — the two variants produce byte-identical output over 1,500 real scan
 * records (66 distinct contact domains, 188 citations, 50 singletons), which is the part of
 * "equivalent mutant" that is otherwise just the author declining to improve the test.
 *
 * One of the twelve sites lists the same contact domain twice, in two different Contact lines.
 * Citations are counted per SITE, so that must still register as one — a site with two addresses
 * at its bug bounty provider is not two organisations exposed, and counting it as two would
 * inflate every concentration figure in the article.
 *
 * Contacts use `.invalid` (RFC 2606, permanently undelegated) so classification resolves to
 * INVALID-TLD without a single DNS query: the test is fast, offline, and deterministic. That
 * also fixes the expected hijackable blast radius at 0, which exercises the zero path — the
 * answer the writeup most likely has to publish, and the one worth being sure about.
 */
'use strict';
const fs = require('fs');
const { execFileSync } = require('child_process');

const IN = '/tmp/conc_test.jsonl';
const OUT = '/tmp/conc_test.json';

const site = (i, contacts) => JSON.stringify({
  domain: `site${i}.example`, ok: true, status: 200, is_security_txt: true,
  contact: contacts, expires: '2030-01-01T00:00:00Z', policy: [], canonical: [],
  field_names: ['contact', 'expires'], bytes: 100,
});

const lines = [];
let n = 0;
for (let i = 0; i < 12; i++) {
  // the last of the twelve cites the same domain twice, via two different addresses
  const c = i === 11
    ? ['mailto:security@c1.invalid', 'mailto:abuse@c1.invalid']
    : ['mailto:security@c1.invalid'];
  lines.push(site(n++, c));
}
// exactly ten: sits on the `>= 10` boundary so `> 10` cannot pass unnoticed
for (let i = 0; i < 10; i++) lines.push(site(n++, ['mailto:security@c14.invalid']));
for (let i = 0; i < 5; i++) lines.push(site(n++, ['mailto:security@c2.invalid']));
for (let i = 0; i < 3; i++) lines.push(site(n++, ['mailto:security@c3.invalid']));
for (let i = 4; i <= 13; i++) lines.push(site(n++, [`mailto:security@c${i}.invalid`]));
fs.writeFileSync(IN, lines.join('\n') + '\n');

// A rank file that does not exist: rank analysis is skipped and every site lands in `unranked`,
// which is irrelevant here and keeps the fixture from depending on a 200k CSV.
execFileSync('node', [`${__dirname}/analyze_securitytxt.js`, IN, OUT, '2', '/tmp/does-not-exist.csv'],
  { stdio: ['ignore', 'ignore', 'inherit'] });

const got = JSON.parse(fs.readFileSync(OUT, 'utf8')).contact_concentration;
const EXPECTED = {
  distinct_third_party_contact_domains: 14,
  site_citations: 40,
  share_top1_pct: 30.0,
  share_top5_pct: 77.5,
  share_top10_pct: 90.0,
  share_top20_pct: 100.0,
  domains_serving_10plus_sites: 2,
  sites_behind_domains_serving_10plus: 22,
  singletons: 10,
  worst_hijackable_blast_radius: 0,
  hijackable_contact_domains: 0,
  sites_behind_hijackable_contact_domains: 0,
};

let bad = 0;
for (const [k, want] of Object.entries(EXPECTED)) {
  const have = got[k];
  const ok = have === want;
  if (!ok) bad++;
  console.log(`${ok ? 'ok  ' : 'FAIL'} ${k.padEnd(42)} got ${String(have).padStart(6)}  want ${want}`);
}
const sizes = JSON.stringify(got.top_sizes);
const wantSizes = JSON.stringify([12, 10, 5, 3, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1]);
if (sizes !== wantSizes) { bad++; console.log(`FAIL top_sizes                                  got ${sizes}  want ${wantSizes}`); }
else console.log(`ok   top_sizes`);

console.log(bad ? `\nCONCENTRATION WRONG — ${bad} mismatch(es)` : '\nconcentration arithmetic matches hand-computed values');
process.exit(bad ? 1 : 0);
