#!/usr/bin/env node
/**
 * psl.js — the registrable-domain boundary, in one place.
 *
 * Split out because this rule is subtle enough that a second copy WILL drift from the first,
 * and getting it wrong silently inflates a security finding. Consider `mail.someconsultancy.com`
 * and `someshop.com.br`: both can return NXDOMAIN, and both have three labels. The first is a
 * missing host inside a zone its owner controls — nobody outside can ever create it. The second
 * is a registrable name under a public suffix (`com.br`), so anyone can buy it and receive mail
 * for it. Only the Public Suffix List separates the two; "count the dots" gets it backwards
 * about as often as not.
 *
 * Data: vendored public_suffix_list.dat (Mozilla, MPL-2.0), comments stripped.
 */
'use strict';
const fs = require('fs');
const path = require('path');

let PSL = null;
function load() {
  if (PSL) return PSL;
  const raw = fs.readFileSync(path.join(__dirname, 'public_suffix_list.dat'), 'utf8');
  PSL = { rules: new Set(), excl: new Set() };
  for (const line of raw.split('\n')) {
    const r = line.trim();
    if (!r) continue;
    if (r.startsWith('!')) PSL.excl.add(r.slice(1)); else PSL.rules.add(r);
  }
  return PSL;
}

/**
 * @returns {{suffix: string, registrable: string}} the public suffix and the eTLD+1.
 * For a name already AT the registrable level, `registrable === domain`.
 */
function publicSuffixOf(domain) {
  const p = load();
  const labels = String(domain).toLowerCase().split('.');
  let best = '';
  for (let i = 0; i < labels.length; i++) {
    const cand = labels.slice(i).join('.');
    if (p.excl.has(cand)) { best = labels.slice(i + 1).join('.'); break; }
    const wild = ['*', ...labels.slice(i + 1)].join('.');
    if (p.rules.has(cand) || p.rules.has(wild)) { best = cand; break; }
  }
  if (!best) best = labels[labels.length - 1];   // unlisted TLD: treat the TLD as the suffix
  const depth = best.split('.').length;
  return { suffix: best, registrable: labels.slice(Math.max(0, labels.length - depth - 1)).join('.') };
}

/** True when `domain` sits BELOW its registrable domain — i.e. only the zone owner can create it. */
function isSubdomain(domain) {
  const { registrable } = publicSuffixOf(domain);
  return Boolean(registrable) && registrable !== String(domain).toLowerCase();
}

module.exports = { publicSuffixOf, isSubdomain };

// Self-test. Every example here is invented or a well-known public service — never a domain
// drawn from a survey result, because an illustrative example is a leak vector.
if (require.main === module) {
  const cases = process.argv.slice(2);
  if (cases.length) {
    for (const d of cases) {
      const r = publicSuffixOf(d);
      console.log(`${d.padEnd(30)} suffix=${r.suffix.padEnd(12)} registrable=${r.registrable.padEnd(24)} ${isSubdomain(d) ? 'SUBDOMAIN (owner-only)' : 'registrable (anyone)'}`);
    }
    process.exit(0);
  }
  const expect = [
    ['example.com', 'com', 'example.com', false],
    ['mail.example.com', 'com', 'example.com', true],
    ['example.com.br', 'com.br', 'example.com.br', false],   // com.br IS a public suffix
    ['mail.example.com.br', 'com.br', 'example.com.br', true],
    ['example.co.uk', 'co.uk', 'example.co.uk', false],
    ['a.b.example.co.uk', 'co.uk', 'example.co.uk', true],
    ['someproject.github.io', 'github.io', 'someproject.github.io', false], // wildcard-ish private suffix
    ['example.dev', 'dev', 'example.dev', false],
    ['localhost', 'localhost', 'localhost', false],          // unlisted TLD: degrade, don't crash
  ];
  let bad = 0;
  for (const [d, sfx, reg, sub] of expect) {
    const r = publicSuffixOf(d);
    const ok = r.suffix === sfx && r.registrable === reg && isSubdomain(d) === sub;
    if (!ok) bad++;
    console.log(`${ok ? 'ok  ' : 'FAIL'} ${d.padEnd(24)} suffix=${r.suffix} registrable=${r.registrable} subdomain=${isSubdomain(d)}`);
  }
  console.log(bad ? `\n${bad} FAILED` : '\nall ok');
  process.exit(bad ? 1 : 0);
}
