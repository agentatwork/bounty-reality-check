#!/usr/bin/env node
/**
 * mkwwwlist_test.js — the second pass gets exactly the domains the first one could not look at.
 *
 *   node mkwwwlist_test.js
 *
 * This list decides three numbers the writeup prints: how many domains the www pass retried, what
 * share of them served a live host, and how many security.txt files it found that the apex pass
 * had missed. It is also the one step whose mistakes are invisible in the output — a list that is
 * too short produces a smaller, perfectly consistent second pass, and nothing downstream can tell
 * that from a web where fewer sites answer on `www.`.
 *
 * Both directions are wrong in a way that matters, and they are not symmetric:
 *
 *   Too wide. Retrying a domain whose apex answered — a timeout, a refused connection, a bad
 *   certificate — is not a second location, it is a second guess at the same site. Anything it
 *   finds gets reported as "a file the apex pass missed" when the apex pass did not miss it.
 *
 *   Too narrow. Dropping a domain that only answers on `www.` biases the survey in its own
 *   favour: "delegated, but no address at the apex" selects for zones nobody has revisited, which
 *   is precisely the population a study of stale contact information is least entitled to lose.
 *
 * The fixture, with every expectation worked out by hand:
 *
 *   a.example   ENOTFOUND, listed TWICE      -> one entry, www.a.example
 *   b.example   ETIMEDOUT                    -> apex answered; not retried
 *   c.example   ECONNREFUSED                 -> apex answered; not retried
 *   d.example   fetched fine                 -> not retried
 *   www.e.example  ENOTFOUND                 -> already a www host; prefixing another is a name
 *                                               nobody publishes
 *   WWW.f.example  ENOTFOUND                 -> same, and DNS is case-insensitive, so the guard
 *                                               has to be too
 *   g.example   ENOTFOUND                    -> www.g.example
 *   (a truncated final line)                 -> ignored, because this is normally run against a
 *                                               file another process is still appending to
 *
 *   => 8 parsed records, 5 ENOTFOUND, 2 skipped as already-www, 2 domains written.
 */
'use strict';
const fs = require('fs');
const { execFileSync } = require('child_process');

const IN = '/tmp/mkwwwlist_test.jsonl';
const OUT = '/tmp/mkwwwlist_test.txt';

fs.writeFileSync(IN,
  '{"domain":"a.example","ok":false,"err":"ENOTFOUND"}\n' +
  '{"domain":"a.example","ok":false,"err":"ENOTFOUND"}\n' +
  '{"domain":"b.example","ok":false,"err":"ETIMEDOUT"}\n' +
  '{"domain":"c.example","ok":false,"err":"ECONNREFUSED"}\n' +
  '{"domain":"d.example","ok":true,"status":200,"is_security_txt":false}\n' +
  '{"domain":"www.e.example","ok":false,"err":"ENOTFOUND"}\n' +
  '{"domain":"WWW.f.example","ok":false,"err":"ENOTFOUND"}\n' +
  '{"domain":"g.example","ok":false,"err":"ENOTFOUND"}\n' +
  '{"domain":"h.example","ok":false,"err":"ENOT');   // torn mid-write, no newline

const stdout = execFileSync('node', [`${__dirname}/mkwwwlist.js`, IN, OUT], { encoding: 'utf8' });
const got = Object.fromEntries(
  [...stdout.matchAll(/(\w+)=(\d+)/g)].map(([, k, v]) => [k, Number(v)]));
const lines = fs.readFileSync(OUT, 'utf8').split('\n').filter(Boolean);

const EXPECTED = {
  records: 8,
  enotfound: 5,
  skipped_already_www: 2,
  wrote: 2,
};

let bad = 0;
for (const [k, want] of Object.entries(EXPECTED)) {
  const ok = got[k] === want;
  if (!ok) bad++;
  console.log(`${ok ? 'ok  ' : 'FAIL'} ${k.padEnd(22)} got ${String(got[k]).padStart(4)}  want ${want}`);
}

// The identities matter as much as the count: two entries could be the right number of the wrong
// domains, and a survey that probes a name the site does not publish reports on nothing.
const WANT_LINES = ['www.a.example', 'www.g.example'];
const sameSet = lines.length === WANT_LINES.length && WANT_LINES.every(d => lines.includes(d));
if (!sameSet) bad++;
console.log(`${sameSet ? 'ok  ' : 'FAIL'} ${'list contents'.padEnd(22)} ${JSON.stringify(lines)}`);

// Every line has to be something scan_securitytxt.js will actually fetch. It accepts either a
// bare domain or `rank,domain`, so a stray comma or a blank line silently becomes a different
// host or an empty one.
const wellFormed = lines.every(d => /^[a-z0-9.-]+$/i.test(d) && !d.includes(','));
if (!wellFormed) bad++;
console.log(`${wellFormed ? 'ok  ' : 'FAIL'} ${'scanner-readable'.padEnd(22)} no commas, no blanks`);

console.log(bad ? `\nWWW LIST WRONG — ${bad} mismatch(es)` : '\nwww retry list matches hand-computed values');
process.exit(bad ? 1 : 0);
