#!/usr/bin/env node
/**
 * parity_test.js — do the two copies of the RFC 9116 classification logic still agree?
 *
 *   node parity_test.js [dataset.jsonl]
 *
 * `stxtlib.js` says at the top that it exists so there is ONE copy of these rules. That is
 * aspirational: `analyze_securitytxt.js` carries its own `parseContact`, `emailVerdict`,
 * `urlVerdict` and `expiryState`. The duplication has already cost something concrete — the
 * undici body-drain crash had to be fixed twice, in two files, weeks apart — and the cost of it
 * drifting is worse than a crash: the survey would publish one classification while `stxtcheck.js`
 * tells a reader something different about their own domain, and nothing would ever fail.
 *
 * So until the analyzer imports the library, this asserts the two behave identically. It runs the
 * real corpus through both (every distinct Contact string in the dataset, which is where the ugly
 * inputs live) plus hand-made edge cases, and every DNS fact combination the verdict functions can
 * see. No network: these are pure functions, and a parity test that needs the internet does not
 * get run.
 *
 * Diffs print the input with hostnames masked — this file is an artifact too, and a failure
 * message that dumps real contact addresses is a leak that only fires when something is wrong.
 */
'use strict';
const fs = require('fs');
const lib = require('./stxtlib.js');

const WANTED = ['parseContact', 'emailVerdict', 'urlVerdict', 'expiryState'];

/**
 * Pull the analyzer's private copies out without running it.
 *
 * Taking "everything above main()" does not work: the analyzer parses argv at the top level and
 * exits with a usage message, so the extraction inherits the exit. Lift only the four function
 * declarations instead — each runs from `^function name(` to the next `}` in column 0, which is
 * exactly this file's style — and none of the four closes over anything outside itself. If that
 * stops being true this throws rather than silently comparing a stale copy.
 */
function loadAnalyzerCopies() {
  const src = fs.readFileSync(require.resolve('./analyze_securitytxt.js'), 'utf8');
  const parts = WANTED.map((name) => {
    const start = src.search(new RegExp(`^function ${name}\\(`, 'm'));
    if (start < 0) throw new Error(`analyzer no longer defines ${name}() — has it started importing stxtlib?`);
    const end = src.indexOf('\n}\n', start);
    if (end < 0) throw new Error(`could not find the end of ${name}()`);
    return src.slice(start, end + 3);
  });
  const m = { exports: {} };
  new Function('module', `${parts.join('\n')}\nmodule.exports = { ${WANTED.join(', ')} };`)(m);
  return m.exports;
}

const mask = (s) => String(s).replace(/[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+/g, '<host>');

function corpusContacts(datasetPath, cap = 20000) {
  const out = [];
  const seen = new Set();
  let txt;
  try { txt = fs.readFileSync(datasetPath, 'utf8'); } catch { return out; }
  for (const line of txt.split('\n')) {
    if (!line || !line.includes('"is_security_txt":true')) continue;
    let r; try { r = JSON.parse(line); } catch { continue; }
    for (const c of r.contact || []) {
      if (seen.has(c) || seen.size >= cap) continue;
      seen.add(c); out.push(c);
    }
    if (seen.size >= cap) break;
  }
  return out;
}

const EDGE = [
  'mailto:a@b.co.', 'MAILTO:X@Y.COM', 'tel:+1-555-0100', 'https://x.example/report',
  'http://x.example/report', 'bare@example.org', 'mailto:no-at-sign', '', '   ',
  'mailto:a@b.example?subject=hi', 'not a uri', '//example.com', 'mailto:', '@example.com',
  'https://', 'MailTo:Mixed@Example.Com', ' mailto:pad@example.com ',
];
const DNS_FACTS = [
  { state: 'EXISTS', hasMx: true, nullMx: false, hasA: true },
  { state: 'EXISTS', hasMx: true, nullMx: false, hasA: false },
  { state: 'EXISTS', hasMx: false, nullMx: true, hasA: true },
  { state: 'EXISTS', hasMx: false, nullMx: false, hasA: true },
  { state: 'EXISTS', hasMx: false, nullMx: false, hasA: false },
  { state: 'UNREGISTERED' }, { state: 'DEAD-SUBDOMAIN' }, { state: 'INVALID-TLD' },
];
const NOW = Date.parse('2026-08-27T12:00:00Z');
// The last three sit exactly ON the boundary and one millisecond either side of it. Without them
// the suite passed a mutant that changed `t < now` to `t <= now`: three mutations were injected
// to check this test can fail at all, and that one escaped. A test nobody has tried to break is
// an assertion that it has never been broken yet.
const EXPIRIES = [null, '', '2020-01-01', '2030-01-01T00:00:00Z', 'not-a-date',
  '2026-08-27T11:00:00Z', '2026-08-27T13:00:00Z', '2024-01-01T06:00:00.000Z',
  '2026-08-27T12:00:00Z', '2026-08-27T11:59:59.999Z', '2026-08-27T12:00:00.001Z'];

function main() {
  const an = loadAnalyzerCopies();
  const contacts = [...corpusContacts(process.argv[2] || '/tmp/stxt.jsonl'), ...EDGE];
  let diff = 0;
  // Mask the VERDICTS too, not just the input. The first version masked only the input and then
  // printed both parsed objects verbatim — which is to say it printed the real report addresses
  // it had just been careful not to print. A leak that only fires on failure is still a leak,
  // and it fires exactly when attention is elsewhere.
  const report = (what, input, a, b) => {
    if (diff < 10) console.log(`${what} DIFF  ${mask(input)}\n  stxtlib:  ${mask(a)}\n  analyzer: ${mask(b)}`);
    diff++;
  };

  // The two copies differ ON PURPOSE in exactly two fields, both payload rather than
  // classification: the analyzer keeps neither `addr` (the local part of a stranger's report
  // address, which it has no use for) nor `raw` (the original string of a tel: or malformed
  // contact). Those are asserted rather than ignored — the comparison is over the fields that
  // drive classification, and a SEPARATE check fails if the key sets ever differ by anything
  // else. Loosening a test until it passes is how drift gets in; this names the permitted
  // differences and still catches everything outside them.
  const CARRIED_NOT_CLASSIFIED = new Set(['addr', 'raw']);
  const CLASSIFY = ['kind', 'domain', 'scheme', 'bare'];
  const proj = (o) => JSON.stringify(CLASSIFY.map(k => o[k] ?? null));
  for (const c of contacts) {
    const la = lib.parseContact(c), ab = an.parseContact(c);
    if (proj(la) !== proj(ab)) report('parseContact', c, mask(proj(la)), mask(proj(ab)));
    const extra = [...new Set([...Object.keys(la), ...Object.keys(ab)])]
      .filter(k => (k in la) !== (k in ab) && !CARRIED_NOT_CLASSIFIED.has(k));
    if (extra.length) report('parseContact key set', c, `keys ${Object.keys(la).join(',')}`, `keys ${Object.keys(ab).join(',')}`);
  }
  for (const s of DNS_FACTS) {
    if (lib.emailVerdict(s) !== an.emailVerdict(s)) report('emailVerdict', JSON.stringify(s), lib.emailVerdict(s), an.emailVerdict(s));
    if (lib.urlVerdict(s) !== an.urlVerdict(s)) report('urlVerdict', JSON.stringify(s), lib.urlVerdict(s), an.urlVerdict(s));
  }
  for (const e of EXPIRIES) {
    if (lib.expiryState(e, NOW) !== an.expiryState(e, NOW)) report('expiryState', e, lib.expiryState(e, NOW), an.expiryState(e, NOW));
  }

  console.log(`checked ${contacts.length} contact strings, ${DNS_FACTS.length} DNS states, ${EXPIRIES.length} expiry values`);
  console.log(diff ? `DIVERGED — ${diff} disagreement(s)` : 'AGREE — the two copies are behaviourally identical');
  process.exit(diff ? 1 : 0);
}

main();
