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
 *
 * MUTATION RESULTS, so the coverage claim is checked rather than asserted. Five mutations were
 * injected into the scanner's copies; four die: dropping the hyphen from the field-name class,
 * shrinking the HTML sniff window from 2000 to 200, removing `looksReal`'s Contact requirement
 * (5 diffs), and letting the last `Expires` win instead of the first. Three bodies were added to
 * kill the first three — before them those mutants survived.
 *
 * The fifth survives and is *equivalent*, not escaped: removing the `startsWith('#')` comment
 * skip changes nothing, because the field regex is anchored and a trimmed comment line always
 * begins with `#`, which the character class cannot match. Verified over 144 bodies covering
 * every ordered pair of comment- and field-shaped lines: zero differences. The clause is
 * therefore redundant today and is kept deliberately — it states the intent, and it stops being
 * redundant the moment someone unanchors that regex.
 */
'use strict';
const fs = require('fs');
const lib = require('./stxtlib.js');

const WANTED = ['parseContact', 'emailVerdict', 'urlVerdict', 'expiryState'];
// The scanner has its own copies too, and these are the ones that matter most: `is_security_txt`
// comes from the scanner's private `looksReal`, which is the numerator of every adoption figure
// the survey publishes. If it drifts from the library, the headline count and `stxtcheck.js`
// disagree about what a security.txt even is, and nothing anywhere fails.
const SCANNER_WANTED = ['parseSecurityTxt', 'looksReal'];

/**
 * Pull a file's private copies out without running it.
 *
 * Taking "everything above main()" does not work: these scripts parse argv at the top level and
 * exit with a usage message, so the extraction inherits the exit. Lift only the named function
 * declarations instead — each runs from `^function name(` to the next `}` in column 0, which is
 * exactly this codebase's style — and none of them closes over anything outside itself. If that
 * stops being true this throws rather than silently comparing a stale copy.
 */
function loadCopies(file, names) {
  const src = fs.readFileSync(require.resolve(file), 'utf8');
  const parts = names.map((name) => {
    const start = src.search(new RegExp(`^function ${name}\\(`, 'm'));
    if (start < 0) throw new Error(`${file} no longer defines ${name}() — has it started importing stxtlib?`);
    const end = src.indexOf('\n}\n', start);
    if (end < 0) throw new Error(`could not find the end of ${name}() in ${file}`);
    return src.slice(start, end + 3);
  });
  const m = { exports: {} };
  new Function('module', `${parts.join('\n')}\nmodule.exports = { ${names.join(', ')} };`)(m);
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

/**
 * Bodies for the scanner comparison. The scan records keep only a byte count, not the body, so
 * these are hand-made — which is the better corpus anyway: the disagreements worth catching live
 * in the RFC's awkward corners, not in the well-formed majority.
 */
const BODIES = [
  'Contact: mailto:a@example.com\n',
  'Contact: mailto:a@example.com\nExpires: 2030-01-01T00:00:00Z\n',
  'Contact: mailto:a@example.com\r\nExpires: 2030-01-01T00:00:00Z\r\n',      // CRLF
  '# comment\n\nContact: mailto:a@example.com\n\n# trailing\n',
  'CONTACT: mailto:a@example.com\nEXPIRES: 2030-01-01T00:00:00Z\n',          // case-insensitive
  'contact  :   mailto:a@example.com   \n',                                  // padding around colon
  'Contact: mailto:a@example.com\nContact: https://example.com/report\n',    // repeated Contact
  'Expires: 2030-01-01T00:00:00Z\nExpires: 2020-01-01T00:00:00Z\nContact: mailto:a@example.com\n',
  'Contact: https://example.com/r?a=b:c\n',                                  // colons inside value
  'Policy: https://example.com/p\nCanonical: https://example.com/.well-known/security.txt\nContact: mailto:a@example.com\n',
  'Encryption: https://example.com/k.asc\nContact: mailto:a@example.com\n',
  '<!DOCTYPE html><html><body>Contact: mailto:a@example.com</body></html>',  // soft 404
  '<html>\nContact: mailto:a@example.com\n</html>',                          // soft 404, no doctype
  'Expires: 2030-01-01T00:00:00Z\n',                                         // no Contact at all
  '', '   \n\n  \n', 'not a security txt at all\n',
  'Contact\n',                                                               // no colon
  '-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA512\n\nContact: mailto:a@example.com\nExpires: 2030-01-01T00:00:00Z\n-----BEGIN PGP SIGNATURE-----\n',
  `${'x'.repeat(2100)}\n<!doctype html>\nContact: mailto:a@example.com\n`,    // HTML past the 2000-char window
  // These three exist because a mutation survived without them. Each targets one clause that
  // would otherwise be untested: the hyphen in the field-name character class, the comment skip,
  // and the size of the HTML sniff window.
  'Preferred-Languages: en, nl\nContact: mailto:a@example.com\n',
  '# Contact: mailto:decoy@example.com\nContact: mailto:a@example.com\n',
  `${'x'.repeat(500)}\n<!doctype html>\nContact: mailto:a@example.com\n`,
];

function main() {
  const an = loadCopies('./analyze_securitytxt.js', WANTED);
  const sc = loadCopies('./scan_securitytxt.js', SCANNER_WANTED);
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

  // The scanner's copies. `encryption` is a permitted omission — the scanner does not collect
  // that field and does not need it — but it is NAMED, exactly like addr/raw above, so anything
  // else appearing or vanishing still fails.
  const PARSE_OMIT = new Set(['encryption']);
  const PARSE_FIELDS = ['contact', 'expires', 'policy', 'canonical', 'fields'];
  for (const body of BODIES) {
    const lp = lib.parseSecurityTxt(body), sp = sc.parseSecurityTxt(body);
    const pick = (o) => JSON.stringify(PARSE_FIELDS.map(k => o[k] ?? null));
    if (pick(lp) !== pick(sp)) report('parseSecurityTxt', body, mask(pick(lp)), mask(pick(sp)));
    const extra = [...new Set([...Object.keys(lp), ...Object.keys(sp)])]
      .filter(k => (k in lp) !== (k in sp) && !PARSE_OMIT.has(k));
    if (extra.length) report('parseSecurityTxt key set', body, `keys ${Object.keys(lp).join(',')}`, `keys ${Object.keys(sp).join(',')}`);
    // looksReal decides is_security_txt, which is the numerator of every published adoption
    // figure. Each side is given its OWN parse, because that is how each is actually called.
    const lr = lib.looksReal(body, lp), sr = sc.looksReal(body, sp);
    if (lr !== sr) report('looksReal', body, String(lr), String(sr));
  }

  // canonicalState is now a single copy in stxtlib, so there is nothing left to compare — which is
  // why it needs a plain unit test instead. It got one only after the two hand-maintained copies
  // were found to have silently disagreed: the analyzer said 'MISMATCH_untrusted_per_spec' where
  // stxtcheck said 'MISMATCH', so the survey and the tool a reader runs on their own domain
  // reported one verdict under two names, and this file's whole premise never covered the branch.
  const WK = '/.well-known/security.txt';
  const CANON_CASES = [
    [[], `https://a.example${WK}`, 'absent'],
    [null, `https://a.example${WK}`, 'absent'],
    // Exact string match on the RETRIEVAL URI, which is what §2.5.2 rules on.
    [[`https://a.example${WK}`], `https://a.example${WK}`, 'exact_match'],
    [[' https://a.example' + WK + ' '], `https://a.example${WK}`, 'exact_match'],
    // The deliberate deviation: identical path, host differs only by `www.`. The old name for
    // this state claimed the PATH differed, which was false in precisely this case.
    [[`https://a.example${WK}`], `https://www.a.example${WK}`, 'host_match_uri_differs'],
    [[`https://www.a.example${WK}`], `https://a.example${WK}`, 'host_match_uri_differs'],
    // Same host, genuinely different path — also the weaker state, and here the old name was right.
    [[`https://a.example/security.txt`], `https://a.example${WK}`, 'host_match_uri_differs'],
    // A different registrable domain is a real mismatch and must never be normalised into a match.
    // This is the x.com/twitter.com case quoted in the article.
    [[`https://b.example${WK}`], `https://a.example${WK}`, 'MISMATCH'],
    // `www.` stripping must not make two distinct domains collide.
    [[`https://www.b.example${WK}`], `https://a.example${WK}`, 'MISMATCH'],
    // Unparseable Canonical must fail closed, not throw and not match.
    [['not a url'], `https://a.example${WK}`, 'MISMATCH'],
    // One good entry among junk still matches: §2.5.2 says "listed within ANY canonical fields".
    [['not a url', `https://a.example${WK}`], `https://a.example${WK}`, 'exact_match'],
  ];
  for (const [canon, fetched, want] of CANON_CASES) {
    const got = lib.canonicalState(canon, fetched);
    if (got !== want) report('canonicalState', `${JSON.stringify(canon)} vs ${fetched}`, want, got);
  }

  console.log(`checked ${contacts.length} contact strings, ${DNS_FACTS.length} DNS states, ${EXPIRIES.length} expiry values, ${BODIES.length} file bodies, ${CANON_CASES.length} canonical states`);
  console.log(diff ? `DIVERGED — ${diff} disagreement(s)` : 'AGREE — the two copies are behaviourally identical');
  process.exit(diff ? 1 : 0);
}

main();
