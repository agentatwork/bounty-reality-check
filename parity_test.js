#!/usr/bin/env node
/**
 * parity_test.js — the analyzer's copies are gone; the scanner's are still under test.
 *
 *   node parity_test.js [dataset.jsonl]
 *
 * This file used to diff `analyze_securitytxt.js`'s private `parseContact`, `emailVerdict`,
 * `urlVerdict` and `expiryState` against the library's. It passed for months. Then a real bug —
 * `Contact: mailto: addr@example.com`, a space after the scheme, parsed as malformed — was fixed
 * in the library, the analyzer was re-run, and every published figure came back byte-identical,
 * because the analyzer was still calling its own copy. Two copies that agree with each other are
 * not one rule; they are one rule and one place for the fix to not reach. The survey shipped a
 * wrong number behind that.
 *
 * So the analyzer imports all four now, and the first section below is the guard that keeps it
 * that way: it fails if that file starts defining any of them again. Diffing copies was the wrong
 * job — this asserts there is nothing to diff.
 *
 * `scan_securitytxt.js` still carries its own `parseSecurityTxt` and `looksReal`, and those ARE
 * still compared here, because deleting them means editing the one component whose output cannot
 * be regenerated: the scan is frozen, the survey is published against it, and behavioural equality
 * over hand-made bodies is weaker evidence than not touching it. The duplication stays, under test,
 * until there is a reason to re-scan.
 *
 * No network: these are pure functions, and a parity test that needs the internet does not get run.
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

// These four must NOT exist a second time. The analyzer defined all of them privately until the
// space-after-`mailto:` fix landed in the library and changed nothing, because the analyzer was
// never calling the library. Now it imports them, and this list is what keeps that true.
const DEDUPED = ['parseContact', 'emailVerdict', 'urlVerdict', 'expiryState'];
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

/**
 * The dedup guard. Fails if `file` declares its own copy of a library function, or if it stops
 * importing the library at all — a file that neither imports nor defines these has been
 * restructured in some way this test no longer understands, and passing silently would be worse
 * than failing loudly.
 */
function assertImportsNotCopies(file, names) {
  const src = fs.readFileSync(require.resolve(file), 'utf8');
  const redefined = names.filter(n => new RegExp(`^function ${n}\\(`, 'm').test(src));
  if (redefined.length) {
    return [`${file} defines its own ${redefined.join(', ')} again — the analyzer must import `
      + `these from stxtlib.js. Two copies is how the mailto-space fix silently missed.`];
  }
  if (!/require\(['"]\.\/stxtlib(?:\.js)?['"]\)/.test(src)) {
    return [`${file} does not require stxtlib.js — where is it getting ${names.join(', ')}?`];
  }
  const missing = names.filter(n => !new RegExp(`\\b${n}\\b`).test(src));
  if (missing.length) return [`${file} no longer references ${missing.join(', ')} at all`];
  return [];
}

// Scrub anything host- or address-shaped out of failure output. The dotted-name pattern alone is
// not enough: the first run of the rewritten test failed on a real contact whose domain had a
// COMMA where the dot should be, so the mask did not recognise it and printed a stranger's report
// address into the log. The local part goes too — `user@` identifies a person even with the host
// removed — and any token holding a dot-substitute typo is treated as a host.
const mask = (s) => String(s)
  .replace(/[A-Za-z0-9._%+-]+@[^\s>]+/g, '<addr>')
  .replace(/[A-Za-z0-9-]+(?:[.,;][A-Za-z0-9-]+)+/g, '<host>');

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
// Every DNS fact combination the verdict functions can see, with the answer each must give. This
// was a copy-vs-copy diff; with one copy left it has to state what the right answer IS. Each line
// is a rule from a spec, not a snapshot of current behaviour:
//   [facts, emailVerdict, urlVerdict]
const DNS_CASES = [
  // MX present: mail is deliverable regardless of whether the domain also serves web.
  [{ state: 'EXISTS', hasMx: true, nullMx: false, hasA: true }, 'LIVE-MX', 'RESOLVES'],
  [{ state: 'EXISTS', hasMx: true, nullMx: false, hasA: false }, 'LIVE-MX', 'NO-ADDRESS'],
  // RFC 7505: a null MX is the domain saying, on the record, that it accepts no mail. That is a
  // broken contact even though every lookup succeeded — which is the whole point of the survey.
  [{ state: 'EXISTS', hasMx: false, nullMx: true, hasA: true }, 'NULL-MX', 'RESOLVES'],
  // RFC 5321 §5.1: no MX but an address record means the A/AAAA host IS the mail exchanger.
  [{ state: 'EXISTS', hasMx: false, nullMx: false, hasA: true }, 'IMPLICIT-A', 'RESOLVES'],
  [{ state: 'EXISTS', hasMx: false, nullMx: false, hasA: false }, 'NO-MAIL', 'NO-ADDRESS'],
  // Domain-level states pass through unchanged: what is wrong is the domain, not the service.
  [{ state: 'UNREGISTERED' }, 'UNREGISTERED', 'UNREGISTERED'],
  [{ state: 'DEAD-SUBDOMAIN' }, 'DEAD-SUBDOMAIN', 'DEAD-SUBDOMAIN'],
  [{ state: 'INVALID-TLD' }, 'INVALID-TLD', 'INVALID-TLD'],
];
// Only LIVE-MX and IMPLICIT-A mean a report can actually arrive. Asserted here because the
// published "no working contact" figure is defined by this set, and three files now consume it.
const WORKING = ['LIVE-MX', 'IMPLICIT-A'];

const NOW = Date.parse('2026-08-27T12:00:00Z');
// The last three sit exactly ON the boundary and one millisecond either side of it. Without them
// the suite passed a mutant that changed `t < now` to `t <= now`: three mutations were injected
// to check this test can fail at all, and that one escaped. A test nobody has tried to break is
// an assertion that it has never been broken yet. RFC 9116 §2.5.5 makes an Expires date in the
// past mean the file "should not be used" — so the boundary instant itself is still valid.
const EXPIRY_CASES = [
  [null, 'missing'], ['', 'missing'],
  ['2020-01-01', 'expired'], ['2030-01-01T00:00:00Z', 'valid'], ['not-a-date', 'unparseable'],
  ['2026-08-27T11:00:00Z', 'expired'], ['2026-08-27T13:00:00Z', 'valid'],
  ['2024-01-01T06:00:00.000Z', 'expired'],
  ['2026-08-27T12:00:00Z', 'valid'],                    // exactly now: not yet past
  ['2026-08-27T11:59:59.999Z', 'expired'], ['2026-08-27T12:00:00.001Z', 'valid'],
];

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

async function main() {
  const sc = loadCopies('./scan_securitytxt.js', SCANNER_WANTED);
  const contacts = [...corpusContacts(process.argv[2] || '/tmp/stxt.jsonl'), ...EDGE];
  let diff = 0;
  // Mask the VERDICTS too, not just the input. The first version masked only the input and then
  // printed both parsed objects verbatim — which is to say it printed the real report addresses
  // it had just been careful not to print. A leak that only fires on failure is still a leak,
  // and it fires exactly when attention is elsewhere.
  const report = (what, input, want, got) => {
    if (diff < 10) console.log(`${what} DIFF  ${mask(input)}\n  want: ${mask(want)}\n  got:  ${mask(got)}`);
    diff++;
  };

  // The guard that replaced the diff. Reported through the same counter as everything else, so a
  // reintroduced copy fails the suite rather than printing a warning nobody reads.
  for (const msg of assertImportsNotCopies('./analyze_securitytxt.js', DEDUPED)) {
    console.log(`dedup DIFF  ${msg}`); diff++;
  }

  // Corpus contacts no longer have a second parser to be compared against, so what is checked is
  // the invariant every consumer relies on: an `email` verdict must carry a domain to resolve, a
  // `url` must carry a parseable URL, and nothing may throw on a string a stranger wrote. The
  // parse SHAPES — including the space after `mailto:` that caused all this — are pinned by name
  // in parsecontact_test.js; this is the sweep over 20k real strings that finds the shape nobody
  // thought to name.
  const tlds = await lib.loadTlds();
  for (const c of contacts) {
    let p;
    try { p = lib.parseContact(c); } catch (e) { report('parseContact threw', c, e.message, ''); continue; }
    if (!p || !p.kind) { report('parseContact', c, 'a verdict', JSON.stringify(p)); continue; }
    if (p.kind === 'email') {
      const d = p.domain || '';
      if (!d || /[\s@]/.test(d)) report('email domain unusable as a DNS name', c, 'a hostname', d);
      // Real corpus entries put a comma where the dot belongs, so `parseContact` hands back
      // things like `example,com` — it takes whatever follows the last `@` and does not judge it.
      // That is fine, and it must stay fine for one reason only: the TLD gate in domainFacts
      // catches it before any lookup, so a typo'd address is INVALID-TLD and can never be counted
      // as a working contact. If a mangled domain could ever pass that gate, the published
      // reachability figures would include addresses that bounce.
      else if (!/^[^\s@]+\.[^\s@.]+$/.test(d) && tlds.has(d.split('.').pop())) {
        report('mangled domain would pass the TLD gate', c, 'INVALID-TLD by construction', d);
      }
    }
    if (p.kind === 'url') {
      try { new URL(p.url); } catch { report('url without a parseable URL', c, 'a URL', String(p.url)); }
    }
  }
  for (const [facts, wantEmail, wantUrl] of DNS_CASES) {
    const ge = lib.emailVerdict(facts), gu = lib.urlVerdict(facts);
    if (ge !== wantEmail) report('emailVerdict', JSON.stringify(facts), wantEmail, ge);
    if (gu !== wantUrl) report('urlVerdict', JSON.stringify(facts), wantUrl, gu);
  }
  if (JSON.stringify([...lib.WORKING_VERDICTS].sort()) !== JSON.stringify([...WORKING].sort())) {
    report('WORKING_VERDICTS', 'the set that defines "reachable"',
      WORKING.join(','), [...lib.WORKING_VERDICTS].join(','));
  }
  for (const [e, want] of EXPIRY_CASES) {
    const got = lib.expiryState(e, NOW);
    if (got !== want) report('expiryState', String(e), want, got);
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

  console.log(`checked ${DEDUPED.length} deduped functions, ${contacts.length} contact strings, ${DNS_CASES.length} DNS states, ${EXPIRY_CASES.length} expiry values, ${BODIES.length} file bodies, ${CANON_CASES.length} canonical states`);
  console.log(diff ? `FAIL — ${diff} problem(s)`
    : 'OK — one copy of the contact rules, and the scanner still agrees with it');
  process.exit(diff ? 1 : 0);
}

main();
