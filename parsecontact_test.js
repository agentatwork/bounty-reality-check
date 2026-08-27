#!/usr/bin/env node
/**
 * parsecontact_test.js — the Contact-line shapes the corpus actually contains.
 *
 *   node parsecontact_test.js
 *
 * THE CASE THIS EXISTS FOR is one space:
 *
 *     Contact: mailto: security@example.com
 *
 * `parseContact` sliced off the seven characters of `mailto:` and split the rest on whitespace.
 * With a space after the scheme the remainder begins with that space, so the first element of the
 * split is the empty string, `lastIndexOf('@')` is -1, and a working address parsed as
 * `malformed`. Nothing crashed and nothing was logged; the address simply stopped existing.
 *
 * The cost was a published number. 105 Contact lines in the 7,780-file survey are written that
 * way, and for 86 sites it was the only address in the file — so those 86 organisations were
 * counted, in an article about unreachable security contacts, as having no working contact. The
 * bug ran in the direction that made the finding bigger. That is the direction that does not get
 * questioned, which is why it survived a full writeup, a numeric gate over every figure in the
 * prose, and publication.
 *
 * It also survived the fix for a while. The library was corrected first and every number came
 * back identical, because `analyze_securitytxt.js` carried its own byte-identical copy of this
 * function and that copy is the one that produces the published output. Both call the library
 * now; `dupecheck.js` is the standing guard, and this file pins the parse itself.
 *
 * Fixtures are invented under RFC 2606 reserved names rather than sampled from the dataset — a
 * real contact domain in a public test file is the leak this project exists to avoid.
 */
'use strict';
const assert = require('assert');
const { parseContact } = require('./stxtlib');

let checks = 0;
const eq = (a, b, msg) => { checks++; assert.strictEqual(a, b, `${msg}: got ${a}, want ${b}`); };

// ---- THE REGRESSION: whitespace after the scheme ---------------------------------------------
for (const raw of [
  'mailto: security@example.com',
  'mailto:  security@example.com',      // two spaces
  'mailto:\tsecurity@example.com',      // a tab, same failure, different byte
  'MAILTO: security@example.com',       // scheme is case-insensitive (RFC 3986 §3.1)
]) {
  const p = parseContact(raw);
  eq(p.kind, 'email', `${JSON.stringify(raw)} is an address`);
  eq(p.domain, 'example.com', `${JSON.stringify(raw)} domain`);
  eq(p.addr, 'security@example.com', `${JSON.stringify(raw)} address`);
}

// ---- the shapes that already worked, pinned so the fix did not widen anything ----------------
eq(parseContact('mailto:security@example.com').domain, 'example.com', 'plain mailto');
eq(parseContact('mailto:security@example.com?subject=bug').domain, 'example.com', 'query stripped');
eq(parseContact('mailto:security@example.com (preferred)').addr, 'security@example.com',
  'trailing comment stripped');
eq(parseContact('mailto:security@EXAMPLE.COM').domain, 'example.com', 'domain lowercased');
eq(parseContact('mailto:security@example.com.').domain, 'example.com', 'root dot stripped');
eq(parseContact('security@example.com').kind, 'email', 'bare address, no scheme');
eq(parseContact('security@example.com').bare, true, '...and it is marked bare');
eq(parseContact('https://example.com/security').kind, 'url', 'portal');
eq(parseContact('https://example.com/security').domain, 'example.com', 'portal domain');
eq(parseContact('tel:+1-555-0100').kind, 'tel', 'telephone, set aside rather than judged');

// ---- still malformed, and each for a reason worth keeping ------------------------------------
// A scheme with nothing usable behind it. The trim must not turn this into an empty-domain email.
eq(parseContact('mailto:').kind, 'malformed', 'bare scheme');
eq(parseContact('mailto: ').kind, 'malformed', 'scheme and whitespace');
eq(parseContact('mailto: @example.com').kind, 'malformed', 'no local part');
// Deliberate anti-harvesting obfuscation. It is unusable by any client, which is the finding.
eq(parseContact('security dash reports AT example DOT com').kind, 'malformed', 'obfuscated');
// Punctuation typo in the scheme: not a URI, and not something to guess at.
eq(parseContact('https;//example.com/security').kind, 'malformed', 'scheme typo');
eq(parseContact('/security').kind, 'malformed', 'site-relative path is not a URI');
eq(parseContact('').kind, 'malformed', 'empty');

// ---- the property the fix rests on -----------------------------------------------------------
// Whitespace inside the scheme's tail must never change the answer. Asserted as an invariant over
// the padding rather than as four more literals, because the next variant nobody thought of is
// the one that reintroduces this.
for (const pad of ['', ' ', '  ', '\t', ' \t ']) {
  const p = parseContact(`mailto:${pad}security@example.com`);
  eq(p.kind, 'email', `padding ${JSON.stringify(pad)} still parses`);
  eq(p.domain, 'example.com', `padding ${JSON.stringify(pad)} domain`);
}

console.log(`parsecontact_test: ${checks} checks passed`);
