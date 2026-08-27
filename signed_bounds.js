#!/usr/bin/env node
'use strict';
// Checks the finished signed-security.txt run against the bounds written in SIGNED_PREREG.md
// BEFORE the run. A number that violates one of these means the harness is wrong, and the point of
// writing them down first is that afterwards every result has a story that makes it sound fine.
//
//   node signed_bounds.js /tmp/stxt_signed.json /tmp/stxt_all.jsonl /tmp/stxt_bodies.jsonl

const fs = require('fs');
const lib = require('./signedlib');

const [resPath, corpusPath, bodiesPath] = process.argv.slice(2);
if (!resPath || !corpusPath || !bodiesPath) {
  console.error('usage: node signed_bounds.js <result.json> <corpus.jsonl> <bodies.jsonl>');
  process.exit(1);
}
const R = JSON.parse(fs.readFileSync(resPath, 'utf8'));
const A = R.aggregate, S = R.stats;

let bad = 0;
const bound = (name, ok, detail) => {
  if (!ok) bad++;
  console.log(`${ok ? 'ok  ' : 'FAIL'}  ${name}${detail ? '  — ' + detail : ''}`);
};

// Corpus facts needed by the bounds.
const isSec = new Set(), sigField = new Set();
for (const line of fs.readFileSync(corpusPath, 'utf8').split('\n')) {
  if (!line) continue;
  let d; try { d = JSON.parse(line); } catch { continue; }
  if (!d.is_security_txt) continue;
  isSec.add(d.domain);
  if ((d.field_names || []).includes('signature')) sigField.add(d.domain);
}

const signedDomains = new Set(R.verdicts.map((v) => v.domain));
const pct = (a, b) => (b ? (100 * a / b) : 0);

// 1. The paper's manual subset said "nearly all" unsigned. A detector firing on more than a tenth
//    of the corpus is matching something that is not a cleartext signature.
bound('A ≤ 10% of analyzable files are signed',
  pct(A.signed_total, S.analyzable) <= 10,
  `${A.signed_total}/${S.analyzable} = ${pct(A.signed_total, S.analyzable).toFixed(2)}%`);

// 2. `Signature` is not an RFC 9116 field. If the signed set were those files, I detected a field
//    name and not the wrapper.
{
  const overlap = [...sigField].filter((d) => signedDomains.has(d)).length;
  bound('A is not merely the files with a `signature` field name',
    !(overlap === A.signed_total && sigField.size === A.signed_total),
    `${sigField.size} files carry a signature field, ${overlap} of them are in the signed set`);
}

// 3. A key ID cannot coincide with a published key that was never published or never fetched.
{
  const fetchable = R.verdicts.filter((v) => v.encryption_kinds.some(
    (k) => k === 'https' || k === 'http_violates_2_5_6')).length;
  bound('D ≤ signed files that publish a fetchable key URL',
    A.issuer_in_published_key <= fetchable,
    `${A.issuer_in_published_key} coincide ≤ ${fetchable} publish a fetchable key`);
}

// 4. gpg cannot verify against a key whose ID did not make the signature.
bound('E ≤ D',
  (A.verified_good + A.verified_good_key_expired + (A.bad_signature || 0)) <= A.issuer_in_published_key,
  `${A.verified_good} good + ${A.verified_good_key_expired} good/expired-key + ${A.bad_signature} bad `
  + `≤ ${A.issuer_in_published_key} coincide`);

// 5. A cleartext wrapper around something that was never a security.txt is my parse failure.
{
  const strays = R.verdicts.filter((v) => !isSec.has(v.domain)).length;
  bound('every signed file is one the first pass classified as a security.txt', strays === 0,
    `${strays} outside the corpus's security.txt set`);
}

// 6. Detection composition: if the detector cannot tell a pasted public key block from a signature,
//    key_block_but_unsigned is zero and the signed count is inflated by exactly those files.
bound('the detector separates pasted key blocks from signatures',
  S.key_block_but_unsigned > 0,
  `${S.key_block_but_unsigned} files paste a public key block and are correctly not counted as signed`);

// 7. Hand-check: re-derive the signed verdict for a spread of the signed set straight from the
//    bodies file, independently of the analyzer's bookkeeping.
{
  const bodies = new Map();
  for (const line of fs.readFileSync(bodiesPath, 'utf8').split('\n')) {
    if (!line) continue;
    let d; try { d = JSON.parse(line); } catch { continue; }
    bodies.set(d.domain, d);
  }
  const picks = R.verdicts.filter((_, i) => i % Math.max(1, Math.floor(R.verdicts.length / 25)) === 0);
  let wrong = 0;
  for (const v of picks) {
    const b = bodies.get(v.domain);
    const st = b ? lib.signedState(b.body || '') : { signed: false };
    if (!st.signed) wrong++;
  }
  bound(`a ${picks.length}-file spread of the signed set really carries the wrapper`, wrong === 0,
    `${picks.length - wrong}/${picks.length} confirmed from the raw body`);
}

console.log(bad ? `\n${bad} bound(s) violated — the harness is wrong, not the web` : '\nall pre-registered bounds hold');
process.exit(bad ? 1 : 0);
