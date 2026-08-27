#!/usr/bin/env node
/**
 * exit_codes_test.js — the exit codes the writeup tells readers to script against.
 *
 *   node exit_codes_test.js
 *
 * The article documents five exit codes and says of one of them "if it exits 2, that is the one to
 * fix today". That makes them an API, and an exit code is the one output a human never looks at:
 * you run the tool, you read the pretty printout, and the number goes to a shell that isn't there.
 * A wrong code is invisible until someone puts it in CI, which is exactly when it matters.
 *
 * This drives stxtlib.triage() from row fixtures rather than from live domains. Doing it the
 * other way — finding a real site in each of the five states — is what kept this untested: those
 * sites are hard to find, they change underneath you, and a test that needs the network to agree
 * with it is a test that gets deleted the first time a resolver hiccups.
 *
 * The fixtures are invented, not sampled. Every domain here is under RFC 2606's reserved names.
 * That is not incidental tidiness: a fixture drawn from the survey's own dataset would put real
 * still-unregistered contact domains into a file that ships publicly, which is the exact leak the
 * whole project is built to avoid.
 *
 * THE CASE THIS EXISTS FOR is `lone portal that times out`. A timeout is not `page_gone`, so that
 * contact is in neither `broken` nor `working`, and the shipped ternary read the empty broken list
 * as good news: the tool printed NO-WORKING-CONTACT and exited 0, "all contacts reachable". The
 * failure ran in the direction that makes the tool look reassuring, which is the direction that
 * does not get noticed. It is fixed; this pins it fixed.
 */
'use strict';
const assert = require('assert');
const { triage, BROKEN_VERDICTS, WORKING_VERDICTS } = require('./stxtlib');

let checks = 0;
const eq = (a, b, msg) => { checks++; assert.strictEqual(a, b, `${msg}: got ${a}, want ${b}`); };

/** A contact row as stxtcheck builds one. `d` present means the tool could verify it. */
const row = (verdict, portal, d = 'example.com') =>
  ({ verdict, contact_domain: d, ...(portal ? { portal } : {}) });
const tel = () => ({ verdict: null, contact_domain: null, kind: 'tel', value: '+1-555-0100' });

// ---- 0: everything works -------------------------------------------------------------------
eq(triage([row('LIVE-MX')], 'valid').exit, 0, 'live MX, unexpired');
eq(triage([row('LIVE-MX')], 'valid').result, 'OK', 'live MX result');
eq(triage([row('IMPLICIT-A')], 'valid').exit, 0, 'implicit MX is deliverable');
eq(triage([row('RESOLVES', { reachable: true })], 'valid').exit, 0, 'portal answers');

// ---- 2: hijackable, and it outranks every other failure ------------------------------------
eq(triage([row('UNREGISTERED')], 'valid').exit, 2, 'unregistered contact domain');
eq(triage([row('UNREGISTERED')], 'valid').result, 'HIJACKABLE-CONTACT', 'hijack result');
// Precedence is the whole point of the ordering, so it is asserted rather than assumed: a file
// that is expired AND has a dead subdomain AND has a claimable domain must still say 2. A tool
// that reported the staleness here would bury the one finding that is silently exploitable.
eq(triage([row('UNREGISTERED'), row('DEAD-SUBDOMAIN'), row('LIVE-MX')], 'expired').exit, 2,
  'hijackable outranks expired and broken');
eq(triage([row('UNREGISTERED')], 'missing').exit, 2, 'hijackable outranks missing Expires');

// ---- 3: broken but not claimable -----------------------------------------------------------
for (const v of BROKEN_VERDICTS) {
  eq(triage([row(v)], 'valid').exit, 3, `${v} alone is broken`);
  eq(triage([row(v)], 'valid').result, 'NO-WORKING-CONTACT', `${v} alone leaves nothing working`);
}
// A portal whose page is gone is broken even though the domain resolves fine.
eq(triage([row('RESOLVES', { reachable: false, why: 'page_gone' })], 'valid').exit, 3,
  'portal 404 is broken');
// Partially broken: one contact works, another does not. Still 3 — exit 0 claims ALL reachable.
const partial = triage([row('LIVE-MX'), row('NULL-MX')], 'valid');
eq(partial.exit, 3, 'one working + one broken is still not "all reachable"');
eq(partial.result, 'PARTIALLY-BROKEN', 'partial result');
eq(partial.working.length, 1, 'partial keeps the working one');

// ---- 3: THE REGRESSION — neither broken nor working ----------------------------------------
// A lone portal that timed out. `why` is not `page_gone`, so `broken` is EMPTY, and the old code
// read that empty list as success. The assertion below is the one that would have failed.
const timedOut = triage([row('RESOLVES', { reachable: false, why: 'timeout' })], 'valid');
eq(timedOut.broken.length, 0, 'a timeout is genuinely not in the broken list');
eq(timedOut.working.length, 0, '...nor in the working list');
eq(timedOut.noWorking, true, '...but nothing verifiable answered');
eq(timedOut.exit, 3, 'REGRESSION: timed-out sole contact must not exit 0');
eq(timedOut.result, 'NO-WORKING-CONTACT', 'and must say so');
// Same shape via a server error, to show the fix is about the empty-list logic and not about
// special-casing the string 'timeout'.
eq(triage([row('RESOLVES', { reachable: false, why: 'server_error' })], 'valid').exit, 3,
  'server_error sole contact also exits 3');

// ---- 4: valid file, stale date -------------------------------------------------------------
eq(triage([row('LIVE-MX')], 'expired').exit, 4, 'expired but reachable');
eq(triage([row('LIVE-MX')], 'expired').result, 'STALE', 'expired result');
eq(triage([row('LIVE-MX')], 'missing').exit, 4, 'missing Expires is a 2.5.5 violation');
// Broken outranks stale: the channel not working is worse than the date being old.
eq(triage([row('NULL-MX')], 'expired').exit, 3, 'broken outranks stale');
// `unparseable` is neither expired nor missing, so it must not trigger 4. It is a parse problem,
// and inventing a staleness verdict from a date nobody could read would be a guess.
eq(triage([row('LIVE-MX')], 'unparseable').exit, 0, 'unparseable Expires is not a staleness claim');

// ---- the tel: exclusion --------------------------------------------------------------------
// An unverifiable contact must not certify a site as reachable, and must not condemn it either.
const onlyTel = triage([tel()], 'valid');
eq(onlyTel.verifiable.length, 0, 'tel is not verifiable');
eq(onlyTel.noWorking, false, 'nothing verifiable failed, because nothing was verifiable');
eq(onlyTel.result, 'UNVERIFIABLE-CONTACT', 'says it could not check, rather than passing it');
eq(onlyTel.exit, 0, 'and does not condemn a site for a contact it cannot dial');
// With a real working contact alongside, the tel must not drag the denominator anywhere.
eq(triage([tel(), row('LIVE-MX')], 'valid').exit, 0, 'tel + working mail is fine');
eq(triage([tel(), row('NULL-MX')], 'valid').exit, 3, 'tel does not rescue a dead mail contact');
eq(triage([tel(), row('NULL-MX')], 'valid').result, 'NO-WORKING-CONTACT',
  'tel is not counted as the thing that works');

// ---- the empty file ------------------------------------------------------------------------
// No contacts at all. RFC 9116 requires Contact, so this is a malformed file, but triage is not
// where that is caught — stxtcheck exits 1 before reaching here. What matters is that it does not
// claim OK: zero contacts is not "all contacts reachable".
eq(triage([], 'valid').result, 'UNVERIFIABLE-CONTACT', 'no contacts is not OK');

// ---- the codes are the ones the article documents -------------------------------------------
// Guards against a renumbering that keeps every test above passing while breaking every reader.
const DOCUMENTED = new Set([0, 2, 3, 4]);   // 1 is emitted before triage: no file, or no parse
for (const [rows, exp] of [
  [[row('LIVE-MX')], 'valid'], [[row('UNREGISTERED')], 'valid'],
  [[row('NULL-MX')], 'valid'], [[row('LIVE-MX')], 'expired'], [[tel()], 'valid'],
]) {
  checks++;
  assert.ok(DOCUMENTED.has(triage(rows, exp).exit), 'exit code outside the documented set');
}
// And that the two verdict lists have not silently gained or lost a member. Adding a verdict to
// the enum without deciding which bucket it belongs in is how a new failure mode ends up counted
// as success by default.
eq(BROKEN_VERDICTS.join(','), 'NULL-MX,NO-MAIL,NO-ADDRESS,DEAD-SUBDOMAIN,INVALID-TLD', 'broken set');
eq(WORKING_VERDICTS.join(','), 'LIVE-MX,IMPLICIT-A', 'working set');

console.log(`${checks} assertions pass`);
console.log('exit codes match the contract the writeup publishes');
