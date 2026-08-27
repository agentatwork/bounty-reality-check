#!/usr/bin/env node
/**
 * notifiable.js — of the sites this survey found a problem at, how many can be TOLD?
 *
 *   node notifiable.js stxt_analysis.json            # print the breakdown
 *   node notifiable.js stxt_analysis.json --write    # also store it under `notifiability`
 *
 * A survey that finds a broken disclosure channel has an obvious duty attached, and an equally
 * obvious obstacle: the broken thing IS the channel. This computes how far that obstacle goes.
 *
 * A site is notifiable through its own published file only if some OTHER contact in that same
 * file is independently working — a second email on a live domain, or a disclosure portal that
 * answers. Anything else means the only address the organisation published is the one that
 * doesn't work, and there is no way to reach them that they consented to.
 *
 * Derived from the frozen analysis rather than recomputed. The analyzer resolves live DNS, so
 * re-running it to add one number would move every published figure underneath the article that
 * quotes them. Same input, same operating point, no new network — see the sibling replay in the
 * canonical-state refactor for the same reasoning.
 *
 * The contact STRINGS are deliberately not in the analysis and are not printed here. This file
 * answers "how many", never "which" — the list of addresses that receive vulnerability reports
 * and don't work is a shopping list, and it is the one artifact this project must never emit.
 */
'use strict';
const fs = require('fs');
const { WORKING_VERDICTS } = require('./stxtlib');

/** Did this verdict describe a contact that actually works, right now?
 *
 *  The email half comes from stxtlib rather than being restated here. It was two hand-written
 *  copies before this file existed — the library's and the analyzer's — and a third one that
 *  agreed with them today is exactly how that stops being true later.
 */
function isWorking(v) {
  if (v.kind === 'email') return WORKING_VERDICTS.includes(v.verdict);
  if (v.kind === 'url') return v.portal_ok === true;
  return false;
}

/** A contact that is claimable by a stranger, as against merely broken. */
function isHijackable(v) {
  return v.verdict === 'UNREGISTERED';
}

function breakdown(sites) {
  const affected = sites.filter(s => s.hijackable_email || s.hijackable_portal);
  const broken = sites.filter(s => !s.reachable);

  const notifiable = affected.filter(s => s.contact_verdicts.some(v => isWorking(v)));
  // The starkest cut: the organisation published exactly one address, and it is claimable.
  const soleContactHijackable = affected.filter(
    s => s.contacts === 1 && s.contact_verdicts.some(isHijackable));

  return {
    hijackable_sites: affected.length,
    hijackable_notifiable_via_own_file: notifiable.length,
    hijackable_unreachable_by_construction: affected.length - notifiable.length,
    hijackable_sole_contact_is_the_broken_one: soleContactHijackable.length,
    no_working_contact_sites: broken.length,
    // Must be 0, and that is the point of computing it: the analyzer decided `reachable` itself,
    // so a non-zero here would mean isWorking() above disagrees with the definition the published
    // numbers were built on. It is a check on this re-derivation, not a measurement.
    no_working_contact_notifiable_via_own_file: broken.filter(
      s => s.contact_verdicts.some(v => isWorking(v))).length,
  };
}

function main() {
  const [path, ...flags] = process.argv.slice(2);
  if (!path) { console.error('usage: node notifiable.js <analysis.json> [--write]'); process.exit(2); }
  const analysis = JSON.parse(fs.readFileSync(path, 'utf8'));
  const out = breakdown(analysis.sites);

  for (const [k, v] of Object.entries(out)) console.log(`${k.padEnd(46)} ${v}`);

  if (flags.includes('--write')) {
    analysis.notifiability = out;
    fs.writeFileSync(path, JSON.stringify(analysis, null, 1));
    console.log(`\nwrote notifiability into ${path}`);
  }
}

if (require.main === module) main();
module.exports = { breakdown, isWorking, isHijackable };
