#!/usr/bin/env node
/**
 * correction.js — what the `mailto:`-with-a-space parse bug cost, measured rather than asserted.
 *
 *   node correction.js <scan.jsonl> <old_analysis.json> <new_analysis.json> [--write]
 *
 * `Contact: mailto: security@example.com` — one space after the scheme — parsed as `malformed`.
 * parseContact sliced off `mailto:` and split the remainder on whitespace to drop a trailing
 * `(preferred)` comment; with a leading space the first element of that split is the empty string,
 * so a live address was recorded as an unusable contact line. Fixed in stxtlib, pinned by
 * parsecontact_test.js.
 *
 * The published article quotes the size of that mistake, so the size has to come from somewhere
 * auditable. This replays the OLD parser (kept below, deliberately, as the only copy of it left)
 * against the frozen scan, diffs it against the fixed one, and writes the result into the new
 * analysis under `correction` so the draft gate can trace every figure in the correction paragraph
 * back to data.
 *
 * Read-only over the network: no DNS, no fetches. Both analyses are inputs.
 */
'use strict';
const fs = require('fs');
const readline = require('readline');
const { parseContact } = require('./stxtlib');

/**
 * The shipped-and-wrong parser, preserved verbatim. Do not fix this one — it exists to reproduce
 * the published numbers, and a correction that cannot regenerate what it is correcting is an
 * assertion.
 */
function parseContactAsShipped(raw) {
  const v = String(raw).trim();
  const low = v.toLowerCase();
  if (low.startsWith('mailto:')) {
    const addr = v.slice(7).split(/[?\s]/)[0];              // <-- no .trim(): the bug
    const at = addr.lastIndexOf('@');
    return at > 0
      ? { kind: 'email', domain: addr.slice(at + 1).toLowerCase().replace(/\.$/, '') }
      : { kind: 'malformed', raw: v };
  }
  if (low.startsWith('tel:')) return { kind: 'tel' };
  if (low.startsWith('http://') || low.startsWith('https://')) {
    try {
      const u = new URL(v);
      return { kind: 'url', url: v, domain: u.hostname.toLowerCase() };
    } catch { return { kind: 'malformed', raw: v }; }
  }
  if (/^[^\s@]+@[^\s@]+\.[a-z]{2,}$/i.test(v)) {
    return { kind: 'email', bare: true, domain: v.slice(v.lastIndexOf('@') + 1).toLowerCase() };
  }
  return { kind: 'malformed', raw: v };
}

/** How the 147 break down: a contact that failed, versus no usable contact to fail. */
function unreachableShape(analysis) {
  const un = analysis.sites.filter(s => !s.reachable);
  const noVerifiable = un.filter(s => s.contact_verdicts.length === 0);
  return {
    total: un.length,
    // A contact this survey could act on — an address or a portal — that did not work.
    verifiable_and_broken: un.length - noVerifiable.length,
    // A Contact line no client can act on at all: obfuscated address, relative path, scheme typo.
    nothing_verifiable_published: noVerifiable.length,
    // Counted, never dialled. Stated so a reader can subtract them if they disagree with me.
    with_a_telephone_number: un.filter(s => s.kinds && s.kinds.tel).length,
  };
}

async function reparseDelta(scanPath) {
  const out = { contacts_reparsed: 0, sites_affected: 0, sites_previously_unreachable: 0,
    new_contact_domains: 0 };
  const doms = new Set();
  const rl = readline.createInterface({ input: fs.createReadStream(scanPath) });
  for await (const line of rl) {
    if (!line.includes('"is_security_txt":true')) continue;
    let r; try { r = JSON.parse(line); } catch { continue; }
    if (!r.is_security_txt || !r.contact) continue;
    let changed = 0, otherParseable = 0;
    for (const c of r.contact) {
      const was = parseContactAsShipped(c), now = parseContact(c);
      if (was.kind !== now.kind) { changed++; if (now.domain) doms.add(now.domain); }
      else if (was.kind === 'email' || was.kind === 'url') otherParseable++;
    }
    if (changed) {
      out.contacts_reparsed += changed;
      out.sites_affected++;
      // No other contact the old parser could act on, so the site was inside the published
      // "no working contact" figure by construction.
      if (otherParseable === 0) out.sites_previously_unreachable++;
    }
  }
  out.new_contact_domains = doms.size;
  return out;
}

async function main() {
  const [scanPath, oldPath, newPath, ...flags] = process.argv.slice(2);
  if (!newPath) {
    console.error('usage: node correction.js <scan.jsonl> <old.json> <new.json> [--write]');
    process.exit(2);
  }
  const oldA = JSON.parse(fs.readFileSync(oldPath, 'utf8'));
  const newA = JSON.parse(fs.readFileSync(newPath, 'utf8'));

  const correction = {
    ...await reparseDelta(scanPath),
    published_no_working_contact: oldA.reachability['NO-WORKING-CONTACT'],
    corrected_no_working_contact: newA.reachability['NO-WORKING-CONTACT'],
    // Kept because the article quotes both versions of the cross-tab side by side. The two
    // borderline verdicts swapped when the bug was fixed, and a reader cannot judge how thin
    // "separated" was in either direction without the superseded intervals in front of them.
    published_expiry_x_reach_rates: oldA.expiry_x_reach_rates,
    unreachable_shape: unreachableShape(newA),
  };
  correction.sites_recovered =
    correction.published_no_working_contact - correction.corrected_no_working_contact;

  console.log(JSON.stringify(correction, null, 1));
  if (flags.includes('--write')) {
    newA.correction = correction;
    fs.writeFileSync(newPath, JSON.stringify(newA, null, 1));
    console.log(`\nwrote correction into ${newPath}`);
  }
}

if (require.main === module) main();
module.exports = { parseContactAsShipped, unreachableShape };
