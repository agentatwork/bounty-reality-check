#!/usr/bin/env node
/**
 * stxtcheck.js — is your security.txt actually a working way to reach you?
 *
 *   node stxtcheck.js example.com
 *   node stxtcheck.js example.com --json
 *
 * Existing validators check that the file PARSES. This checks that it WORKS: that the domain
 * in every Contact still exists, that mail can be delivered to it, that the portal answers,
 * and — the part nothing else checks — that no contact domain has lapsed into a state where a
 * stranger could register it and receive your vulnerability reports instead of you.
 *
 * Exit codes:
 *   0  all contacts reachable
 *   1  could not check: no file, or the name does not resolve, or the host did not answer
 *   2  a contact domain is UNREGISTERED — anyone can claim it and collect your reports
 *   3  a contact is broken but not claimable (dead subdomain, null MX, portal gone), or
 *      nothing verifiable answered at all
 *   4  file is valid but expired, or Expires is missing (RFC 9116 requires it)
 *
 * Read-only. Nothing is registered, and no report address is written to.
 */
'use strict';
const {
  parseContact, expiryState, domainFacts, emailVerdict, urlVerdict, probePortal, fetchSecurityTxt,
  triage, canonicalState,
} = require('./stxtlib');
const { publicSuffixOf } = require('./psl');

const args = process.argv.slice(2);
const JSON_OUT = args.includes('--json');
const domain = args.find(a => !a.startsWith('-'));
if (!domain) {
  console.error('usage: node stxtcheck.js <domain> [--json]');
  process.exit(1);
}

const ICON = {
  'LIVE-MX': '✅', 'RESOLVES': '✅', 'IMPLICIT-A': '⚠️ ', 'NULL-MX': '⛔',
  'NO-MAIL': '⛔', 'NO-ADDRESS': '⛔', 'DEAD-SUBDOMAIN': '🚫', 'INVALID-TLD': '🚫',
  'UNREGISTERED': '🔴',
};
const EXPLAIN = {
  'LIVE-MX': 'mail server accepts reports',
  'RESOLVES': 'host resolves',
  'IMPLICIT-A': 'no MX, A record only — deliverable via RFC 5321 implicit MX, but fragile',
  'NULL-MX': 'RFC 7505 null MX — this domain declares it accepts no mail',
  'NO-MAIL': 'domain exists but has no MX and no A record — mail cannot be delivered',
  'NO-ADDRESS': 'domain exists but has no A record — nothing to connect to',
  'DEAD-SUBDOMAIN': 'does not exist, but only the parent zone owner could create it — bounces, NOT claimable',
  'INVALID-TLD': 'not a delegated TLD — a typo. Unreachable, but nobody can register it either',
  'UNREGISTERED': 'DOES NOT EXIST AND ANYONE CAN REGISTER IT',
};

async function main() {
  const NOW = Date.now();
  const res = await fetchSecurityTxt(domain);
  const out = { domain, checked: new Date(NOW).toISOString() };

  if (!res.ok) {
    // "You publish no file", "your name does not resolve" and "I could not reach you right now"
    // are three different findings, and this reported all of them as the first. That is a small
    // copy of the category error this whole tool exists to catch: a dead name dressed up as a
    // configuration gap. Someone who mistypes their domain deserves to be told they mistyped it,
    // not advised to publish a file at an address that does not exist.
    //
    // All three still exit 1: "I could not verify you" is one outcome to a script, and splitting
    // the codes would say in the exit status what the message already says in words. The README
    // and the article both document 1 as "couldn't check" and enumerate the three — keep those
    // three descriptions in step if this branch ever changes again.
    const DNS_ERRS = new Set(['ENOTFOUND', 'ENODATA', 'EAI_AGAIN']);
    const kind = !res.err ? 'no-file' : DNS_ERRS.has(res.err) ? 'no-dns' : 'unreachable';
    out.result = { 'no-file': 'NO-FILE', 'no-dns': 'NO-DNS', 'unreachable': 'UNREACHABLE' }[kind];
    out.detail = res.err ? `fetch failed: ${res.err}` : `HTTP ${res.status}`;
    if (JSON_OUT) console.log(JSON.stringify(out, null, 1));
    else if (kind === 'no-dns') {
      console.log(`\n  ${domain}`);
      console.log(`  ⛔ ${domain} does not resolve (${res.err})\n`);
      console.log('  There is no host here, so there is nothing to publish a file on and');
      console.log('  nothing to check. If you expected a site at this name, check the spelling');
      console.log('  and check that the zone still carries a record for it.\n');
    } else if (kind === 'unreachable') {
      console.log(`\n  ${domain}`);
      console.log(`  ⛔ could not reach ${domain} (${res.err})\n`);
      console.log('  The name resolves but the request failed, so this says nothing either way');
      console.log('  about whether you publish a security.txt. Retry before concluding anything.\n');
    } else {
      console.log(`\n  ${domain}`);
      console.log(`  ⛔ no security.txt at /.well-known/security.txt (${out.detail})\n`);
      console.log('  RFC 9116 says the file MUST live at that path. Without it, a researcher');
      console.log('  who wants to report a bug has to guess how to reach you.\n');
    }
    process.exit(1);
  }
  if (!res.real) {
    out.result = 'NOT-A-SECURITY-TXT';
    out.detail = res.parsed.contact.length
      ? 'response looks like HTML, not text/plain — probably a soft 404'
      : 'no Contact field — RFC 9116 2.5.3 makes it mandatory';
    if (JSON_OUT) console.log(JSON.stringify(out, null, 1));
    else console.log(`\n  ${domain}\n  ⛔ ${out.detail}\n`);
    process.exit(1);
  }

  const p = res.parsed;
  const contacts = p.contact.map(parseContact);
  const siteReg = publicSuffixOf(domain).registrable;

  const rows = [];
  for (const c of contacts) {
    if (!c.domain) { rows.push({ ...c, verdict: c.kind === 'tel' ? 'TEL' : 'MALFORMED' }); continue; }
    const f = await domainFacts(c.domain);
    const verdict = c.kind === 'url' ? urlVerdict(f) : emailVerdict(f);
    const row = {
      kind: c.kind, value: c.addr || c.url, contact_domain: c.domain, verdict,
      third_party: publicSuffixOf(c.domain).registrable !== siteReg,
      // MX records explain an email verdict and mean nothing for a portal — don't print them there.
      detail: f.detail || (c.kind === 'email' && f.mx && f.mx.length ? f.mx.join(', ') : undefined),
    };
    if (c.kind === 'url' && f.state === 'EXISTS') {
      const pr = await probePortal(c.url);
      row.portal = pr;
    }
    rows.push(row);
  }

  const exp = expiryState(p.expires, NOW);
  out.expires = p.expires || null;
  out.expiry = exp;
  out.contacts = rows;

  // Canonical: RFC 9116 §2.5.2. Rule, the three states, and the one deliberate deviation from the
  // spec are all documented on canonicalState() in stxtlib.
  out.canonical = canonicalState(p.canonical, res.final_url || res.url);

  // Verdict, result string and exit code all come from stxtlib.triage — see the contract note
  // there. Kept in the library rather than here so exit_codes_test.js can drive all five outcomes
  // from row fixtures instead of needing a real domain in each state.
  const verdict = triage(rows, exp);
  const { hijack, broken, working } = verdict;

  out.hijackable = hijack.length;
  out.broken = broken.length;
  out.working = working.length;
  out.result = verdict.result;

  if (JSON_OUT) { console.log(JSON.stringify(out, null, 1)); }
  else {
    console.log(`\n  ${domain} — security.txt found\n`);
    for (const r of rows) {
      if (!r.contact_domain) { console.log(`  ${r.kind === 'tel' ? '📞' : '❓'} ${r.kind}: ${r.value || r.raw || ''}`); continue; }
      const ic = ICON[r.verdict] || '  ';
      const tp = r.third_party ? '  [third-party domain]' : '';
      console.log(`  ${ic} ${r.kind.padEnd(5)} ${r.value}${tp}`);
      console.log(`        ${r.verdict} — ${EXPLAIN[r.verdict] || ''}`);
      if (r.detail && r.verdict !== 'UNREGISTERED') console.log(`        ${r.detail}`);
      if (r.portal) {
        const pw = { ok: 'portal responds', alive_gated: 'server alive but refused this client (bot wall) — a browser is likely fine',
          page_gone: 'PORTAL PAGE IS GONE (404)', server_error: 'server error', timeout: 'timed out' }[r.portal.why] || r.portal.why;
        console.log(`        portal: ${pw}${r.portal.status ? ` [HTTP ${r.portal.status}]` : ''}`);
      }
    }
    const expTxt = { valid: `valid until ${p.expires}`, expired: `EXPIRED ${p.expires}`,
      missing: 'MISSING — RFC 9116 2.5.5 requires it', unparseable: `unparseable (${p.expires})` }[exp];
    console.log(`\n  Expires: ${expTxt}`);
    if (out.canonical === 'MISMATCH') {
      console.log('  Canonical: MISMATCH — the file does not list the URI it was fetched from.');
      console.log('             RFC 9116 2.5.2 says its contents SHOULD NOT be trusted.');
    }
    console.log(`\n  → ${out.result}`);
    if (hijack.length) {
      console.log('\n  One or more contact domains do not exist and are registerable by anyone.');
      console.log('  This is not a bounce. Whoever registers the domain receives your inbound');
      console.log('  vulnerability reports, silently, with no error visible to the reporter.');
      console.log('  Register the domain yourself, or change the contact — today.');
    }
    console.log('');
  }

  process.exit(verdict.exit);
}

main().catch(e => { console.error('error:', e.message); process.exit(1); });
