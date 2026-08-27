#!/usr/bin/env node
/**
 * draftcheck.js — can every number in the writeup be traced to the analysis it came from?
 *
 *   node draftcheck.js draft.md analysis.json      # exit 1 if anything is unfilled or unsourced
 *
 * Two failure modes, both of which have already happened to me on published work.
 *
 * A placeholder survives to publication. The draft is written before the run finishes, with
 * ⟨TOKENS⟩ standing in for numbers that do not exist yet. One left in is a visible embarrassment;
 * worse is the one silently replaced by a plausible number remembered from a pilot run.
 *
 * A number is quoted from the wrong operating point. I once published "9 of 11 improved to 11 of
 * 11" by taking the count from one decision rule and the worst case from another. Both numbers
 * were real. Neither was wrong on its own. Together they described a run that never happened, and
 * the error flattered me, which is why it survived several readings.
 *
 * So the rule enforced here is mechanical: every numeric literal in the prose must either appear
 * in the analysis JSON, or be listed below as coming from somewhere else, with its source named.
 * A number that is in neither place is one I made up, however honestly.
 *
 * What this does NOT check: that a sourced number is in the RIGHT sentence. Nothing automatic can.
 * It narrows the failure to "a real number in the wrong place" from "any number at all", which is
 * the difference between a mistake a careful reread can catch and one it cannot.
 */
'use strict';
const fs = require('fs');

/**
 * Numbers that legitimately do not come from my analysis. Each needs a source, because an
 * unexplained entry here is indistinguishable from a number I could not justify and chose to
 * silence — the exact move this file exists to prevent.
 */
const EXTERNAL = new Map([
  // Structure of the standard being surveyed.
  ['9116', 'RFC 9116'], ['2606', 'RFC 2606, reserved example domains'],
  ['2.5.5', 'RFC 9116 §2.5.5, Expires'], ['2.5.2', 'RFC 9116 §2.5.2, Canonical'],
  ['3', 'RFC 9116 §3, well-known location'],
  // Prior work, each tied to the citation in the article body.
  ['0.7', 'URIports 2024: adoption in top 1M'],
  ['19', 'URIports 2024: RFC-compliant share'],
  ['46', 'URIports 2024: missing Expires'],
  ['18', 'URIports 2024: already expired'],
  ['13', 'URIports 2025: already expired'],
  ['1.78', 'iotdef 2026: Expires adoption, before'],
  ['88.61', 'iotdef 2026: Expires adoption, after'],
  ['7.3', 'iotdef 2026: already expired'],
  ['240', 'iotdef 2026: domains surveyed, millions'],
  ['9.9', 'BSI/CRA: publish a file'],
  ['7.0', 'BSI/CRA: conforming'],
  ['1.8', 'BSI/CRA: headline percentage in the cited URL'],
  ['63.5', 'quoted from prior work: "valid" contact emails'],
  ['3609234', 'DOI of security.txt Revisited'],
  ['1145', 'DOI prefix'],
  ['2023', 'year, Digital Threats'], ['2024', 'year'], ['2025', 'year'],
  ['2026', 'year'], ['2017', 'year, USENIX Security'], ['27', 'date of writing'],
  ['2024-01-01', "twitter/x.com's published Expires value, verifiable by anyone"],
  ['06', 'hour in that same timestamp'], ['00', 'minutes/seconds in that same timestamp'],
  ['000', 'milliseconds in that same timestamp'],
  // HTTP status codes, named as part of the argument about what each one means.
  ['200', 'HTTP status'], ['403', 'HTTP status'], ['404', 'HTTP status'], ['410', 'HTTP status'],
  // Rank-bucket boundaries. These are the shape of the analysis, not results from it: they are
  // chosen before the scan and would be the same numbers if every fetch had failed.
  ['1000', 'rank bucket boundary'], ['100000', 'rank bucket boundary'],
  ['95', 'confidence level of the Wilson interval'],
  // Exit codes of the tool the article ships.
  ['0', 'stxtcheck exit code'], ['1', 'stxtcheck exit code'], ['2', 'stxtcheck exit code'],
  ['4', 'stxtcheck exit code'],
  // Counts stated about my own method rather than measured by the analyzer.
  ['62', 'sample-stage bug: sites misreported by the MX-for-portals defect'],
  ['3000', 'size of the pilot sample'], ['3', 'pilot sample, thousand'],
  ['23', 'pilot: no-working-contact before the 403 fix'],
  ['9', 'pilot: no-working-contact after it'],
  ['60', 'the resulting reduction, percent'],
  ['200', 'scan size, thousand'], ['1000000', 'top 1M, as words in prose'],
  ['1', 'ordinary prose number'], ['10', 'the ten-or-more concentration threshold'],
  ['20', 'top-20 concentration cutoff'], ['5', 'top-5 concentration cutoff'],
  ['8', 'months, in the staleness sentence'],
]);

/** Every numeric value anywhere in the analysis, in each shape it might be written as prose. */
function analysisNumbers(obj, out = new Set()) {
  const add = (n) => {
    if (typeof n !== 'number' || !isFinite(n)) return;
    out.add(String(n));
    out.add(n.toFixed(0)); out.add(n.toFixed(1)); out.add(n.toFixed(2));
    // A count is often written with thousands separators; a rate is often rounded down a digit.
    out.add(Math.round(n).toLocaleString('en-US'));
    out.add(String(Math.round(n)));
  };
  const walk = (o) => {
    if (o === null || o === undefined) return;
    if (typeof o === 'number') return add(o);
    if (Array.isArray(o)) return o.forEach(walk);
    if (typeof o === 'object') for (const v of Object.values(o)) walk(v);
  };
  walk(obj);
  return out;
}

function main() {
  const [draftPath, analysisPath] = process.argv.slice(2);
  if (!draftPath || !analysisPath) {
    console.error('usage: node draftcheck.js <draft.md> <analysis.json>');
    process.exit(2);
  }
  const text = fs.readFileSync(draftPath, 'utf8');
  const lines = text.split('\n');
  const nums = analysisNumbers(JSON.parse(fs.readFileSync(analysisPath, 'utf8')));

  let unfilled = 0, unsourced = 0;
  for (let i = 0; i < lines.length; i++) {
    for (const m of lines[i].matchAll(/⟨[^⟩]*⟩/g)) {
      console.log(`UNFILLED  ${draftPath}:${i + 1}  ${m[0].slice(0, 60)}${m[0].length > 60 ? '…' : ''}`);
      unfilled++;
    }
  }

  // Skip fenced code blocks and link targets: a URL's digits and a shell example's numbers are
  // not claims about the data, and flagging them is the kind of noise that gets a check ignored.
  let inFence = false;
  for (let i = 0; i < lines.length; i++) {
    if (/^```/.test(lines[i])) { inFence = !inFence; continue; }
    if (inFence) continue;
    const prose = lines[i]
      .replace(/\]\([^)]*\)/g, ']()')          // link targets
      .replace(/`[^`]*`/g, '``')               // inline code
      .replace(/⟨[^⟩]*⟩/g, '');                // placeholders, already reported above
    for (const m of prose.matchAll(/\d[\d,.]*/g)) {
      const raw = m[0].replace(/[.,]$/, '');
      const bare = raw.replace(/,/g, '');
      if (nums.has(bare) || nums.has(raw) || EXTERNAL.has(bare) || EXTERNAL.has(raw)) continue;
      console.log(`UNSOURCED ${draftPath}:${i + 1}  ${raw}   in: ${prose.trim().slice(0, 90)}`);
      unsourced++;
    }
  }

  const bad = unfilled + unsourced;
  console.log(bad
    ? `\nNOT PUBLISHABLE — ${unfilled} placeholder(s), ${unsourced} unsourced number(s)`
    : `\nevery number in the draft is in the analysis or an accounted-for external source`);
  process.exit(bad ? 1 : 0);
}

main();
