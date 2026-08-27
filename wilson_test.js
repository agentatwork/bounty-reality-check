#!/usr/bin/env node
/**
 * wilson_test.js — the interval, and the verdict the article's central claim is read off.
 *
 *   node wilson_test.js
 *
 * The expiry-vs-reachability cross-tab is the one correlation in this survey that nobody has
 * published before, which makes it the number I am least able to sanity-check against the world
 * and most inclined to believe. Everything about whether it gets written as a finding comes down
 * to two confidence intervals and a boolean.
 *
 * The interval is checked against closed forms derived independently of the implementation rather
 * than against values copied out of it. At k = 0 the Wilson upper bound collapses to
 *
 *      hi = z² / (n + z²)
 *
 * and at k = n the lower bound collapses to
 *
 *      lo = n / (n + z²)
 *
 * — both by hand from the definition, the square-root term vanishing in each case. A test that
 * compares against numbers printed by the code under test proves only that it is deterministic.
 *
 * The k = 0 form is also the reason Wilson is here at all. The normal approximation
 * p ± z·√(p(1-p)/n) returns [0, 0] when nothing was observed: zero events out of twenty-two
 * becomes a claim of certainty, and certainty separates from every other interval, so the
 * comparison the writeup depends on would report a finding out of an empty cell. On the pilot
 * slice that cell was real — 0 unreachable out of 22 — and the honest interval is 0.00%–14.87%,
 * which overlaps everything.
 *
 * The second half runs the analyzer end to end on two fixtures, one built to overlap and one
 * built to separate, because the verdict is not the interval — the article says "a real
 * difference" or "no supportable difference" on the strength of that boolean alone.
 *
 * Three mutations were injected into the verdict and the interval. Two die here. One survives and
 * is EQUIVALENT: flipping `a.ci95_lo > b.ci95_hi` to `a.ci95_hi < b.ci95_lo` cannot change the
 * answer, because the comparison runs over ordered pairs — for every pair that separates one way
 * there is a reversed pair separating the other, so the two forms agree on every possible input.
 * I expected a one-directional fixture to tell them apart and it does not; that was worth
 * finding out by running it rather than by believing the header I had already written.
 *
 * The one that is NOT equivalent is `>` versus `>=`, and no fixture built from real data can
 * reach it, since two rounded percentages landing on exactly the same hundredth by accident is
 * vanishingly unlikely. It gets a constructed case instead.
 *
 * No network: the DNS answers are seeded into the analyzer's lookup cache, which also means this
 * test fails if the cache format ever changes underneath it — the resume path and the fixture
 * cannot drift apart silently.
 */
'use strict';
const fs = require('fs');
const { execFileSync } = require('child_process');
const { wilson, separates } = require('./stats');

let bad = 0;
const check = (name, ok, detail) => {
  if (!ok) bad++;
  console.log(`${ok ? 'ok  ' : 'FAIL'} ${name.padEnd(46)} ${detail}`);
};
const near = (a, b, eps = 1e-12) => Math.abs(a - b) < eps;

// ---- the interval itself, against hand-derived closed forms --------------------------------
const Z = 1.96, Z2 = Z * Z;

// The closed forms are exact in real arithmetic; the implementation works in doubles, where the
// two halves of `centre - half` cancel to within one ulp rather than to nothing. n=22 lands on
// 1.4e-17 and n=100 on 1 - 1.1e-16. Both were written here as exact equalities first and both
// failed, which is worth recording: the assertion was wrong, not the code. What the survey
// actually publishes is `+(100 * lo).toFixed(2)`, so the standard to hold is that the residue
// cannot reach two decimal places of a percent — 1e-15 is thirteen orders of magnitude clear of
// it — and that is asserted directly rather than left as an argument.
for (const n of [1, 22, 100, 5000]) {
  const [lo, hi] = wilson(0, n);
  check(`k=0, n=${n}: lo is 0 to within float noise`, near(lo, 0, 1e-15), `lo=${lo}`);
  check(`k=0, n=${n}: lo publishes as 0.00%`, +(100 * lo).toFixed(2) === 0, `${(100 * lo).toFixed(2)}%`);
  check(`k=0, n=${n}: hi = z²/(n+z²)`, near(hi, Z2 / (n + Z2)), `${hi.toFixed(6)} vs ${(Z2 / (n + Z2)).toFixed(6)}`);
}
for (const n of [1, 22, 100, 5000]) {
  const [lo, hi] = wilson(n, n);
  check(`k=n, n=${n}: hi is 1 to within float noise`, near(hi, 1, 1e-15), `hi=${hi}`);
  check(`k=n, n=${n}: hi publishes as 100.00%`, +(100 * hi).toFixed(2) === 100, `${(100 * hi).toFixed(2)}%`);
  check(`k=n, n=${n}: lo = n/(n+z²)`, near(lo, n / (n + Z2)), `${lo.toFixed(6)} vs ${(n / (n + Z2)).toFixed(6)}`);
}

// The pilot value quoted in the draft, so the sentence and the code cannot drift apart.
check('0 of 22 gives the pilot interval 0.00–14.87%',
  +(100 * wilson(0, 22)[1]).toFixed(2) === 14.87, `hi=${(100 * wilson(0, 22)[1]).toFixed(2)}%`);

// Wilson is symmetric under relabelling success and failure. This catches a sign error or a
// dropped term in a way the closed forms above cannot, because it constrains the interior.
for (const [k, n] of [[1, 20], [4, 20], [3, 82], [37, 100], [499, 1000]]) {
  const a = wilson(k, n), b = wilson(n - k, n);
  check(`symmetry ${k}/${n}: lo(k) = 1 - hi(n-k)`, near(a[0], 1 - b[1]) && near(a[1], 1 - b[0]),
    `[${a[0].toFixed(6)}, ${a[1].toFixed(6)}]`);
}

for (const [k, n] of [[1, 20], [3, 82], [37, 100]]) {
  const [lo, hi] = wilson(k, n), p = k / n;
  check(`${k}/${n}: interval contains the point estimate`, lo < p && p < hi,
    `${(100 * lo).toFixed(2)} < ${(100 * p).toFixed(2)} < ${(100 * hi).toFixed(2)}`);
}

const w = (k, n) => { const [lo, hi] = wilson(k, n); return hi - lo; };
check('width shrinks as n grows at fixed p', w(1, 10) > w(10, 100) && w(10, 100) > w(100, 1000),
  `${w(1, 10).toFixed(4)} > ${w(10, 100).toFixed(4)} > ${w(100, 1000).toFixed(4)}`);
check('an unobserved event still has width', w(0, 22) > 0.14, `width=${w(0, 22).toFixed(4)}`);
check('a wider z gives a wider interval',
  wilson(3, 82, 2.58)[1] > wilson(3, 82, 1.96)[1], '99% vs 95%');
check('n=0 returns a degenerate interval, not NaN',
  JSON.stringify(wilson(0, 0)) === '[0,0]', JSON.stringify(wilson(0, 0)));

// The [0,1] clamps are not decoration. Without them the cancellation at k=0 lands *below* zero
// for 68,338 of the first 300,000 values of n — including n=5, 10 and 20, the small cells this
// survey is full of — and the printed interval reads "-0.00". Same at the top end for k=n.
// Removing both clamps was injected as a mutation and survived until these lines existed.
for (const n of [5, 10, 20, 23]) {
  check(`k=0, n=${n}: clamped to >= 0`, wilson(0, n)[0] >= 0, `lo=${wilson(0, n)[0]}`);
  check(`k=n, n=${n}: clamped to <= 1`, wilson(n, n)[1] <= 1, `hi=${wilson(n, n)[1]}`);
}

// ---- the verdict, as a function --------------------------------------------------------------
// Whether two intervals that touch at the published precision count as separated is a real
// choice, not a typo, and it is invisible in any fixture built from actual data because exact
// equality at two decimals essentially never happens by accident. Constructed directly.
check('touching intervals do NOT separate',
  separates({ a: { ci95_lo: 0, ci95_hi: 0.95 }, b: { ci95_lo: 0.95, ci95_hi: 5 } }) === false,
  'hi = lo = 0.95');
check('a gap of one hundredth of a point DOES separate',
  separates({ a: { ci95_lo: 0, ci95_hi: 0.95 }, b: { ci95_lo: 0.96, ci95_hi: 5 } }) === true,
  '0.96 > 0.95');
check('one state cannot separate from itself',
  separates({ a: { ci95_lo: 1, ci95_hi: 5 } }) === false, 'single row');
check('no states, no claim', separates({}) === false, 'empty');

// ---- the verdict, end to end ----------------------------------------------------------------
// Two contact domains, both answered from the seeded cache: one accepts mail, one is registered
// but has no way to receive any.
const DNS = [
  { t: 'dns', k: 'live.example', v: { state: 'EXISTS', hasMx: true, nullMx: false, hasA: true, mx: ['mx.live.example'] } },
  { t: 'dns', k: 'nomail.example', v: { state: 'EXISTS', hasMx: false, nullMx: false, hasA: false, mx: [] } },
];

/** One site with a parseable file: `expiredFile` picks the expiry state, `dead` the reachability. */
const site = (i, expiredFile, dead) => JSON.stringify({
  domain: `s${i}.example`, ok: true, status: 200, is_security_txt: true,
  contact: [`mailto:security@${dead ? 'nomail' : 'live'}.example`],
  expires: expiredFile ? '2020-01-01T00:00:00Z' : '2030-01-01T00:00:00Z',
  policy: [], canonical: [], field_names: ['contact', 'expires'], bytes: 60,
});

function verdictFor(label, validTotal, validDead, expiredTotal, expiredDead) {
  const IN = `/tmp/wilson_${label}.jsonl`;
  const OUT = `/tmp/wilson_${label}.json`;
  const rows = [];
  let i = 0;
  for (let j = 0; j < validTotal; j++) rows.push(site(i++, false, j < validDead));
  for (let j = 0; j < expiredTotal; j++) rows.push(site(i++, true, j < expiredDead));
  fs.writeFileSync(IN, rows.join('\n') + '\n');
  fs.writeFileSync(`${IN}.lookups.jsonl`, DNS.map((d) => JSON.stringify(d)).join('\n') + '\n');
  execFileSync('node', [`${__dirname}/analyze_securitytxt.js`, IN, OUT, '2', '/tmp/wilson_norank.csv'],
    { stdio: ['ignore', 'ignore', 'inherit'] });
  return JSON.parse(fs.readFileSync(OUT, 'utf8'));
}

// Overlapping: 1 of 20 against 4 of 20. The point estimates differ fourfold and look like a
// finding; 4.9%–23.6% against 20.0%–43.7% is not one.
const a = verdictFor('overlap', 20, 1, 20, 4);
check('overlap fixture: cells are as constructed',
  a.expiry_x_reach_rates.valid.n === 20 && a.expiry_x_reach_rates.valid.unreachable === 1 &&
  a.expiry_x_reach_rates.expired.n === 20 && a.expiry_x_reach_rates.expired.unreachable === 4,
  `valid ${a.expiry_x_reach_rates.valid.pct}%  expired ${a.expiry_x_reach_rates.expired.pct}%`);
check('overlap fixture: separates = false', a.expiry_x_reach_separates === false,
  `[${a.expiry_x_reach_rates.valid.ci95_lo}, ${a.expiry_x_reach_rates.valid.ci95_hi}] vs ` +
  `[${a.expiry_x_reach_rates.expired.ci95_lo}, ${a.expiry_x_reach_rates.expired.ci95_hi}]`);

// Separating, and deliberately in one direction only: `valid` is the LOW cell, so the verdict is
// reached by finding a pair with expired.lo > valid.hi. Reversing the comparison misses it.
const b = verdictFor('separate', 400, 0, 400, 200);
check('separating fixture: cells are as constructed',
  b.expiry_x_reach_rates.valid.n === 400 && b.expiry_x_reach_rates.valid.unreachable === 0 &&
  b.expiry_x_reach_rates.expired.n === 400 && b.expiry_x_reach_rates.expired.unreachable === 200,
  `valid ${b.expiry_x_reach_rates.valid.pct}%  expired ${b.expiry_x_reach_rates.expired.pct}%`);
check('separating fixture: separates = true', b.expiry_x_reach_separates === true,
  `[${b.expiry_x_reach_rates.valid.ci95_lo}, ${b.expiry_x_reach_rates.valid.ci95_hi}] vs ` +
  `[${b.expiry_x_reach_rates.expired.ci95_lo}, ${b.expiry_x_reach_rates.expired.ci95_hi}]`);

console.log(bad ? `\nINTERVALS WRONG — ${bad} failure(s)` : '\nintervals match hand-derived forms, and the verdict goes both ways');
process.exit(bad ? 1 : 0);
