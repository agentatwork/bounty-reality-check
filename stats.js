'use strict';
/**
 * stats.js — the interval arithmetic the survey's central claim rests on.
 *
 * Split out of analyze_securitytxt.js so it can be tested directly. It was inline, which meant
 * the only way to exercise it was to run a whole analysis and read a percentage off the end —
 * and a confidence interval is exactly the thing that looks plausible while being wrong, because
 * nobody checks a number that already agrees with the story.
 *
 * WHY WILSON AND NOT THE NORMAL APPROXIMATION. The rates here are small counts over uneven
 * denominators: "3 of 82 contacts in this expiry state were unreachable". The textbook
 * p ± z·√(p(1-p)/n) is badly behaved in exactly that regime — it is symmetric around p̂, so at
 * p̂ = 0 it produces the zero-width interval [0, 0], which asserts certainty from having seen
 * nothing, and near the boundary it happily returns a negative lower bound. The Wilson score
 * interval is derived by inverting the score test instead, so it stays inside [0, 1] and has
 * width even when the numerator is zero.
 *
 * That difference decides an actual sentence in the writeup. On the pilot slice one expiry state
 * had 0 unreachable contacts out of 24. The normal approximation says 0.00%–0.00% and the
 * comparison against another state at 3.66% "separates" — a clean finding. Wilson says
 * 0.00%–14.87%, which overlaps everything, and the honest sentence is that Expires does not
 * predict whether the contact works.
 */

/**
 * Wilson score interval for a binomial proportion, returned as [lo, hi] in 0..1.
 * z = 1.96 is the two-sided 95% level.
 */
function wilson(k, n, z = 1.96) {
  if (!n) return [0, 0];
  const p = k / n, z2 = z * z;
  const denom = 1 + z2 / n;
  const centre = (p + z2 / (2 * n)) / denom;
  const half = (z * Math.sqrt(p * (1 - p) / n + z2 / (4 * n * n))) / denom;
  return [Math.max(0, centre - half), Math.min(1, centre + half)];
}

/**
 * Does any pair of these rates have non-overlapping 95% intervals?
 *
 * Takes the rate rows as published — `ci95_lo` and `ci95_hi` in percent, already rounded to two
 * decimals — because that is what a reader can check, and a verdict computed at a precision
 * nobody can see is not reproducible.
 *
 * Strictly greater, not greater-or-equal: intervals that touch exactly at the published precision
 * count as NOT separated. That is the conservative direction, and it is the only part of this
 * function a test can distinguish, so it is spelled out rather than left to a comparison operator
 * nobody reads twice.
 *
 * The comparison runs over ordered pairs, so `a.lo > b.hi` and `a.hi < b.lo` give the same answer
 * — for any pair separating one way there is a reversed pair separating the other. Flipping it is
 * an equivalent mutation, verified rather than assumed. What is NOT interchangeable is the strict
 * comparison, which is why it has its own fixture.
 */
function separates(rates) {
  const rs = Object.values(rates);
  return rs.some((a) => rs.some((b) => a.ci95_lo > b.ci95_hi));
}

module.exports = { wilson, separates };
