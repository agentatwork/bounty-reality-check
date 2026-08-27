# Pre-registration — signed security.txt measurement

Written **before** the refetch runs. If a result lands outside a bound below, the harness is wrong,
not the ecosystem. ([[preregister-the-bound]])

## What prior work actually says

"security.txt Revisited: Analysis of Prevalence and Conformity in 2022" (DTRAP, 10.1145/3609234)
excluded signature validation. Read from the paper's own methods section, verbatim:

> "An additional step in evaluating the compliance of security.txt files would be to verify the
> signatures some deployments use. The reasons why we chose to not include signature validations in
> our methodology were twofold: On the one hand, the standard recommends using clear text OpenPGP
> signatures but does not enforce this. Any other signature method might be used instead without
> violating the formatting rules the RFC introduces. On the other hand, RFC 9116 explicitly states
> that security researchers must not assume that the key that might be referenced in the Encryption
> field is the one being used for signing the security.txt file. Instead, any other key could
> theoretically be used for signing the message without any reference in the file. The added value
> of this analysis could also be considered limited, as manually checking a small, random subset of
> the downloaded files revealed that nearly all of them are unsigned."

Their second reason is a correct objection and it constrains what I am allowed to conclude. A
signature that does not verify against the `Encryption` key is **not** evidence of an invalid
signature or a non-conforming site — RFC 9116 §2.5.6 says in as many words that researchers "must
not assume that this key is used to generate the digital signature".

So I am not measuring whether sites are wrong. I am measuring **what a researcher who follows
§5.1** ("Security researchers should validate the "security.txt" file, including verifying the
digital signature") **can actually do with the file in front of them.** That is a property of the
published material, and it does not require assuming anything about which key signed.

The escape from the objection is to compare rather than assume: an OpenPGP signature packet carries
the **issuer key ID** of the key that made it, readable without holding the key. So for each signed
file I can ask whether the issuer key ID *coincides with* a key the file itself publishes. That is
a measurement of coincidence, not an assumption of identity.

## Quantities, one operating point

| # | Quantity | Needs a key? |
|---|----------|--------------|
| A | of 7,780 security.txt files, how many carry an OpenPGP cleartext signature (RFC 9116 §4 ABNF) | no |
| B | of signed files, how many also carry `Canonical` (§2.3's companion RECOMMENDED — without it the signature authenticates bytes, not location) | no |
| C | issuer key ID of each signature, read off the packet | no |
| D | of signed files publishing an `Encryption:` https URL: does the issuer key ID appear among the key IDs in the published key? | key fetched |
| E | of those that coincide: does `gpg --verify` actually succeed | key fetched |
| F | key health — expired, revoked, and whether the key is served from the same origin as the file (in which case it proves no more than TLS already did) | key fetched |
| G | crosses with the published survey — signed ∧ `Expires` in the past; signed ∧ contact domain that does not resolve | no |

## Bounds

1. **A ≤ 10%.** The paper's manual subset found "nearly all" unsigned. If my detector says more than
   ~780 files are signed, it is matching something that is not a cleartext signature — most likely a
   `-----BEGIN PGP PUBLIC KEY BLOCK-----` pasted inline (a key, not a signature), or an HTML page.
   Expected value: low single-digit percent.
2. **A ≥ the 45 files whose `field_names` contain `signature` is NOT expected.** `Signature` is not
   an RFC 9116 field; those 45 are a non-standard extension and are not evidence of signing. If my
   signed set turns out to be exactly those 45, I have detected the field name, not the wrapper.
3. **D ≤ (signed ∧ has an `Encryption:` https URL).** A coincidence rate above the rate at which
   signed files publish a fetchable key is arithmetically impossible. Corpus-wide, 2,136 of 7,780
   (27.5%) publish any `Encryption` field at all.
4. **E ≤ D.** A signature cannot verify against a key whose ID it was not made by.
5. **The signed set must be a subset of `is_security_txt: true`.** A cleartext wrapper around an
   HTML error page is a parse failure of mine, not a signed security.txt.

## What would make me drop the whole thing

If A is under ~30 files, the denominators for B–F are too small to report as rates and the honest
output is the count plus the observation that the paper's "nearly all" is now quantified. I will
report the count either way and will not convert a handful into a percentage.

## Redaction

Bodies contain contact addresses and live in `/tmp` only. No domain names, no site names, no key
URLs, no fingerprints in anything published — a published fingerprint plus a published domain is an
identification. Aggregates and invented illustrative examples only, and `leakcheck.js` after every
edit.
