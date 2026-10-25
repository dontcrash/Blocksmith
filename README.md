# Blocksmith

[![Update lists](https://github.com/dontcrash/Blocksmith/actions/workflows/main.yml/badge.svg)](https://github.com/dontcrash/Blocksmith/actions/workflows/main.yml)

Compiles 45 third-party DNS blocklist feeds into clean, flat,
**`domain.com`-per-line** blocklists in three sizes. No adblock syntax, no
hosts headers, no comments, no URLs, no IPs — just domains, ready to import
into any DNS filter or firewall.

A GitHub Action rebuilds and pushes the lists twice a day. Point your resolver
at the raw files and forget about it.

## The lists

Pick **ONE** tier per device — they are cumulative in coverage
(small ⊆ medium ⊆ large).

| File | Contents | Entries |
|---|---|---|
| [`lists/small.txt`](lists/small.txt) | The heavy hitters: most popular, reputable, near-zero breakage | ~318k |
| [`lists/medium.txt`](lists/medium.txt) | small + wider trusted security & device-telemetry coverage | ~430k |
| [`lists/large.txt`](lists/large.txt) | **All** of it: adds the threat-intel mega-feeds and aggressive tiers. | ~2.7M |
| [`lists/tlds.txt`](lists/tlds.txt) | Whole-TLD blocks (`.top`, `.xyz` …) from HaGeZi's abused-TLD list | 283 |
| [`lists/adguard-small.txt`](lists/adguard-small.txt) | Raw originals concatenated, format preserved verbatim | ~10.6 MB |
| [`lists/adguard-medium.txt`](lists/adguard-medium.txt) | Raw originals concatenated (small + medium) | ~18 MB |
| [`lists/adguard-large.txt`](lists/adguard-large.txt) | Raw originals concatenated, everything | ~81 MB |
| [`lists/adguard-tlds.txt`](lists/adguard-tlds.txt) | TLD sources verbatim (`||*.tld^` rules) | 283 rules |

Pick **one pipeline**: plain-domain tiers (`small/medium/large`) for
firewalls and resolvers that need `domain.com` per line, or the `adguard-*`
files for AdGuard Home / Pi-hole / uBlock — the latter keep every published
rule, comment and `$`-exception exactly as upstream wrote it, including scoped
rules a flat list must refuse.

`tlds.txt` is separate because a flat domain list cannot express
"block every .xyz domain". Feed it to whatever accepts TLD/wildcard rules
(e.g. AdGuard wildcard syntax: `*.top`).

`build-summary.txt` records every source, its entry count, and any warnings
from the last successful build — that is the honest answer to "what did I
just import?".

## Source curation

Tiers are set per-source in [`source.txt`](source.txt) (`url|tier|format`).
Everything was verified live before shipping; each line carries its entry
count and a reputation note. The noise hunt that shaped the tiers:

**Reputable core (small):** HaGeZi Normal, OISD Small, AdGuard DNS filter,
Peter Lowe, URLHaus (abuse.ch), PhishTank/OpenPhish, Dandelion Sprout
Anti-Malware, Stalkerware Indicators.

**Trusted-but-wider (medium):** HaGeZi's native-telemetry/fake/popupads
files, 1Hosts Lite, Steven Black, Dan Pollock, AdAway, WindowsSpyBlocker,
NoCoin, uBlock badware, ShadowWhisperer.

**Aggressive / high-volume / opinionated (large only):** HaGeZi TIF full
(2.1M threat-intel) and Ultimate, OISD Big, 1Hosts Xtra, Phishing Army,
SNAFU (famously breakage-prone), DoH/VPN-bypass and badware-hosters
(over-blocking by design), No Google, dating.

**Removed as noise** (not in the build, listed at the bottom of `source.txt`):

- `dl.threat-list.com` — dead host (NXDOMAIN)
- `filter_45` — HaGeZi *Allowlist* Referral: an allowlist in blocklist clothing
- `filter_59` — AdGuard Popup Hosts: 100% `$popup`-scoped rules → 0 DNS-expressible domains
- `filter_44` — duplicate of HaGeZi's own TIF URL (both exactly 2,117,716 entries; publisher URL wins)
- `filter_48`/`filter_51` — HaGeZi Pro/Pro++ are strict subsets of Ultimate, which is included
- `filter_63` — duplicate of `native.winoffice.txt`

## Usage

```bash
python3 -m unittest test_blocklist_core.py   # 68 offline tests, no network
python3 update.py                    # fetch, parse, validate, rebuild lists/
python3 update.py --dry-run        # build in memory, write nothing
python3 update.py --offline        # reuse .cache downloads
python3 validate_output.py         # audit the written lists
```

Python 3.10+, stdlib only — no pip installs needed.

Adding a source: append `https://…/list.txt|tier` (format auto-detected;
add `|adblock|hosts|domains|tld` to override) to `source.txt` and commit.

## How it stays clean

Input can be any mix of adblock (`||host^$mod`), hosts (`0.0.0.0 host`) or
plain-domain syntax. Every rule is converted or refused, never guessed:

- Rules narrowed by a modifier (`$script`, `$domain=`, `$popup`, `denyallow=`…)
  are **refused** — flattening them would over-block.
- Publisher exceptions (`@@`) unblock matching entries.
- A `PROTECTED` set (captive portals, Apple/Google/Microsoft sign-in) can
  never be blocked, no matter what a feed claims.
- Public suffixes (`blogspot.com`, `co.uk`) are refused via the
  Public Suffix List; `.onion` is dropped (unresolvable).
- Subdomains covered by a blocked parent in the same file are removed
  (saves import slots, zero coverage lost).
- The build **fails loudly** rather than publishing a gutted list when too
  many sources are unreachable, and splits `large.txt` into `-N` parts to
  stay under GitHub's 100 MB file limit.

## Automation

[`.github/workflows/main.yml`](.github/workflows/main.yml) runs offline tests,
then `update.py`, then `validate_output.py` at 00:00 and 12:00 UTC daily (plus
manual dispatch). A successful run commits `lists/*` and `build-summary.txt`
and pushes to `main`. If a build would publish a partial or invalid list it
fails and leaves the last good lists untouched.

Because git is content-addressed, a list that rebuilds byte-for-byte identical
to the last run uploads nothing new — quiet days add no storage weight. If you
want to slim `large`, trim `source.txt` and rebuild rather than editing
`lists/` by hand.

## Credits

Lists aggregate third-party feeds (HaGeZi, OISD, AdGuard, abuse.ch,
Dandelion Sprout, 1Hosts, Perflyst, curbengh, StevenBlack, and others named
in `source.txt`); upstream contents remain under their respective licenses.
