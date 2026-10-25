# AGENTS.md

Blocksmith: compiles third-party DNS blocklists from `source.txt` into flat
`domain.com`-per-line tiers + verbatim AdGuard concatenations. Stdlib-only
Python 3.10+ (CI pins 3.14). No pip installs, no build step.

## Commands (run in this order when verifying)

```bash
python3 -m unittest test_blocklist_core.py   # 68 offline tests, ~5ms, hermetic
python3 update.py --dry-run                  # or --offline to reuse .cache
python3 update.py                            # full network build (~80 MB fetched)
python3 validate_output.py                   # audits lists/
```

- `update.py` is the only entrypoint; CI runs exactly: tests → `update.py` →
  `validate_output.py` → commit `lists/* build-summary.txt` → push.
- To test one source's parsing without network: `update.py --offline`
  reuses `.cache/` (keyed by sanitized URL; delete a file there to refetch).

## Architecture

- `blocklist_core.py` = parser/validator system of record; `update.py` =
  fetch/tier/write. Keep rule-syntax logic in core, orchestration in update.
- `source.txt` lines: `url|tier|format` (tier = minimum tier: small ⊂ medium
  ⊂ large; format auto|adblock|hosts|domains|tld). Inline `#` comments OK.
- Two parallel pipelines: plain tiers (`small/medium/large/tlds.txt`) are
  validated + parent-reduced; `adguard-*` are upstream bytes concatenated
  verbatim with `! Source:` banners — never "clean" or sort those.

## Do not "fix"

- Modifier refusal (`$script`, `$domain=`, `$popup`…): flattening over-blocks.
  Only `MODIFIER_ALLOW` modifiers may be dropped. Conditional `@@` keeps the
  block by design.
- `PROTECTED` set and public-suffix/`.onion` refusals are safety rails.
- Build fails loudly on gutted/partial results; never soften those guards to
  make a run green.
- `MAX_BYTES_PER_OUTPUT_FILE = 95_000_000` — GitHub hard-blocks 100 MB;
  splits are order-preserving, keep them that way.
- Test suite uses a synthetic PSL fixture — new test domains must use TLDs
  present in `PSL_TEXT` or you get a confusing "unknown TLD".
