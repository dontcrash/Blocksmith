#!/usr/bin/env python3
"""Blocksmith - compile a tiered DNS blocklist set from third-party feeds.

Output (one directory, overwritten in place each run, plain domain per line):

    lists/small.txt      the most popular, reputable, low-breakage feeds
    lists/medium.txt     small + the wider trusted set
    lists/large.txt      everything healthy in source.txt
    lists/tlds.txt       whole-TLD blocks (cannot be expressed as domains)
    build-summary.txt    per-source stats for the last successful build

Lists are cumulative: small is a subset of medium, medium is a subset of
large. Pick ONE to import per device.

Sources live in source.txt, one per line:

    https://example.com/list.txt          -> tier "large", format auto-detected
    https://example.com/list.txt|medium   -> also lands in medium + small
    https://example.com/list.txt|large|tld  -> whole-TLD list, passthrough

Tiers are minimum membership: 'small' ships in all three lists, 'medium' in
medium and large, 'large' only in large. Format is 'adblock', 'hosts',
'domains' or 'tld' (default auto-detected from the file itself).

Usage:
    python3 update.py
    python3 update.py --offline            # reuse .cache downloads
    python3 update.py --dry-run          # build in memory, write nothing
"""

import argparse
import hashlib
import os
import re
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

from blocklist_core import WARNINGS, parse_source, reduce_parents, warn, PublicSuffixList

TIER_ORDER = ('small', 'medium', 'large')
FORMATS = ('auto', 'adblock', 'hosts', 'domains', 'tld')
USER_AGENT = 'Blocksmith/1.0 (+https://github.com/dontcrash/Blocksmith)'
MAX_BYTES_PER_SOURCE = 256 * 1024 * 1024
MAX_BYTES_PER_OUTPUT_FILE = 95_000_000  # GitHub blocks files over 100 MB
PSL_URLS = [
    'https://publicsuffix.org/list/public_suffix_list.dat',
    'https://raw.githubusercontent.com/publicsuffix/list/master/public_suffix_list.dat',
]

def log(message):
    print(message, file=sys.stderr, flush=True)


class Source:
    __slots__ = ('url', 'tier', 'fmt', 'label')

    def __init__(self, url, tier='large', fmt='auto'):
        self.url = url
        self.tier = tier
        self.fmt = fmt
        self.label = url.split('://', 1)[-1][:52]


# --------------------------------------------------------------------------
# Config
# --------------------------------------------------------------------------

def read_sources(path):
    sources = []

    for line in Path(path).read_text(encoding='utf-8-sig').splitlines():
        line = line.strip()

        if not line or line.startswith('#'):
            continue

        line = line.split('#', 1)[0].strip()

        if not line:
            continue

        parts = [part.strip() for part in line.split('|')]
        url = parts[0]

        if not url.startswith(('http://', 'https://')):
            raise ValueError(f'{path}: not a URL: {url!r}')

        tier = parts[1] if len(parts) > 1 and parts[1] else 'large'
        fmt = parts[2] if len(parts) > 2 and parts[2] else 'auto'

        if tier not in TIER_ORDER:
            raise ValueError(f'{url}: tier must be one of {TIER_ORDER}, got {tier!r}')

        if fmt not in FORMATS:
            raise ValueError(f'{url}: format must be one of {FORMATS}, got {fmt!r}')

        sources.append(Source(url, tier, fmt))

    if not sources:
        raise ValueError(f'{path}: no sources configured')

    return sources


# --------------------------------------------------------------------------
# Downloading
# --------------------------------------------------------------------------

def cache_name(url):
    return re.sub(r'[^A-Za-z0-9]+', '_', url.split('://', 1)[-1])[:120] + '.txt'


def http_get(url, cache_dir=None, cache_only=False, retries=3):
    cached = Path(cache_dir) / cache_name(url) if cache_dir else None

    if cached is not None and cached.exists() and cached.stat().st_size > 0 and cache_only:
        return cached.read_bytes()

    if cache_only:
        raise FileNotFoundError(f'no cached copy of {url}')

    last_error = None

    for attempt in range(1, retries + 1):
        try:
            request = urllib.request.Request(url, headers={'User-Agent': USER_AGENT})

            with urllib.request.urlopen(request, timeout=180) as response:
                if response.status != 200:
                    raise ValueError(f'HTTP {response.status}')

                data = response.read(MAX_BYTES_PER_SOURCE + 1)

            if len(data) > MAX_BYTES_PER_SOURCE:
                raise ValueError('source exceeds size limit')

            if cached is not None:
                cached.parent.mkdir(parents=True, exist_ok=True)
                cached.write_bytes(data)

            return data
        except (OSError, urllib.error.URLError, ValueError) as error:
            last_error = error

            if attempt < retries:
                time.sleep(2 * attempt)

    raise ValueError(f'failed after {retries} attempts: {last_error}')


def load_psl(cache_dir, offline):
    cached = Path(cache_dir) / 'public_suffix_list.dat' if cache_dir else None

    if cached is not None and cached.exists() and cached.stat().st_size > 4096:
        return PublicSuffixList(cached.read_text(encoding='utf-8-sig'))

    if offline:
        raise ValueError('offline and no cached Public Suffix List')

    text = None

    for url in PSL_URLS:
        try:
            text = http_get(url).decode('utf-8-sig')

            if cached is not None:
                cached.parent.mkdir(parents=True, exist_ok=True)
                cached.write_text(text, encoding='utf-8')

            break
        except (OSError, ValueError) as error:
            warn(f'Public Suffix List {url}: {error}')

    if text is None:
        raise ValueError('no Public Suffix List available; refusing to build unvalidated lists')

    return PublicSuffixList(text)


def detect_format(raw):
    """Guess the syntax of an unmarked list from its first lines."""
    head = raw[:16384].decode('utf-8-sig', errors='replace')
    body = '\n'.join(line for line in head.splitlines() if not line.startswith(('!', '#', '[')))

    if re.search(r'^(?:0\.0\.0\.0|127\.0\.0\.1)\s', body, re.M):
        return 'hosts'

    if body.startswith('||') or '\n||' in body or '@@' in body:
        return 'adblock'

    return 'domains'


def publisher_title(raw):
    match = re.search(rb'(?im)^!\s*title:\s*(.+)$', raw[:8192])

    return match.group(1).decode('utf-8-sig', errors='replace').strip() if match else ''


# --------------------------------------------------------------------------
# Building
# --------------------------------------------------------------------------

def build(sources, psl, cache_dir, offline):
    buckets = {tier: set() for tier in TIER_ORDER}
    tlds = set()
    per_source = []
    # verbatim bodies of every source, grouped by minimum tier (for adguard-*)
    raw_parts = {tier: [] for tier in TIER_ORDER}
    raw_tlds = []

    for source in sources:
        log(f'fetching {source.url}')
        record = {'url': source.url, 'tier': source.tier, 'status': 'ok',
                 'title': '', 'format': source.fmt, 'entries': 0,
                 'lines': 0, 'invalid': 0, 'unsupported': 0}

        try:
            raw = http_get(source.url, cache_dir, cache_only=offline)
        except (OSError, ValueError) as error:
            record.update(status='failed', error=str(error))
            warn(f'source skipped: {source.url}: {error}')
            per_source.append(record)
            continue

        fmt = source.fmt if source.fmt != 'auto' else detect_format(raw)
        entries, stats = parse_source(raw, fmt, psl, name=source.label)
        record.update(title=publisher_title(raw) or source.label, format=fmt,
                      lines=stats['lines'], entries=len(entries),
                      invalid=stats['invalid_name'], unsupported=stats['unsupported_syntax'])

        if not entries and fmt != 'tld':
            record['status'] = 'empty'
            warn(f'source contributed nothing: {record["title"] or source.url} ({fmt})')

        if fmt == 'tld':
            tlds.update(entries)
            raw_tlds.append((source, raw))
        else:
            buckets[source.tier].update(entries)
            raw_parts[source.tier].append((source, raw))

        log(f'  {record["title"] or source.url}: {len(entries):,} entries ({fmt})')
        per_source.append(record)

    return buckets, tlds, per_source, raw_parts, raw_tlds


def cumulative(buckets):
    """small is a subset of medium is a subset of large."""
    tiers = {}
    accumulated = set()

    for tier in TIER_ORDER:
        accumulated = accumulated | buckets[tier]
        tiers[tier] = set(accumulated)

    return tiers


# --------------------------------------------------------------------------
# Writing
# --------------------------------------------------------------------------

def atomic_write(path, data):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=path.name + '.', suffix='.tmp', dir=path.parent)

    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())

        os.replace(temporary, path)
        os.chmod(path, 0o644)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def split_to_parts(name, lines, max_bytes):
    """Chunk sorted domains so no file crosses GitHub's 100 MB block limit.

    Cuts happen between whole lines in sorted order, so parts are stable
    between builds and a consumer can concatenate them back into one list.
    """
    parts = []
    chunk = []
    size = 0

    for line in lines:
        encoded = len(line) + 1

        if size + encoded > max_bytes and chunk:
            parts.append(chunk)
            chunk = []
            size = 0

        chunk.append(line)
        size += encoded

    if chunk:
        parts.append(chunk)

    if len(parts) == 1:
        return [(name, parts[0])]

    return [(name.replace('.txt', f'-{index}.txt'), part)
            for index, part in enumerate(parts, 1)]


def write_lists(output_dir, tiers, tlds, max_bytes):
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    report = []
    written = []

    for tier in TIER_ORDER:
        domains, removed = reduce_parents(tiers[tier])
        lines = sorted(domains)

        for name, chunk in split_to_parts(f'{tier}.txt', lines, max_bytes):
            data = ''.join(f'{domain}\n' for domain in chunk).encode('ascii')
            atomic_write(output_dir / name, data)
            written.append(name)
            report.append({'file': name, 'entries': len(chunk), 'bytes': len(data),
                          'sha256': sha256(data)[:16]})

    if tlds:
        data = ''.join(f'{tld}\n' for tld in sorted(tlds)).encode('ascii')
        atomic_write(output_dir / 'tlds.txt', data)
        written.append('tlds.txt')
        report.append({'file': 'tlds.txt', 'entries': len(tlds), 'bytes': len(data),
                       'sha256': sha256(data)[:16]})

    for path in sorted(output_dir.glob('*.txt')):
        if path.name not in written and re.fullmatch(r'(small|medium|large)(-\d+)?(-\d+-of-\d+)?\.txt|tlds\.txt', path.name):
            log(f'removed stale {path.name}')
            path.unlink()

    return report


def write_adguard(output_dir, raw_parts, raw_tlds, max_bytes):
    """Concatenate original source bodies verbatim (plus a provenance banner).

    Format is preserved exactly - adblock rules, hosts lines, exceptions and
    comments stay as published, so these files import straight into AdGuard
    Home, Pi-hole or uBlock without any conversion.
    """
    report = []
    written = []

    for tier in TIER_ORDER:
        lines = []

        for included in TIER_ORDER[:TIER_ORDER.index(tier) + 1]:
            for source, raw in raw_parts[included]:
                banner = [f'! ========================================',
                          f'! Source:  {source.url}',
                          f'! Format:  kept exactly as published',
                          f'! ========================================']
                lines.extend(banner)
                lines.extend(raw.decode('utf-8-sig', errors='replace').splitlines())
                lines.append('')

        for name, chunk in split_to_parts(f'adguard-{tier}.txt', lines, max_bytes):
            data = ('\n'.join(chunk) + '\n').encode('utf-8')
            atomic_write(output_dir / name, data)
            written.append(name)
            report.append({'file': name, 'entries': len(chunk), 'bytes': len(data),
                          'sha256': sha256(data)[:16]})

    if raw_tlds:
        lines = []

        for source, raw in raw_tlds:
            lines.extend([f'! Source: {source.url}'])
            lines.extend(raw.decode('utf-8-sig', errors='replace').splitlines())
            lines.append('')

        data = ('\n'.join(lines) + '\n').encode('utf-8')
        atomic_write(output_dir / 'adguard-tlds.txt', data)
        written.append('adguard-tlds.txt')
        report.append({'file': 'adguard-tlds.txt', 'entries': len(lines),
                       'bytes': len(data), 'sha256': sha256(data)[:16]})

    return report, written


def build_summary(tiers, report, per_source, tlds, started):
    ok = [r for r in per_source if r['status'] == 'ok']
    empty = [r for r in per_source if r['status'] == 'empty']
    failed = [r for r in per_source if r['status'] == 'failed']

    lines = [
        'Blocksmith build summary',
        f'Finished: {time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())} '
        f'in {time.monotonic() - started:.0f}s',
        f'Sources: {len(ok)} ok, {len(empty)} empty, {len(failed)} failed '
        f'of {len(per_source)} configured',
        '',
    ]

    for entry in report:
        lines.append(f'  {entry["file"]:14s} {entry["entries"]:>9,} entries  '
                     f'{entry["bytes"] / 1048576:7.1f} MB')

    lines.append(f'  whole-TLD blocks in tlds.txt: {len(tlds)} (cannot be plain domains)')
    lines += ['', 'Per-source (entries after syntax conversion and validation):']

    for record in per_source:
        flag = {'ok': ' ', 'empty': '!', 'failed': 'x'}.get(record['status'], '?')
        note = record.get('error', '')
        lines.append(f'  [{flag}] {record["tier"]:6s} {record["format"]:7s} '
                     f'{record["entries"]:>9,}  {record["title"][:56]:56s} {note[:40]}')

    if WARNINGS:
        lines += ['', f'Warnings ({len(WARNINGS)}):']
        lines += [f'  {text}' for text in WARNINGS]

    return '\n'.join(lines) + '\n'


# --------------------------------------------------------------------------

def main():
    started = time.monotonic()
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--sources', type=Path, default=Path('source.txt'))
    parser.add_argument('--output-dir', type=Path, default=Path('lists'))
    parser.add_argument('--cache-dir', type=Path, default=Path('.cache'))
    parser.add_argument('--offline', action='store_true', help='reuse cached downloads only')
    parser.add_argument('--dry-run', action='store_true', help='build in memory, write nothing')
    parser.add_argument('--max-bytes-per-file', type=int, default=MAX_BYTES_PER_OUTPUT_FILE,
                        help='split output files past this size (default 95 MB)')
    args = parser.parse_args()

    sources = read_sources(args.sources)
    log(f'sources: {len(sources)} configured '
        f'({sum(1 for s in sources if s.tier == "small")} small, '
        f'{sum(1 for s in sources if s.tier == "medium")} medium, '
        f'{sum(1 for s in sources if s.tier == "large")} large-only)')

    cache_dir = args.cache_dir

    try:
        psl = load_psl(cache_dir, args.offline)
    except ValueError as error:
        print(f'Build failed: {error}', file=sys.stderr)
        return 1

    buckets, tlds, per_source, raw_parts, raw_tlds = build(sources, psl, cache_dir, args.offline)
    ok = [r for r in per_source if r['status'] == 'ok']

    if not ok:
        print('Build failed: no usable sources', file=sys.stderr)
        return 1

    if len(ok) < len(per_source) // 2:
        print(f'Build failed: only {len(ok)} of {len(per_source)} sources usable; '
              'refusing to publish a gutted list', file=sys.stderr)
        return 1

    tiers = cumulative(buckets)

    if not tiers['small']:
        print('Build failed: small list is empty', file=sys.stderr)
        return 1

    if args.dry_run:
        print('\nDry run, nothing written:')

        for tier in TIER_ORDER:
            print(f'  {tier}: {len(tiers[tier]):,} domains')

        print(f'  tlds: {len(tlds)}')
        print(f'  adguard raw: {sum(1 for t in raw_parts.values() for _ in t)} sources concatenated')
        return 0

    report = write_lists(args.output_dir, tiers, tlds, args.max_bytes_per_file)
    adguard_report, written_adguard = write_adguard(args.output_dir, raw_parts, raw_tlds, args.max_bytes_per_file)

    for path in sorted(args.output_dir.glob('adguard-*.txt')):
        if path.name not in written_adguard:
            log(f'removed stale {path.name}')
            path.unlink()

    summary = build_summary(tiers, report + adguard_report, per_source, tlds, started)
    atomic_write(Path('build-summary.txt'), summary.encode('utf-8'))
    print('\n' + summary)

    return 0


if __name__ == '__main__':
    raise SystemExit(main())
