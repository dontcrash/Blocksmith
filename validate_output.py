#!/usr/bin/env python3
"""Validate Blocksmith output: every line is a plain lowercase registrable
domain, files are sorted and unique, tiers are cumulative, TLDs are bare.

    python3 validate_output.py            # checks lists/
    python3 validate_output.py other-dir
"""

import re
import sys
from pathlib import Path

from blocklist_core import LABEL, PublicSuffixList

DOMAIN = re.compile(r'^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$')


def read_lines(path):
    return path.read_text(encoding='utf-8').splitlines()


def main():
    lists_dir = Path(sys.argv[1] if len(sys.argv) > 1 else 'lists')
    psl = PublicSuffixList(Path('.cache/public_suffix_list.dat').read_text(encoding='utf-8-sig'))
    errors = []

    tiers = {}

    for name in ('small.txt', 'medium.txt'):
        path = lists_dir / name

        if not path.exists():
            errors.append(f'missing {name}')
            continue

        tiers[name] = check(path, psl, errors)

    large = set()

    for path in sorted(lists_dir.glob('large*.txt')):
        if not re.fullmatch(r'large(-\d+)?\.txt', path.name):
            errors.append(f'unexpected large file name: {path.name}')

        large |= check(path, psl, errors)

    if not large:
        errors.append('no large*.txt found')

    # cumulative coverage: every tier must be covered by the tier below it.
    # 'covered' is by blocked parent OR exact match, since parent-reduction
    # legitimately drops a child from a smaller file when its parent lives in
    # a bigger file.
    def covered(child_set, parent_set):
        missing = []

        for domain in child_set:
            if domain in parent_set:
                continue

            if any(p in parent_set for p in ('.'.join(domain.split('.')[i:]) for i in range(1, domain.count('.')))):
                continue

            missing.append(domain)

        return missing

    if len(tiers) == 2:
        for parent_name, child_name in (('medium.txt', 'small.txt'), ('large.txt', 'medium.txt')):
            parent_set = large if parent_name == 'large.txt' else tiers[parent_name]
            missing = covered(tiers[child_name], parent_set)

            if missing:
                errors.append(f'{child_name} has {len(missing)} domains not covered by {parent_name}, e.g. {missing[:3]}')

    for name in ('adguard-small.txt', 'adguard-medium.txt', 'adguard-large.txt'):
        path = lists_dir / name

        if not path.exists() or path.stat().st_size < 1024:
            errors.append(f'missing or empty {name}')

    tld_path = lists_dir / 'tlds.txt'

    if tld_path.exists():
        tlds = read_lines(tld_path)

        if tlds != sorted(set(tlds)):
            errors.append('tlds.txt not sorted/unique')

        for tld in tlds:
            if not LABEL.fullmatch(tld):
                errors.append(f'bad TLD line: {tld!r}')

        print(f'  tlds.txt: {len(tlds)} whole-TLD blocks (bare, no dots)')

    if errors:
        print(f'FAILED: {len(errors)} problem(s)')

        for e in errors[:40]:
            print(f'  - {e}')

        return 1

    print('OK: output is plain-domain, sorted, unique, tiers cumulative')
    return 0


def check(path, psl, errors):
    lines = read_lines(path)

    if lines != sorted(lines):
        errors.append(f'{path.name}: not sorted')

    if len(lines) != len(set(lines)):
        errors.append(f'{path.name}: has duplicates')

    bad = 0

    for line in lines:
        if not DOMAIN.fullmatch(line) or '.' not in line:
            errors.append(f'{path.name}: bad domain line {line!r}')
            bad += 1

            if bad > 5:
                break

            continue

        if line == psl.suffix(line):
            errors.append(f'{path.name}: public suffix blocked {line!r}')
            bad += 1

    print(f'  {path.name}: {len(lines):,} domains validated')
    return set(lines)


if __name__ == '__main__':
    raise SystemExit(main())
