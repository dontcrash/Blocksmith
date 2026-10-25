#!/usr/bin/env python3
"""Core parsing and validation for Blocksmith.

Convert any of adblock / hosts / plain-domain input into validated plain
domains, one per line, plus a small TLD extractor for whole-TLD blocklists
that cannot be expressed as domains. Input can mix formats; output never does.
"""

import gzip
import ipaddress
import re
import sys


WARNINGS = []


def warn(message):
    WARNINGS.append(message)
    print(f'WARNING: {message}', file=sys.stderr, flush=True)


# AdGuard modifiers that do not narrow *which* names are blocked, so dropping
# them keeps the same DNS meaning. Anything not listed here narrows the rule
# (resource type, frame, path, first-party only, domain=..., redirect=...) and
# would become over-blocking if converted, so the rule is skipped instead.
MODIFIER_ALLOW = {'all', 'important', 'third-party', '3p', 'dup', 'strict'}
MODIFIER_DENY_PREFIX = ('domain=', 'denyallow=', '~', 'path=', 'url=', 'tag=', 'ctag=',
                       'app=', 'from=', 'to=', 'header=', 'frame-src=', 'rewrite=')
MODIFIER_NARROWS = {
    'script', 'css', 'image', 'images', 'media', 'font', 'object', 'subdocument',
    'xmlhttprequest', 'websocket', 'popup', 'document', 'elemhide', 'generichide',
    'genericblock', 'stylesheet', 'inline-font', 'inline-script', 'other', 'empty',
    'ping', 'stealth', 'ehide', 'ghide', 'cshide', 'shide', '3p-script', '3p-frame',
    '1p-script', '1p', 'first-party', 'ghb', 'badge', 'replace', 'redirect',
    'redirect-rule', 'csp', 'removeparam', 'match-case', 'cname', 'all-xhr',
}

UNSUPPORTED_ERRORS = {
    'cosmetic rule', 'regex rule', 'wildcard pattern rule', 'path-scoped rule',
    'path-anchored rule', 'unsupported rule modifier', 'not a domain-anchor rule',
    'unanchored URL rule', 'missing separator', 'exception cannot be expressed',
}

LABEL = re.compile(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z', re.ASCII)
HOSTS_PREFIX = re.compile(r'^(?:0\.0\.0\.0|127\.0\.0\.1|::1|\[::1\])\s+')
TLD_RULE = re.compile(r'^\|\|\*\.([a-z0-9][a-z0-9-]*)\^')

# Blocking these breaks sign-in, captive portals or device setup. Deliberately
# short and explicit; this is not a general allowlist.
PROTECTED = {
    'captive.apple.com',
    'connectivitycheck.android.com',
    'connectivitycheck.gstatic.com',
    'connectivity-check.ubuntu.com',
    'detectportal.firefox.com',
    'clients3.google.com',
    'dns.google',
    'one.one.one.one',
    'appleid.apple.com',
    'id.apple.com',
    'accounts.google.com',
    'login.microsoftonline.com',
    'login.live.com',
    'icloud.com',
    'www.icloud.com',
    'setup.icloud.com',
    'gateway.icloud.com',
    'albert.apple.com',
}


# The Public Suffix List carries a few pseudo-TLDs that a normal recursive
# resolver will never answer for, so they are useless inside a firewall
# domain list.
NON_RESOLVABLE_SUFFIXES = {'onion'}


class PublicSuffixList:
    """Enough of the Public Suffix List to validate names and find registrable domains."""

    def __init__(self, text=None):
        self.exact = set()
        self.wildcard = set()
        self.exception = set()
        self.tlds = set()

        for line in (text or '').splitlines():
            rule = line.strip().lower()

            if not rule or rule.startswith('//'):
                continue

            if rule.startswith('*.'):
                self.wildcard.add(rule[2:])
            elif rule.startswith('!'):
                self.exception.add(rule[1:])
            else:
                self.exact.add(rule)

                if '.' not in rule:
                    self.tlds.add(rule)

    def suffix(self, host):
        labels = host.split('.')

        for index in range(len(labels)):
            candidate = '.'.join(labels[index:])

            if candidate in self.exception:
                return '.'.join(labels[index + 1:])

            if candidate in self.exact:
                return candidate

            parent = '.'.join(labels[index + 1:])

            if parent and parent in self.wildcard:
                return candidate

        return '.'.join(labels[-2:]) if len(labels) >= 2 else None

    def registrable(self, host):
        suffix = self.suffix(host)

        if not suffix:
            return None

        depth = suffix.count('.') + 1
        labels = host.split('.')

        if len(labels) <= depth:
            return host

        return '.'.join(labels[len(labels) - depth - 1:])


def normalize_domain(value, psl=None):
    """Validate one hostname. Raises ValueError when it must not be blocked."""
    if not value.isascii():
        raise ValueError('non-ASCII hostname')

    value = value.lower().rstrip('.')

    if not value or len(value) > 253:
        raise ValueError('invalid hostname length')

    labels = value.split('.')

    if len(labels) < 2:
        raise ValueError('single-label hostname')

    if not all(LABEL.fullmatch(label) for label in labels):
        raise ValueError('invalid hostname characters')

    try:
        ipaddress.ip_address(value)
    except ValueError:
        pass
    else:
        raise ValueError('IP addresses are not domains')

    if labels[-1] in NON_RESOLVABLE_SUFFIXES:
        raise ValueError('non-resolvable suffix')

    if psl is not None:
        if labels[-1] not in psl.tlds:
            raise ValueError('unknown TLD')

        if value == psl.suffix(value):
            raise ValueError('refusing to block a public suffix')

    return value


def ancestors(name):
    labels = name.split('.')

    for index in range(1, len(labels)):
        yield '.'.join(labels[index:])


def check_modifiers(modifiers):
    if not modifiers:
        return False

    for modifier in modifiers.split(','):
        modifier = modifier.strip()

        if not modifier or modifier in MODIFIER_ALLOW:
            continue

        if modifier.startswith(MODIFIER_DENY_PREFIX) or modifier in MODIFIER_NARROWS:
            return False

        return False

    return True


def parse_line(line, fmt='adblock'):
    """Return (hostname, is_exception) or raise ValueError with a reason."""
    if fmt in ('hosts', 'domains'):
        host = HOSTS_PREFIX.sub('', line).strip()

        if host.startswith('||'):
            host = host[2:].split('^')[0]
        elif host.startswith('/') or host.endswith('/'):
            raise ValueError('regex rule')

        host = host.split('/')[0].split(' ')[0].split('\t')[0]

        if '@' in host:
            host = host.split('@', 1)[1]

        if host.startswith('@@'):
            raise ValueError('exception cannot be expressed')

        if ':' in host:
            host = host.split(':', 1)[0]

        if not host:
            raise ValueError('empty hostname')

        return host, False

    body = line
    is_exception = body.startswith('@@')

    if is_exception:
        body = body[2:]

    if '##' in body or '#$#' in body or '#@#' in body or '#+#' in body:
        raise ValueError('cosmetic rule')

    if '$' in body:
        head, modifiers = body.rsplit('$', 1)

        if not check_modifiers(modifiers):
            raise ValueError('unsupported rule modifier')

        body = head

    if body.startswith('|http://') or body.startswith('|https://'):
        remainder = body.split('://', 1)[1]

        if '/' in remainder.split('^', 1)[0]:
            raise ValueError('path-anchored rule')

        if '^' not in remainder:
            raise ValueError('unanchored URL rule')

        host, rest = remainder.split('^', 1)

        if rest:
            raise ValueError('path-anchored rule')

        return host, is_exception

    if body.startswith('/') or body.startswith('*'):
        raise ValueError('regex rule')

    if not body.startswith('||'):
        raise ValueError('not a domain-anchor rule')

    body = body[2:]

    if '^' not in body:
        raise ValueError('missing separator')

    host, rest = body.split('^', 1)

    if rest:
        raise ValueError('path-scoped rule')

    if not host:
        raise ValueError('empty hostname')

    return host, is_exception


def parse_tld_line(line):
    """Return a bare TLD ('xyz') or raise ValueError. Input forms:
    '||*.xyz^...' (HaGeZi TLD list), '.xyz', 'xyz'."""
    match = TLD_RULE.match(line)

    if match:
        tld = match.group(1)
    else:
        tld = line.lstrip('*.')

    if not tld or not LABEL.fullmatch(tld):
        raise ValueError(f'not a TLD: {line[:60]!r}')

    return tld


def strip_comment(line):
    for marker in (' #', '\t#'):
        if marker in line:
            line = line.split(marker, 1)[0]

    return line.strip()


def parse_source(raw, fmt='adblock', psl=None, name=''):
    """Parse one source body.

    fmt='tld' extracts whole-TLD blocks instead of domains. Returns
    (entries, stats) where stats explains every line that was not converted.
    """
    if raw[:2] == b'\x1f\x8b':
        raw = gzip.decompress(raw)

    text = raw.decode('utf-8-sig', errors='replace')

    entries = set()
    allows = set()
    stats = {
        'lines': 0,
        'accepted': 0,
        'unsupported_syntax': 0,
        'invalid_name': 0,
        'conditional_exception': 0,
        'exception_lines': 0,
        'protected': 0,
        'preprocessor_skipped': 0,
        'unresolved_include': 0,
        'duplicate': 0,
        'exception_removed': 0,
        'unexpressible_exception': 0,
    }
    warnings = []
    conditional = 0

    for number, original in enumerate(text.splitlines(), 1):
        line = original.strip()

        if not line:
            continue

        if line.startswith('!#'):
            words = line[2:].split()
            directive = words[0] if words else ''

            if directive == 'endif':
                conditional = max(0, conditional - 1)
            elif directive == 'if':
                conditional += 1
                stats['preprocessor_skipped'] += 1
            elif directive == 'include':
                stats['unresolved_include'] += 1

            continue

        if conditional:
            continue

        if line.startswith(('!', '#', '[', 'server=', 'address=', 'ip6addr=')):
            continue

        line = strip_comment(line)

        if not line:
            continue

        stats['lines'] += 1

        try:
            if fmt == 'tld':
                if line.startswith('@@'):
                    stats['exception_lines'] += 1
                    continue

                entry = parse_tld_line(line)

                if psl is not None and entry not in psl.tlds:
                    raise ValueError(f'unknown TLD {entry!r}')
            else:
                if line.startswith('@@'):
                    body = line[2:]
                    head, separator, modifiers = body.rpartition('$')

                    if not separator:
                        head, modifiers = body, ''

                    if modifiers and not check_modifiers(modifiers):
                        stats['conditional_exception'] += 1
                        continue

                    host, _ = parse_line(head, fmt)
                    allows.add(normalize_domain(host, psl))
                    stats['exception_lines'] += 1
                    continue

                host, _ = parse_line(line, fmt)
                entry = normalize_domain(host, psl)
        except ValueError as error:
            reason = str(error)

            if reason in UNSUPPORTED_ERRORS:
                stats['unsupported_syntax'] += 1
            else:
                stats['invalid_name'] += 1

            if len(warnings) < 5:
                warnings.append(f'{name}:{number}: {reason}: {line[:120]!r}')

            continue

        if fmt != 'tld' and entry in PROTECTED:
            stats['protected'] += 1
            continue

        if entry in entries:
            stats['duplicate'] += 1

        stats['accepted'] += 1
        entries.add(entry)

    if allows:
        covered = {e for e in entries if e in allows or any(p in allows for p in ancestors(e))}
        entries.difference_update(covered)
        stats['exception_removed'] = len(covered)

        # An allow rule below a still-blocked parent cannot be expressed in a
        # plain domain list; the parent stays blocked.
        stats['unexpressible_exception'] = sum(
            1 for allowed in allows if any(parent in entries for parent in ancestors(allowed))
        )

    stats['examples'] = warnings

    return entries, stats


def reduce_parents(domains):
    """Drop names already covered by a blocked parent in the same list."""
    kept = set()
    removed = set()

    for name in sorted(domains, key=lambda value: (len(value), value)):
        if any(parent in kept for parent in ancestors(name)):
            removed.add(name)
        else:
            kept.add(name)

    return kept, removed
