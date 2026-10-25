#!/usr/bin/env python3
"""Offline tests for Blocksmith: parser, validator, TLD handling, config and
chunking. No network, no writes.

    python3 -m unittest -v test_blocklist_core.py
"""

import tempfile
import unittest
from pathlib import Path

from blocklist_core import (
    PublicSuffixList,
    check_modifiers,
    normalize_domain,
    parse_line,
    parse_source,
    parse_tld_line,
    reduce_parents,
)
from update import Source, cumulative, detect_format, read_sources, split_to_parts


PSL_TEXT = '''
// ===BEGIN ICANN DOMAINS===
com
net
org
uk
co.uk
pl
*.ck
!www.ck
jp
io
xyz
top
live
onion
example
invalid
test
// ===END ICANN DOMAINS===
// ===BEGIN PRIVATE DOMAINS===
blogspot.com
duckdns.org
vercel.app
github.io
firewalled.cc
'''

PSL = PublicSuffixList(PSL_TEXT)


class TestRuleSyntax(unittest.TestCase):
    def assert_host(self, rule, host):
        self.assertEqual(parse_line(rule, 'adblock'), (host, False))

    def assert_rejected(self, rule, reason):
        with self.assertRaises(ValueError) as caught:
            parse_line(rule, 'adblock')

        self.assertEqual(str(caught.exception), reason)

    def test_plain_anchor(self):
        self.assert_host('||example.com^', 'example.com')

    def test_deep_subdomain(self):
        self.assert_host('||a.b.c.example.co.uk^', 'a.b.c.example.co.uk')

    def test_trailing_dot_is_normalised(self):
        host, _ = parse_line('||example.com.^', 'adblock')
        self.assertEqual(normalize_domain(host, PSL), 'example.com')

    def test_inert_modifiers_are_dropped(self):
        self.assert_host('||example.com^$all', 'example.com')
        self.assert_host('||example.com^$important', 'example.com')
        self.assert_host('||example.com^$important,all', 'example.com')

    def test_third_party_blocks_the_name_too(self):
        # DNS cannot tell first party from third party, and the intent for
        # miner/ad networks is to stop the name outright.
        self.assert_host('||miner.example.com^$third-party', 'miner.example.com')

    def test_first_party_only_is_refused(self):
        self.assert_rejected('||example.com^$1p', 'unsupported rule modifier')

    def test_domain_scoped_is_refused(self):
        self.assert_rejected('||example.com^$domain=foo.com', 'unsupported rule modifier')

    def test_denyallow_is_refused(self):
        self.assert_rejected('||example.com^$denyallow=good.com', 'unsupported rule modifier')

    def test_negated_third_party_is_refused(self):
        self.assert_rejected('||example.com^$~third-party', 'unsupported rule modifier')

    def test_resource_type_is_refused(self):
        for modifier in ('script', 'css', 'image', 'subdocument', 'xmlhttprequest',
                         'websocket', 'popup', 'font', 'media', 'object', 'other', 'empty'):
            self.assert_rejected(f'||example.com^${modifier}', 'unsupported rule modifier')

    def test_redirect_and_removeparam_are_refused(self):
        self.assert_rejected('||example.com^$redirect=nooptext', 'unsupported rule modifier')
        self.assert_rejected('||example.com^$removeparam=utm_source', 'unsupported rule modifier')

    def test_path_scoped_is_refused(self):
        self.assert_rejected('||example.com^/login', 'path-scoped rule')
        self.assert_rejected('||example.com^/ads/banner.js', 'path-scoped rule')

    def test_missing_caret_is_refused(self):
        self.assert_rejected('||example.com', 'missing separator')

    def test_bare_anchor_is_refused(self):
        self.assert_rejected('||^', 'empty hostname')

    def test_single_label_is_refused(self):
        host, _ = parse_line('||localhost^', 'adblock')

        with self.assertRaises(ValueError) as caught:
            normalize_domain(host, PSL)

        self.assertEqual(str(caught.exception), 'single-label hostname')

    def test_cosmetic_is_refused(self):
        self.assert_rejected('example.com##.ad', 'cosmetic rule')
        self.assert_rejected('||example.com##.ad', 'cosmetic rule')
        self.assert_rejected('||example.com#$#display:none', 'cosmetic rule')
        self.assert_rejected('example.com#@#.adsbox', 'cosmetic rule')

    def test_regex_is_refused(self):
        self.assert_rejected('/banner[0-9]+\\.gif/', 'regex rule')
        self.assert_rejected('*.example.com^', 'regex rule')

    def test_url_anchor_rule(self):
        self.assert_host('|https://example.com^', 'example.com')
        self.assert_rejected('|https://example.com/path', 'path-anchored rule')
        self.assert_rejected('|https://example.com', 'unanchored URL rule')

    def test_exception_rule_marks_exception(self):
        self.assertEqual(parse_line('@@||example.com^', 'adblock'), ('example.com', True))

    def test_modifier_allowlist(self):
        self.assertTrue(check_modifiers('all'))
        self.assertTrue(check_modifiers('important,all'))
        self.assertTrue(check_modifiers('third-party'))
        self.assertFalse(check_modifiers(''))
        self.assertFalse(check_modifiers('script'))
        self.assertFalse(check_modifiers('all,script'))
        self.assertFalse(check_modifiers('domain=example.com'))


class TestHostsAndDomainsFormats(unittest.TestCase):
    def test_zero_zero_zero_zero(self):
        self.assertEqual(parse_line('0.0.0.0 example.com', 'hosts'), ('example.com', False))

    def test_localhost_style(self):
        self.assertEqual(parse_line('127.0.0.1 ads.example.com', 'hosts'), ('ads.example.com', False))

    def test_ipv6_localhost(self):
        self.assertEqual(parse_line('::1 ipv6.example.com', 'hosts'), ('ipv6.example.com', False))

    def test_plain_domain(self):
        self.assertEqual(parse_line('example.com', 'domains'), ('example.com', False))

    def test_adguard_syntax_inside_domains_feed(self):
        self.assertEqual(parse_line('||example.com^', 'domains'), ('example.com', False))

    def test_ports_are_dropped(self):
        self.assertEqual(parse_line('example.com:8080', 'domains'), ('example.com', False))


class TestValidation(unittest.TestCase):
    def test_ok(self):
        self.assertEqual(normalize_domain('Example.COM', PSL), 'example.com')

    def test_unknown_tld_is_rejected(self):
        with self.assertRaises(ValueError) as caught:
            normalize_domain('login.account-streamparent', PSL)

        self.assertEqual(str(caught.exception), 'unknown TLD')

    def test_onion_is_rejected(self):
        # The PSL carries .onion, but a unicast resolver never answers for it.
        self.assertIn('onion', PSL.tlds)

        with self.assertRaises(ValueError) as caught:
            normalize_domain('darkmarket.onion', PSL)

        self.assertEqual(str(caught.exception), 'non-resolvable suffix')

    def test_ip_literal_is_rejected(self):
        for value in ('1.2.3.4', '192.168.1.1'):
            with self.assertRaises(ValueError) as caught:
                normalize_domain(value, PSL)

            self.assertEqual(str(caught.exception), 'IP addresses are not domains')

    def test_ip_derived_hostname_is_allowed(self):
        # URLhaus reports hostnames that merely look like IP addresses.
        self.assertEqual(normalize_domain('0.232.205.92.host.secureserver.net', PSL),
                         '0.232.205.92.host.secureserver.net')

    def test_underscore_is_rejected(self):
        with self.assertRaises(ValueError):
            normalize_domain('evil_label.example.com', PSL)

    def test_non_ascii_is_rejected(self):
        with self.assertRaises(ValueError):
            normalize_domain('exämple.com', PSL)

    def test_punycode_is_allowed(self):
        self.assertEqual(normalize_domain('xn--80ak6aa92e.com', PSL), 'xn--80ak6aa92e.com')

    def test_refuses_public_suffix(self):
        for value in ('co.uk', 'blogspot.com', 'duckdns.org'):
            with self.assertRaises(ValueError) as caught:
                normalize_domain(value, PSL)

            self.assertEqual(str(caught.exception), 'refusing to block a public suffix')

    def test_subdomain_of_public_suffix_is_allowed(self):
        self.assertEqual(normalize_domain('evil.duckdns.org', PSL), 'evil.duckdns.org')


class TestPublicSuffixList(unittest.TestCase):
    def test_multi_part_suffix(self):
        self.assertEqual(PSL.suffix('shop.example.co.uk'), 'co.uk')
        self.assertEqual(PSL.registrable('shop.example.co.uk'), 'example.co.uk')

    def test_wildcard_suffix(self):
        self.assertEqual(PSL.suffix('anything.bar.ck'), 'bar.ck')

    def test_wildcard_exception(self):
        self.assertEqual(PSL.suffix('www.ck'), 'ck')

    def test_single_label_tld_set(self):
        self.assertIn('com', PSL.tlds)
        self.assertNotIn('co.uk', PSL.tlds)


class TestFeedParsing(unittest.TestCase):
    def parse(self, body, fmt='adblock'):
        return parse_source(body.encode('utf-8'), fmt, PSL)

    def test_comments_headers_and_blank_lines(self):
        body = '[Adblock Plus 2.0]\n! Title: Test\n# comment\n\n||one.example^\n'
        domains, stats = self.parse(body)
        self.assertEqual(domains, {'one.example'})
        self.assertEqual(stats['accepted'], 1)

    def test_only_clean_domain_survives_noise(self):
        body = '\n'.join([
            '[Adblock Plus 2.0]',
            '! Title: Threat feed',
            '!#if admagic',
            '||should-not-appear.example^',
            '!#endif',
            '||good.example^',
            '||good.example^',
            '||tracking.example^$third-party,script',
            '||path.example^/ad.js',
            '||bad-tld.streamparent^',
            '||dark.onion^',
            '||192.0.2.7^',
            '||und_score.example^',
            'example.com##.banner',
            '@@||allow.example^',
            '@@||evil.example^$domain=partner.example',
            '||allow.example^',
            '||evil.example^',
            '||sub.allow.example^',
        ]) + '\n'
        domains, stats = self.parse(body)

        self.assertIn('good.example', domains)
        self.assertIn('evil.example', domains)
        self.assertNotIn('should-not-appear.example', domains)
        self.assertNotIn('bad-tld.streamparent', domains)
        self.assertNotIn('dark.onion', domains)
        self.assertNotIn('und_score.example', domains)
        self.assertNotIn('allow.example', domains)
        self.assertNotIn('sub.allow.example', domains)
        self.assertEqual(stats['exception_removed'], 2)
        self.assertEqual(stats['conditional_exception'], 1)
        self.assertEqual(stats['preprocessor_skipped'], 1)

    def test_allow_wins_over_own_block(self):
        domains, stats = self.parse('||example.com^\n@@||example.com^\n')
        self.assertEqual(domains, set())
        self.assertEqual(stats['exception_removed'], 1)

    def test_allow_cannot_punch_hole_in_parent(self):
        body = '||example.com^\n@@||cdn.example.com^\n'
        domains, stats = self.parse(body)
        self.assertEqual(domains, {'example.com'})
        self.assertEqual(stats['unexpressible_exception'], 1)

    def test_inline_comments_are_stripped(self):
        domains, _ = self.parse('||ads.example.com^   # ad network\n')
        self.assertEqual(domains, {'ads.example.com'})

    def test_hosts_format(self):
        body = '127.0.0.1 one.example.com\n0.0.0.0 two.example.com # inline\n::1 three.example.com\n'
        domains, _ = self.parse(body, 'hosts')
        self.assertEqual(domains, {'one.example.com', 'two.example.com', 'three.example.com'})

    def test_protected_names_are_never_blocked(self):
        domains, stats = self.parse('||captive.apple.com^\n||accounts.google.com^\n||ads.example^\n')
        self.assertEqual(domains, {'ads.example'})
        self.assertEqual(stats['protected'], 2)

    def test_gzip_input(self):
        import gzip
        raw = gzip.compress(b'||example.com^\n')
        domains, _ = parse_source(raw, 'adblock', PSL)
        self.assertEqual(domains, {'example.com'})


class TestTldParsing(unittest.TestCase):
    def test_hagezi_rule_forms(self):
        self.assertEqual(parse_tld_line('||*.xyz^'), 'xyz')
        self.assertEqual(parse_tld_line('||*.agency^$denyallow=x.agency'), 'agency')

    def test_bare_and_dotted_forms(self):
        self.assertEqual(parse_tld_line('.top'), 'top')
        self.assertEqual(parse_tld_line('live'), 'live')

    def test_rejects_nonsense(self):
        for bad in ('..', '-bad', 'not a tld'):
            with self.assertRaises(ValueError, msg=bad):
                parse_tld_line(bad)

    def test_parse_source_tld_format(self):
        body = '||*.xyz^\n||*.top^$denyallow=a.top\nmade-up-tld\n'
        entries, stats = parse_source(body.encode('utf-8'), 'tld', PSL)
        self.assertEqual(entries, {'xyz', 'top'})
        self.assertEqual(stats['invalid_name'], 1)

    def test_tld_list_exceptions_do_not_leak_domains(self):
        body = '@@||*.com^\n||*.xyz^\n'
        entries, stats = parse_source(body.encode('utf-8'), 'tld', PSL)
        self.assertEqual(entries, {'xyz'})
        self.assertEqual(stats['exception_lines'], 1)


class TestParentReduction(unittest.TestCase):
    def test_descendants_removed(self):
        kept, removed = reduce_parents({'example.com', 'a.example.com', 'b.a.example.com', 'other.com'})
        self.assertEqual(kept, {'example.com', 'other.com'})
        self.assertEqual(removed, {'a.example.com', 'b.a.example.com'})

    def test_unrelated_same_suffix_kept(self):
        kept, _ = reduce_parents({'notexample.com', 'example.com'})
        self.assertEqual(kept, {'notexample.com', 'example.com'})

    def test_multi_part_suffix(self):
        kept, removed = reduce_parents({'example.co.uk', 'shop.example.co.uk'})
        self.assertEqual(kept, {'example.co.uk'})


class TestSourceConfig(unittest.TestCase):
    def read(self, body):
        with tempfile.NamedTemporaryFile('w', suffix='.txt', delete=False) as fh:
            fh.write(body)
            path = Path(fh.name)

        try:
            return read_sources(path)
        finally:
            path.unlink()

    def test_defaults_and_inline_comments(self):
        sources = self.read(
            '# header comment\n'
            'https://a.example/x.txt            # large + auto\n'
            'https://b.example/y.txt|small\n'
            'https://c.example/z.txt|large|tld\n'
        )
        self.assertEqual([(s.url, s.tier, s.fmt) for s in sources], [
            ('https://a.example/x.txt', 'large', 'auto'),
            ('https://b.example/y.txt', 'small', 'auto'),
            ('https://c.example/z.txt', 'large', 'tld'),
        ])

    def test_unknown_tier_is_refused(self):
        with self.assertRaises(ValueError):
            self.read('https://a.example/x.txt|huge\n')

    def test_unknown_format_is_refused(self):
        with self.assertRaises(ValueError):
            self.read('https://a.example/x.txt|small|regex\n')

    def test_non_url_is_refused(self):
        with self.assertRaises(ValueError):
            self.read('localhost\n')

    def test_empty_registry_is_refused(self):
        with self.assertRaises(ValueError):
            self.read('# nothing here\n')


class TestTiers(unittest.TestCase):
    def test_cumulative_subsets(self):
        buckets = {
            'small': {'a.com'},
            'medium': {'b.com'},
            'large': {'c.com'},
        }
        tiers = cumulative(buckets)
        self.assertEqual(tiers['small'], {'a.com'})
        self.assertEqual(tiers['medium'], {'a.com', 'b.com'})
        self.assertEqual(tiers['large'], {'a.com', 'b.com', 'c.com'})
        self.assertTrue(tiers['small'] <= tiers['medium'] <= tiers['large'])


class TestSplitToParts(unittest.TestCase):
    def test_under_cap_stays_one_file(self):
        parts = split_to_parts('large.txt', ['a.com', 'b.com'], 100)
        self.assertEqual([name for name, _ in parts], ['large.txt'])

    def test_over_cap_splits_and_keeps_everything(self):
        lines = sorted(f'{n:04d}.com' for n in range(50))
        parts = split_to_parts('large.txt', lines, 300)
        self.assertGreater(len(parts), 1)
        self.assertEqual([name for name, _ in parts],
                         [f'large-{i}.txt' for i in range(1, len(parts) + 1)])

        for _, chunk in parts:
            self.assertLessEqual(sum(len(line) + 1 for line in chunk), 300)

        joined = [line for _, chunk in parts for line in chunk]
        self.assertEqual(joined, lines)

    def test_split_is_stable(self):
        lines = sorted(f'{n:04d}.com' for n in range(100))
        first = split_to_parts('large.txt', lines, 500)
        second = split_to_parts('large.txt', lines, 500)
        self.assertEqual(first, second)


class TestFormatDetection(unittest.TestCase):
    def test_adblock(self):
        self.assertEqual(detect_format(b'! c\n||example.com^\n'), 'adblock')

    def test_hosts(self):
        self.assertEqual(detect_format(b'0.0.0.0 example.com\n'), 'hosts')

    def test_domains(self):
        self.assertEqual(detect_format(b'example.com\nother.com\n'), 'domains')


if __name__ == '__main__':
    unittest.main(verbosity=2)
