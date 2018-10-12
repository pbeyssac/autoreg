#!/usr/local/bin/python
# $Id$

import autoreg.dns.parser

import unittest

class TestDnsParser(unittest.TestCase):
  def setUp(self):
    self.p = autoreg.dns.parser.DnsParser()
  def _test_type_val(self, rrtype, rrvallist,
                     force_upper=False, force_lower=False):
    for rrval in rrvallist:
      retval = rrval
      if force_upper:
        retval = retval.upper()
      elif force_lower:
        retval = retval.lower()
      for label in ['', 'Z', 'z', 'z_1', 'z-1', '1234', 'ab.cd',
                    'ab.cd.ef', 'ab.cd.ef.gh', '1234567890'*6, '1234567890'*7,
                    '*', '*.aa']:
        for rrtypem in rrtype.lower(), rrtype.upper():
          for inclass in 'IN ', '':
            self.assertEqual(self.p.parseline("%s %s %s %s"
                                              % (label, inclass,
                                                 rrtypem, rrval)),
                             (label.upper(), None, rrtype.upper(), retval))
            self.assertEqual(self.p.parseline("%s %s %s %s "
                                              % (label, inclass,
                                                 rrtypem, rrval)),
                             (label.upper(), None, rrtype.upper(), retval))
            for ttl in ['0', '600', '3600', '86400', '172800']:
              self.assertEqual(self.p.parseline("%s %s %s %s %s"
                                                % (label, ttl, inclass,
                                                   rrtypem, rrval)),
                               (label.upper(), ttl, rrtype.upper(), retval))
              self.assertEqual(self.p.parseline("%s %s %s %s %s "
                                                % (label, ttl, inclass,
                                                   rrtypem, rrval)),
                               (label.upper(), ttl, rrtype.upper(), retval))
  def test_nok(self):
    for l in [' A ', 'z', 'z A', ' 3600 A', ' TXT ', ' 1D A 1.2.3.4']:
      self.assertRaises(autoreg.dns.parser.ParseError, self.p.parseline, l)
  def test_ok(self):
    for l in ['', ' ', '\t']:
      self.assertEqual(self.p.parseline(l), None)
  def testa_ok(self):
    self._test_type_val('A', ['10.1.2.3', '0.0.0.0', '255.255.255.255'])
  def testa_nok(self):
    for addr in ['127', '1278.0.0.1', '127.0.0.1/8', '1.2.3.455',
                 '01.02.03.04', 'aaaa', '0.0.0.0-1']:
      self.assertRaises(autoreg.dns.parser.ParseError, self.p.parseline,
                        ' A %s' % addr)
  def testaaaa_ok(self):
    self._test_type_val('AAAA', ['::', '::1', '2001::', '1:2:3:4:5:6:7:8',
                                 '12:34:56:78:9A:BC:DE:F0',
                                 '12:34:56:78:9a:bc:de:f0',
                                 '123:456:789:ABC:DEF:012:345:678',
                                 '123:456:789:abc:def:012:345:678',
                                 '1234:5678:9abc:def0:1234:5678:9abc:def0',
                                 '1234::1', '1234:5678::2',
                                 '1234:5678:9abc::3', '1234:5678:9abc:def0::4',
                                 '1234:5678:9abc:def0:1234::5',
                                 '1234:5678:9abc:def0:1234:5678::6',
                                 'ff80::1',
                                 '::10.1.2.3',
                                 '::ffff:10.1.2.3'], force_lower=True)
  def testaaaa_nok(self):
    for addr in [':::', '1.2.3.4', '::1::']:
      self.assertRaises(autoreg.dns.parser.ParseError, self.p.parseline,
                        ' AAAA %s' % addr)
  def testns_ko(self):
    self.assertRaises(autoreg.dns.parser.ParseError, self._test_type_val, 'NS', ['signal'])
  def testns_ok(self):
    self._test_type_val('NS', ['ns.eu.org.', 'a.root-servers.net.'], force_upper=True)
  def testptr_ko(self):
    self.assertRaises(autoreg.dns.parser.ParseError, self._test_type_val, 'PTR', ['signal'])
  def testptr_ok(self):
    self._test_type_val('PTR', ['ns.eu.org.', 'a.root-servers.net.'], force_upper=True)
  def testcname_ko(self):
    self.assertRaises(autoreg.dns.parser.ParseError,
      self._test_type_val, 'CNAME', ['signal'])
  def testcname_ok(self):
    self._test_type_val('CNAME',
                        ['ns.eu.org.', 'a.root-servers.net.'], force_upper=True)
  def testmx_ko(self):
    self.assertRaises(autoreg.dns.parser.ParseError,
      self._test_type_val, 'MX', ['255 signal'])
  def testmx_ok(self):
    self._test_type_val('MX', ['10 eu.org.', '0 blablabla.org.',
                               '20 ns.eu.org.'],
                        force_upper=True)
  def testmx_nok(self):
    for mx in ['0', '-100 eu.org.', '1000 eu.org', '256 eu.org']:
      self.assertRaises(autoreg.dns.parser.ParseError, self.p.parseline,
                        ' MX %s' % mx)
  def testtxt_ok(self):
    self._test_type_val('TXT', ['"texte 1"', '"texte2"'])
  def testsrv_ko(self):
    self.assertRaises(autoreg.dns.parser.ParseError,
      self._test_type_val, 'SRV', ['0 ns.eu.org.', '100 eu.org.'])
  def testsrv_ok(self):
    self._test_type_val('SRV', ['0 0 53 ns.eu.org.', '100 0 80 eu.org.'],
                        force_upper=True)

if __name__ == '__main__':
  unittest.main()

