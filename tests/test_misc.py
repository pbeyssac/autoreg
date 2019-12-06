#!/usr/local/bin/python3.6


import io
import os
import unittest

import autoreg.dns.check
import autoreg.dns.newzones
import autoreg.newsecret


class TestHandles(unittest.TestCase):
  def test1(self):
    autoreg.newsecret.new_handle_secret()

class TestCheckAllSoa(unittest.TestCase):
  def test1(self):
    os.environ['USER'] = 'autoreg'
    out = io.StringIO()
    autoreg.dns.check.checkallsoa(['checkallsoa', 'HISTORY.TESTS.EU.ORG'], file=out)
    self.assertTrue('HISTORY.TESTS.EU.ORG FAILED' in out.getvalue())
    self.assertTrue('Error: empty name server list' in out.getvalue())
  def test2(self):
    os.environ['USER'] = 'autoreg'
    out = io.StringIO()
    autoreg.dns.check.checkallsoa(['checkallsoa', 'DNSSEC.TESTS.EU.ORG'], file=out)
    self.assertTrue('Accepted IP for NS1.DNSSEC.TESTS.EU.ORG: 192.168.0.15' in out.getvalue())
    self.assertTrue('NS from NS1.DNSSEC.TESTS.EU.ORG at 192.168.0.15: Error: Answer not authoritative' in out.getvalue())
    self.assertTrue('SOA from NS1.DNSSEC.TESTS.EU.ORG at 192.168.0.15: Error: Answer not authoritative' in out.getvalue())
  def test3(self):
    out = io.StringIO()
    zone = io.StringIO()
    autoreg.dns.newzones.transfer(['importzone', '127.0.0.1', 'serial.tests.eu.org'],
                                  outfile=out, zonefile=zone)
    os.environ['USER'] = 'autoreg'
    out = io.StringIO()
    autoreg.dns.check.checkallsoa(['checkallsoa', 'SERIAL.TESTS.EU.ORG'], file=out)
    print(out.getvalue())


class TestNewZone(unittest.TestCase):
  def test1(self):
    out = io.StringIO()
    zone = io.StringIO()
    autoreg.dns.newzones.create(['newzone', 'newtest.tests.eu.org'],
                                outfile=out, zonefile=zone)
    self.assertEqual(
"""; zone name=NEWTEST.TESTS.EU.ORG
$TTL 259200
@	SOA	NS.EU.ORG. hostmaster.eu.org. 1 3600 1800 12096000 259200
	NS	NS.EU.ORG.
_END-MARK	TXT	"end mark"
""", zone.getvalue())
    self.assertEqual(
"""Allowed zone NEWTEST.TESTS.EU.ORG to 2 administrators
Add the following to your BIND configuration file:
zone "NEWTEST.TESTS.EU.ORG" { type master; file "<internal>"; allow-transfer {}; };
Then run 'rndc reconfig'
""", out.getvalue())

if __name__ == '__main__':
  unittest.main()
