#!/usr/local/bin/python

import unittest


import autoreg.dns.dnssec


class TestDnsParser(unittest.TestCase):
  def setUp(self):
    pass
  def test_ds_ok_1(self):
    self.assertEqual(
      (True, [(36406, 8, 2, '4c6ca5ce24b94eeb26cfb2bb9594dcd553088c4ae22a9f98bc5ca5fc36a6f4d2')]),
      autoreg.dns.dnssec.make_ds('eu.org. 12998 IN DS 36406 8 2 4C6CA5CE24B94EEB26CFB2BB9594DCD553088C4AE22A9F98BC5CA5FC 36A6F4D2',
                                 'eu.org'))
  def test_ds_ok_2(self):
    self.assertEqual(
      (True, [(36406, 8, 2, '4c6ca5ce24b94eeb26cfb2bb9594dcd553088c4ae22a9f98bc5ca5fc36a6f4d2')]),
      autoreg.dns.dnssec.make_ds(' DS 36406 8 2 4C6CA5CE24B94EEB26CFB2BB9594DCD553088C4AE22A9F98BC5CA5FC 36A6F4D2',
                                 'eu.org'))
  def test_ds_ko_1(self):
    self.assertEqual(
      (False, "Domain doesn't match record"),
      autoreg.dns.dnssec.make_ds('eu.org. 12998 IN DS 36406 8 2 4C6CA5CE24B94EEB26CFB2BB9594DCD553088C4AE22A9F98BC5CA5FC 36A6F4D2',
                                 'zz.org'))
  def test_dnskey_ok_1(self):
    self.assertEqual(
      (True, [(36406, 8, 2, '0785d750915bb8b69efd251c6a10a90d4bd9a644fa390faf70820aebe6bc88f8'),
              (36406, 8, 4, 'f3f01b98d1f4a940e3982631e3c6535d04c1c3f8e3e84a0a3463f5ec7f8554f56185b8ff67b7515c4fa930be28457036')]),
      autoreg.dns.dnssec.make_ds('eu.org. 12774 IN DNSKEY 257 3 8 AwEAAbZnzLeWuVFj4oKwMgUfcgIw1GBQWqLZr50YeVS3KPDzwcxXTANx cuMQcKSLoNGpT+UDKhN5QzKOrlRn8aOEjE1RmKaEe+X+Pd3jnf+JX1SI UFnorS2z5uekKigq/Ebd/6bLwUgBRe2BPR93rhEVORnjyNpHneAgQ0uz YsAHWkI26cPAwLQ9/fkNrmsEOeHkOsy/s8FpvFPWqz+CrTFO2VSx4GwN i7hMi6reGKZSGVDqDR1HCYxozSBnqV11pC1cZKt/aCIOnQ6pi5/U8QqH RpU3DkhEghLzO2YMg1pd8FpliMf+vE2uPe8XFyO9+EcxOk6HBIDTBRsX eVeAiR0p8QSPuMBJ1VN1CLjQP5Sylv7bBfurdnl/f3xb+bIuD7B9utUy jnZpvrelLw1Mxt2BjoMaVc8KtaQM9SSwVbZzIU7Vu6BqfSRzwI1Vxis6 +Bogp8ERpEh9VgWzPqnH8ZtF35jsb8MinjaXYkz9tLuxUD+9yOnflLUo erYT3kzvEM/jKWFig9VEuzM12fpOcEDS93iRi3s2HvKrlc/3XT4WOZ1e +v020HxiScTvuOMueXGvxbXb0SqnHEd6pJU+5owJafxctw2eEw+aaQP8 xuWDhoqtrakMXsZ9UByg3LqwkXq3oVMyU8/9Wv/IqjTV9Rli5idYPS3O jg3+8ZORrxxjMRDh', 'eu.org'))
  def test_dnskey_ko_1(self):
    self.assertEqual(
      (False, "Domain doesn't match record"),
      autoreg.dns.dnssec.make_ds('eu.org. 12774 IN DNSKEY 257 3 8 AwEAAbZnzLeWuVFj4oKwMgUfcgIw1GBQWqLZr50YeVS3KPDzwcxXTANx cuMQcKSLoNGpT+UDKhN5QzKOrlRn8aOEjE1RmKaEe+X+Pd3jnf+JX1SI UFnorS2z5uekKigq/Ebd/6bLwUgBRe2BPR93rhEVORnjyNpHneAgQ0uz YsAHWkI26cPAwLQ9/fkNrmsEOeHkOsy/s8FpvFPWqz+CrTFO2VSx4GwN i7hMi6reGKZSGVDqDR1HCYxozSBnqV11pC1cZKt/aCIOnQ6pi5/U8QqH RpU3DkhEghLzO2YMg1pd8FpliMf+vE2uPe8XFyO9+EcxOk6HBIDTBRsX eVeAiR0p8QSPuMBJ1VN1CLjQP5Sylv7bBfurdnl/f3xb+bIuD7B9utUy jnZpvrelLw1Mxt2BjoMaVc8KtaQM9SSwVbZzIU7Vu6BqfSRzwI1Vxis6 +Bogp8ERpEh9VgWzPqnH8ZtF35jsb8MinjaXYkz9tLuxUD+9yOnflLUo erYT3kzvEM/jKWFig9VEuzM12fpOcEDS93iRi3s2HvKrlc/3XT4WOZ1e +v020HxiScTvuOMueXGvxbXb0SqnHEd6pJU+5owJafxctw2eEw+aaQP8 xuWDhoqtrakMXsZ9UByg3LqwkXq3oVMyU8/9Wv/IqjTV9Rli5idYPS3O jg3+8ZORrxxjMRDh', 'zz.org'))
  def test_dnskey_ko_2(self):
    self.assertEqual(
      (False, 'Flags field should be 257 (key-signing key, security entry point)'),
      autoreg.dns.dnssec.make_ds('eu.org. 12190 IN DNSKEY 256 3 8 AwEAAbD16qAm2QsVzE6pELckbjHvCx2UPmQ6qXGPTsq0PNPxVpbMWX/U n49Kqg//+9BSOomQIEiX80B4on22cw0nfpzabW5eImKeoeuNq178vCV9 xebc0UhF9huRWRntEzVs1wZ90DZABcPGhgpKv/6x7zYItYeLpd+cmAB6 MmigxEhP', 'eu.org'))
  def test_dnskey_ko_3(self):
    self.assertEqual(
      (False, 'Protocol field should be 3'),
      autoreg.dns.dnssec.make_ds('eu.org. 12190 IN DNSKEY 257 9 8 AwEAAbD16qAm2QsVzE6pELckbjHvCx2UPmQ6qXGPTsq0PNPxVpbMWX/U n49Kqg//+9BSOomQIEiX80B4on22cw0nfpzabW5eImKeoeuNq178vCV9 xebc0UhF9huRWRntEzVs1wZ90DZABcPGhgpKv/6x7zYItYeLpd+cmAB6 MmigxEhP', 'eu.org'))
  def test_make_ds_dnskeys_ns(self):
      keylist = autoreg.dns.dnssec.make_ds_dnskeys_ns('.', ['a.root-servers.net', 'b.root-servers.net'])
      self.assertNotEqual(0, len(keylist))

if __name__ == '__main__':
  unittest.main()
