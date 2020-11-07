#!/usr/local/bin/python3.6

import io as cStringIO
import re
import os
import sys

import psycopg2

import autoreg.conf
import autoreg.dns.db

import unittest

class TestDnsDb(unittest.TestCase):
  re_do = re.compile('^; domain (\S+)$')
  re_zo = re.compile('^; zone (\S+)$')
  re_cr = re.compile('^; created: by (\S+), (\S+ \S+)$')
  re_up = re.compile('^; updated: by (\S+), (\S+ \S+)$')
  ns12 = """				NS	NS1.EU.ORG.
				NS	NS2.EU.ORG.
"""
  null = ""
  ns345 = """				NS	NS3.EU.ORG.
				NS	NS4.EU.ORG.
				NS	NS5.EU.ORG.
"""
  glue12 = """				NS	NS1.TESTGL.EU.ORG.
				NS	NS2.TESTGL.EU.ORG.
NS1.TESTGL			A	1.2.3.4
NS2.TESTGL			AAAA	::ffff:10.1.2.3
"""
  def _parseout(self, d, z):
    fout = cStringIO.StringIO()
    self.dd.show(d, z, outfile=fout)
    flags = []
    dom, zone, crby, upby = None, None, None, None
    rest = ''
    for l in fout.getvalue().split('\n'):
      if l == '; registry_hold' or l == '; registry_lock' or l == '; internal':
        flags.append(l[2:])
        continue
      if l == '; (NO RECORD)':
        continue
      m = self.re_do.match(l)
      if m:
        dom = m.groups()[0]
        continue
      m = self.re_zo.match(l)
      if m:
        zone = m.groups()[0]
        continue
      m = self.re_cr.match(l)
      if m:
        crby = m.groups()[0]
        continue
      m = self.re_up.match(l)
      if m:
        upby = m.groups()[0]
        continue
      rest += l + '\n'
    return dom, zone, crby, upby, flags, rest
  def _dropdb(self):
    self.dbc.execute("ABORT")
  def setUp(self):
    self.dbh = psycopg2.connect(autoreg.conf.dbstring)
    dbc = self.dbh.cursor()
    self.dbh.set_isolation_level(0)
    dbc.execute("BEGIN")
    self.dd = autoreg.dns.db.db(dbc=dbc)
    self.dd.login('DNSADMIN')
    self.dbc = dbc

  def tearDown(self):
    del self.dd
    del self.dbh
    self._dropdb()
    del self.dbc
  def _test_base(self, dom, zone, internal, val1, val2):
    zone = 'EU.ORG'
    fqdn = dom + '.' + zone
    expect_flags = []
    if internal:
      expect_flags.append('internal')
    f1 = val1
    f2 = val2
    of1 = val1 + '\n'
    if val1 != '':
      of1 = dom + of1
    of2 = val2 + '\n'
    if val2 != '':
      of2 = dom + of2
    self.dd.new(fqdn, zone, 'NS', file=cStringIO.StringIO(f1),
                internal=internal)
    self.assertRaises(autoreg.dns.db.DomainError,
                      self.dd.new, fqdn, zone, 'NS',
                      file=cStringIO.StringIO(f1))
    self.assertEqual(self._parseout(fqdn, zone),
                     (fqdn, zone,
                      '*unknown*', '*unknown*', expect_flags, of1))
    self.dd.set_registry_lock(fqdn, zone, True)
    self.assertEqual(self._parseout(fqdn, zone),
                     (fqdn, zone,
                      '*unknown*', '*unknown*',
                      ['registry_lock'] + expect_flags,
                      of1))
    self.dd.set_registry_hold(fqdn, zone, True)
    self.assertEqual((self.dd.dyn.has_actions(), dom), (val1 != self.null, dom))
    self.dd.dyn.clear()
    self.dd.set_registry_hold(fqdn, zone, True)
    self.assertEqual((self.dd.dyn.has_actions(), dom), (False, dom))
    self.assertEqual(self._parseout(fqdn, zone),
                     (fqdn, zone,
                      '*unknown*', '*unknown*',
                      ['registry_lock', 'registry_hold'] + expect_flags,
                      of1))
    self.assertRaises(autoreg.dns.db.AccessError,
                      self.dd.delete, fqdn, zone)
    self.assertRaises(autoreg.dns.db.AccessError,
                      self.dd.modify, fqdn, zone, 'NS',
                      file=cStringIO.StringIO(f2))
    self.dd.set_registry_lock(fqdn, zone, False)
    self.assertEqual(self.dd.dyn.has_actions(), False)
    self.assertEqual(self._parseout(fqdn, zone),
                     (fqdn, zone,
                      '*unknown*', '*unknown*',
                      ['registry_hold'] + expect_flags, of1))
    if internal:
      self.assertRaises(autoreg.dns.db.AccessError,
                        self.dd.modify, fqdn, zone, 'NS',
                        file=cStringIO.StringIO(f2))
      self.assertEqual(self._parseout(fqdn, zone),
                       (fqdn, zone,
                        '*unknown*', '*unknown*',
                        ['registry_hold'] + expect_flags, of1))
      self.assertRaises(autoreg.dns.db.AccessError,
                        self.dd.delete, fqdn, zone)
      self.assertEqual(self._parseout(fqdn, zone),
                       (fqdn, zone,
                        '*unknown*', '*unknown*',
                        ['registry_hold'] + expect_flags, of1))
      self.dd.modify(fqdn, zone, 'NS',
                     file=cStringIO.StringIO(f2),
                     override_internal=True)
      self.assertEqual(self._parseout(fqdn, zone),
                       (fqdn, zone,
                        '*unknown*', '*unknown*',
                        ['registry_hold'] + expect_flags, of2))
      # "Domain is held" exceptions
      self.assertRaises(autoreg.dns.db.AccessError,
                        self.dd.delete, fqdn, zone, override_internal=True)
      self.assertRaises(autoreg.dns.db.AccessError,
                        self.dd.delete, fqdn, zone, override_internal=True,
                        grace_days=0)
      self.dd.set_registry_hold(fqdn, zone, False)
      self.dd.delete(fqdn, zone, override_internal=True, grace_days=0)
    else:
      self.dd.modify(fqdn, zone, 'NS', file=cStringIO.StringIO(f2))
      self.assertEqual(self._parseout(fqdn, zone),
                       (fqdn, zone,
                        '*unknown*', '*unknown*',
                        ['registry_hold'] + expect_flags, of2))
      # "Domain is held" exceptions
      self.assertRaises(autoreg.dns.db.AccessError,
                        self.dd.delete, fqdn, zone)
      self.assertRaises(autoreg.dns.db.AccessError,
                        self.dd.delete, fqdn, zone,
                        grace_days=0)
      self.dd.set_registry_hold(fqdn, zone, False)
      self.dd.delete(fqdn, zone, grace_days=0)
    self.assertRaises(autoreg.dns.db.DomainError,
                      self.dd.delete, fqdn, zone)
  def test1(self):
    self._test_base('TEST1', 'EU.ORG', False, self.ns12, self.ns345)
  def test1i(self):
    self._test_base('TEST1I', 'EU.ORG', True, self.ns12, self.ns345)
  def test2(self):
    self._test_base('TESTGL', 'EU.ORG', False, self.glue12, self.ns345)
  def test2c(self):
    self._test_base('TESTGL', 'EU.ORG', False, self.ns345, self.glue12)
  def test2u(self):
    self._test_base('TESTGL', 'EU.ORG', False, self.glue12, self.glue12)
  def test3a(self):
    self._test_base('TESTNL', 'EU.ORG', False, self.null, self.ns12)
  def test3b(self):
    self._test_base('TESTNL', 'EU.ORG', False, self.ns12, self.null)
  def test4(self):
    dom = 'TESTGL'
    zone = 'EU.ORG'
    fqdn = dom + '.' + zone
    self.dd.new(fqdn, zone, 'NS', file=cStringIO.StringIO(self.null))
    self.dd.set_registry_hold(fqdn, zone, True)
    self.assertEqual(self.dd.dyn.has_actions(), False)
  def test5(self):
    dom = 'TESTGL'
    zone = 'EU.ORG'
    fqdn = dom + '.' + zone
    self.dd.new(fqdn, zone, 'NS', file=cStringIO.StringIO(self.ns12))
    self.assertEqual(str(self.dd.dyn),
"""nxd TESTGL None None None
add TESTGL 259200 NS NS1.EU.ORG.
add TESTGL 259200 NS NS2.EU.ORG.
""")
    self.dd.dyn.clear()
    self.dd.set_registry_hold(fqdn, zone, True)
    self.assertEqual(self.dd.dyn.has_actions(), True)
    self.assertEqual(str(self.dd.dyn),
"""yxd TESTGL None None None
del TESTGL None None None
""")
  def test6(self):
    dom = 'TESTGL'
    zone = 'EU.ORG'
    fqdn = dom + '.' + zone
    self.dd.new(fqdn, zone, 'NS', file=cStringIO.StringIO(self.ns12))
    self.assertEqual(str(self.dd.dyn),
"""nxd TESTGL None None None
add TESTGL 259200 NS NS1.EU.ORG.
add TESTGL 259200 NS NS2.EU.ORG.
""")
    self.dd.dyn.clear()
    self.dd.set_registry_hold(fqdn, zone, True)
    self.assertEqual(self.dd.dyn.has_actions(), True)
    self.assertEqual(str(self.dd.dyn),
"""yxd TESTGL None None None
del TESTGL None None None
""")
    self.dd.dyn.clear()
    self.dd.modify(fqdn, zone, 'NS', file=cStringIO.StringIO(self.ns345))
    self.assertEqual(self.dd.dyn.has_actions(), False)
    self.dd.dyn.clear()
    self.dd.set_registry_hold(fqdn, zone, False)
    self.assertEqual(self.dd.dyn.has_actions(), True)
    self.assertEqual(str(self.dd.dyn),
"""nxd TESTGL None None None
add TESTGL 259200 NS NS3.EU.ORG.
add TESTGL 259200 NS NS4.EU.ORG.
add TESTGL 259200 NS NS5.EU.ORG.
""")
  def test7addrr(self):
    dom = 'TESTGL'
    zone = 'EU.ORG'
    fqdn = dom + '.' + zone
    self.dd.new(fqdn, zone, 'NS', file=cStringIO.StringIO(self.ns12))
    self.dd.dyn.clear()
    self.dd.addrr(fqdn, zone, "", 600, "NS", "NS3.EU.ORG.")
    self.assertEqual(self.dd.dyn.has_actions(), True)
    self.dd.dyn.clear()
    self.dd.set_registry_hold(fqdn, zone, True)
    self.assertEqual(self.dd.dyn.has_actions(), True)
    self.assertEqual(str(self.dd.dyn),
"""yxd TESTGL None None None
del TESTGL None None None
""")
  def test8addrr(self):
    dom = 'TESTGL'
    zone = 'EU.ORG'
    fqdn = dom + '.' + zone
    self.dd.new(fqdn, zone, 'NS', file=cStringIO.StringIO(self.ns12))
    self.dd.set_registry_hold(fqdn, zone, True)
    self.assertEqual(self.dd.dyn.has_actions(), True)
    self.dd.dyn.clear()
    self.dd.addrr(fqdn, zone, "", 600, "NS", "NS3.EU.ORG.")
    self.assertEqual(self.dd.dyn.has_actions(), False)
    self.dd.set_registry_hold(fqdn, zone, False)
    self.assertEqual(self.dd.dyn.has_actions(), True)
    self.assertEqual(str(self.dd.dyn),
"""nxd TESTGL None None None
add TESTGL 259200 NS NS1.EU.ORG.
add TESTGL 259200 NS NS2.EU.ORG.
add TESTGL 600 NS NS3.EU.ORG.
""")
  def test8delrr(self):
    dom = 'TESTGL'
    zone = 'EU.ORG'
    fqdn = dom + '.' + zone
    self.dd.new(fqdn, zone, 'NS', file=cStringIO.StringIO(self.ns12))
    self.dd.dyn.clear()
    self.dd.delrr(fqdn, zone, "", "NS", "NS2.EU.ORG.")
    self.assertEqual(self.dd.dyn.has_actions(), True)
    self.dd.dyn.clear()
    self.dd.set_registry_hold(fqdn, zone, True)
    self.assertEqual(self.dd.dyn.has_actions(), True)
    self.assertEqual(str(self.dd.dyn),
"""nxd TESTGL None None None
add TESTGL 259200 NS NS1.EU.ORG.
add TESTGL 259200 NS NS2.EU.ORG.
add TESTGL 600 NS NS3.EU.ORG.
""")
  def test8delrr(self):
    dom = 'TESTGL'
    zone = 'EU.ORG'
    fqdn = dom + '.' + zone
    self.dd.new(fqdn, zone, 'NS', file=cStringIO.StringIO(self.ns12))
    self.dd.set_registry_hold(fqdn, zone, True)
    self.assertEqual(self.dd.dyn.has_actions(), True)
    self.dd.dyn.clear()
    self.dd.delrr(fqdn, zone, "", "NS", "NS2.EU.ORG.")
    self.assertEqual(self.dd.dyn.has_actions(), False)
    self.dd.set_registry_hold(fqdn, zone, False)
    self.assertEqual(self.dd.dyn.has_actions(), True)
    self.assertEqual(str(self.dd.dyn),
"""nxd TESTGL None None None
add TESTGL 259200 NS NS1.EU.ORG.
""")
  def test9duprr(self):
    dom = 'TESTGL'
    zone = 'EU.ORG'
    fqdn = dom + '.' + zone
    self.dd.new(fqdn, zone, 'NS', file=cStringIO.StringIO(self.null))
    self.dd.dyn.clear()
    self.dd.addrr(fqdn, zone, "", 3600, "NS", "NS2.EU.ORG.")
    self.dd.addrr(fqdn, zone, "", 3600, "NS", "NS2.EU.ORG.")
    self.assertEqual(str(self.dd.dyn),
"""add TESTGL 3600 NS NS2.EU.ORG.
add TESTGL 3600 NS NS2.EU.ORG.
""")
    self.dd.dyn.clear()
    self.dd.delrr(fqdn, zone, "", "NS", "NS2.EU.ORG.")
    self.assertEqual(self.dd.dyn.has_actions(), True)
    self.assertEqual(str(self.dd.dyn), "del TESTGL None NS NS2.EU.ORG.\n")
    of1 = dom + "			3600	NS	NS2.EU.ORG.\n\n"
    self.assertEqual(self._parseout(fqdn, zone),
                     (fqdn, zone,
                      '*unknown*', '*unknown*', [], of1))


if __name__ == '__main__':
  unittest.main()

