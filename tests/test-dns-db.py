#!/usr/local/bin/python
# $Id$

import cStringIO
import re
import os
import sys

import psycopg2

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
NS2.TESTGL			AAAA	::FFFF:10.1.2.3
"""
  def _parseout(self, d, z):
    oldstdout = sys.stdout
    fout = cStringIO.StringIO()
    sys.stdout = fout
    self.dd.show(d, z)
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
    sys.stdout = oldstdout
    return dom, zone, crby, upby, flags, rest
  def _dropdb(self):
    dbh = psycopg2.connect('dbname=template1')
    dbh.set_isolation_level(0)
    dbc = dbh.cursor()
    try:
      dbc.execute("DROP DATABASE eutest")
    #except psycopg2.ProgrammingError('database "eutest" does not exist'):
    except psycopg2.ProgrammingError:
      pass
  def setUp(self):
    self._dropdb()
    dbh = psycopg2.connect('dbname=template1')
    dbh.set_isolation_level(0)
    dbc = dbh.cursor()
    dbc.execute("CREATE DATABASE eutest WITH ENCODING='UTF-8'")
    del dbc
    del dbh
    os.system("psql eutest < ../eu.org.schema >/dev/null 2>&1")
    self.dbh = psycopg2.connect('dbname=eutest')
    dbc = self.dbh.cursor()
    dbc.execute("INSERT INTO zones (name, soaprimary, soaemail, soaserial)"
                " VALUES ('EU.ORG', 'NS.EU.ORG', 'hostmaster.eu.org',"
                "2007110600)")
    dbc.execute("INSERT INTO allowed_rr (zone_id, rrtype_id)"
                " VALUES ((SELECT id FROM zones WHERE name='EU.ORG'),"
                "(SELECT id FROM rrtypes WHERE label='NS'))")
    self.dd = autoreg.dns.db.db(self.dbh)
    self.dd.login('DNSADMIN')
  def tearDown(self):
    del self.dd
    del self.dbh
    self._dropdb()
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
      self.dd.delete(fqdn, zone, override_internal=True)
    else:
      self.dd.modify(fqdn, zone, 'NS', file=cStringIO.StringIO(f2))
      self.assertEqual(self._parseout(fqdn, zone),
                       (fqdn, zone,
                        '*unknown*', '*unknown*',
                        ['registry_hold'] + expect_flags, of2))
      self.dd.delete(fqdn, zone)
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
            
if __name__ == '__main__':
  unittest.main()

