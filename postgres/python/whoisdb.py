#!/usr/local/bin/python

import sre
import sys

import dnsdb

_tv6 = sre.compile('^\S+\s*(\d\d)(\d\d)(\d\d)$')
_tv8 = sre.compile('^\S+\s*(\d\d\d\d)(\d\d)(\d\d)$')

def parse_changed(timeval):
  ma = _tv6.search(timeval)
  if ma:
    y, m, d = ma.groups()
    y = int(y)
    if y > 50:
      y += 1900
    else:
      y += 2000
  else:
    ma = _tv8.search(timeval)
    if ma:
      y, m, d = ma.groups()
      y = int(y)
    else:
      raise Error
  m = int(m)
  d = int(d)
  return "%04d-%02d-%02d 00:00:00" % (y, m, d)

class Person:
  def __init__(self, dbc):
    self._dbc = dbc
  
  def insert(self, o):
    print "insert person:"
    print o
    for i in [('nh',0), ('em',0),
              ('ad',0), ('ad',1), ('ad',2), ('ad',3), ('ad',4), ('ad',5),
              ('ph',0), ('fx',0)]:
      if not o.has_key(i):
        o[i] = None
    self._dbc.execute('INSERT INTO contacts (handle,name,email,addr1,'
                      'addr2,addr3,addr4,addr5,addr6,phone,fax,updated_on) '
                      'VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)',
                      (o['nh',0], o['pn',0], o['em',0],
                       o['ad',0], o['ad',1], o['ad',2],
                       o['ad',3], o['ad',4], o['ad',5],
                       o['ph',0], o['fx',0], parse_changed(o['ch',0])))

class Domain:
  def __init__(self, dbc):
    self._dbc = dbc
    self.zl = dnsdb._ZoneList(dbc)
    self.ct = Person(dbc)
  def insert(self, o):
    domain = o['dn',0].upper()
    ambig, inval = 0, 0
    print "insert domain:"
    print o
    # initialize missing attributes
    for i in ['ad', 'tc', 'zc', 'ac']:
      for j in range(10):
        if not o.has_key((i, j)):
          o[i, j] = None
    # find domain and zone
    d, z = self.zl.find(domain, None, raise_nf=False)
    if d == None:
      d, z = self.zl.find(domain, '', raise_nf=False)
    assert z != None
    if d == None:
      # not found, insert "dummy" domain
      print "Domain %s not handled, inserting as dummy domain" % domain
      self._dbc.execute('INSERT INTO domains (name,zone_id) VALUES (%s, %d)',
                        (domain, z.id))
      self._dbc.execute("SELECT currval('domains_id_seq'")
      assert self._dbc.rowcount == 1
      did, = self._dbc.fetchone()
    else:
      did = d.id

    # create domain_contact records linking to all contacts
    for i in [('tc','technical'), ('zc','zone'), ('ac','administrative')]:
      si, full = i
      for j in range(10):
        if not o.has_key((si,j)):
          break
        v = o[si,j]
        if v == None:
          break
        self._dbc.execute('INSERT INTO domain_contact '
                          '(domain_id,contact_id,contact_type_id) '
                          ' (SELECT %d,id,'
                          '  (SELECT id FROM contact_types WHERE name=%s) '
                          ' FROM contacts WHERE (lower(name)=%s OR handle=%s) '
                          ' AND email IS NOT NULL)',
                          (did, full, v.lower(), v.upper()))
        # check the returned number of inserted lines and
        # issue an approriate warning message if it differs from 1.
        if self._dbc.rowcount == 0:
          print "Invalid contact '%s' for domain %s" % (v, domain)
          inval += 1
        elif self._dbc.rowcount > 1:
          print "Ambiguous contact '%s' for domain %s" % (v, domain)
          ambig += 1
    # Create a "registrant" contact, storing the address lines
    # of the RIPE-style domain object.
    c = {}
    c['pn',0] = o['ad',0]
    c['em',0] = None
    for k in range(6):
      c['ad',k] = o['ad',k+1]
    c['ph',0] = None
    c['fx',0] = None
    c['ch',0] = o['ch',0]
    self.ct.insert(c)
    self._dbc.execute("INSERT INTO domain_contact "
                      "(domain_id,contact_id,contact_type_id) "
                      "VALUES (%d,(SELECT currval('contacts_id_seq')),"
                      "(SELECT id FROM contact_types WHERE name=%s))",
                      (did, 'registrant'))
    return ambig, inval
    
class Main:
  shorts = { 'person': 'pn', 'address': 'ad', 'tech-c': 'tc',
             'admin-c': 'ac', 'phone': 'ph', 'fax': 'fx', 'e-mail': 'em',
             'changed': 'ch', 'remark': 'rm', 'nic-hdl': 'nh',
             'notify': 'ny', 'mnt-by': 'mb', 'source': 'so',
             'upd->to': 'dt', 'auth': 'at', 'mntner': 'mt',
             'domain': 'dn' }
  comment_re = sre.compile('^\s*#')
  white_re = sre.compile('^\s*$')
  empty_re = sre.compile('^$')
  longattr_re = sre.compile('^([a-z-]+):\s*(.*\S)\s*$')
  shortattr_re = sre.compile('^\*([a-zA-Z][a-zA-Z]):\s*(.*\S)\s*$')
  def __init__(self, dbc):
    self.dom = {}
    self.ndom = 0
    self.nperson = 0
    self.ct = Person(dbc)
    self._dbc = dbc
    self.ambig = 0
    self.inval = 0
  def insert(self, o):
    if o.has_key(('dn',0)):
      # domain object
      print "insert domain", o['dn', 0].upper(), "=> postponed"
      self.dom[o['dn',0].upper()] = o
      self.ndom += 1
    elif o.has_key(('pn',0)):
      assert o.has_key(('em',0))
      self.nperson += 1
      self.ct.insert(o)
    elif o.has_key(('mt',0)):
      # maintainer object, ignore
      print "maintainer, skip"
    elif o.has_key(('XX',0)):
      print "deleted, skip"
      # deleted object, ignore
    else:
      print >>sys.stderr, "Unknown object type"
      print str(o)

  def parsefile(self, file):
    o = {}
    for l in file:
      if self.comment_re.search(l):
        # skip comment
        continue
      if self.white_re.search(l) and len(o):
        # white line or empty line and o is not empty:
        # end of object, insert then cleanup for next object.
        self.insert(o)
        o = {}
        continue
      if self.empty_re.search(l):
        # empty line, no object in progress: skip
        continue
      m = self.shortattr_re.search(l)
      if m:
        a, v = m.groups()
      else:
        m = self.longattr_re.search(l)
        assert m
        a, v = m.groups()
        if not shorts.has_key(a):
          raise Error
        a = self.shorts[a]
      for i in range(10):
        if not o.has_key((a, i)):
          o[a, i] = v
          break
      else:
        raise Error
    if len(o):
      # end of file: insert last object
      self.insert(o)
    # now that contacts are ready to be used, insert domain_contact records
    # from the domain list we gathered.
    wd = Domain(self._dbc)
    for i in sorted(self.dom.keys()):
      ambig, inval = wd.insert(self.dom[i])
      self.ambig += ambig
      self.inval += inval
    print "Domains:", self.ndom
    print "Persons:", self.nperson
    print "Ambiguous contacts:", self.ambig
    print "Invalid contacts:", self.inval
    del self.dom
