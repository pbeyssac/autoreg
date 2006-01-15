#!/usr/local/bin/python

import sre
import sys

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
      print "Cannot parse_changed:", timeval
      raise Error
  m = int(m)
  d = int(d)
  return "%04d-%02d-%02d 00:00:00" % (y, m, d)

ripe_ltos = { 'person': 'pn', 'address': 'ad', 'tech-c': 'tc',
              'admin-c': 'ac', 'phone': 'ph', 'fax': 'fx', 'e-mail': 'em',
              'changed': 'ch', 'remark': 'rm', 'nic-hdl': 'nh',
              'notify': 'ny', 'mnt-by': 'mb', 'source': 'so',
              'upd-to': 'dt', 'auth': 'at', 'mntner': 'mt',
              'domain': 'dn' }
ripe_stol = dict((v, k) for k, v in ripe_ltos.iteritems())

domainattrs = {'dn': (1, 1), 'ad': (0,6),
               'tc': (0,3), 'ac': (1,3), 'zc': (0,3), 'ch': (1,1) }

personattrs = {'pn': (0,1), 'ad': (0,6),
               'ph': (0,1), 'fx': (0,1),
               'em': (0,1), 'ch': (1,1), 'nh': (0,1)}

def from_ripe(o, attrlist):
  for k in o:
    if not k in attrlist and not k in ['so', 'mb']:
      print o
      print "ignoring attribute %s: %s" % (k, o[k])
  for k, mm in attrlist.iteritems():
    min, max = mm
    if not k in o:
      if min > 0:
        print o
        print "missing attribute %s" % ripe_stol[k]
        raise Error
      o[k] = [ None ]
    else:
      if not (min <= len(o[k]) <= max):
        print o
        print "attribute %s found %d times, should appear %d to %d time(s)" % \
              (ripe_stol[k], len(o[k]), min, max)
        o[k] = o[k][:max]
  if len(o['ad']) < 6:
    o['ad'].extend([ None ] * (6-len(o['ad'])))

class Person:
  def __init__(self, dbc, id=None, key=None):
    self._dbc = dbc
    self.id = id
    self.key = key
    self.d = {}
  def from_ripe(self, o):
    from_ripe(o, personattrs)
    self.d = o
  def insert(self):
    o = self.d
    self._dbc.execute('INSERT INTO contacts (handle,name,email,addr1,'
                      'addr2,addr3,addr4,addr5,addr6,phone,fax,updated_on) '
                      'VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)',
                      (o['nh'][0], o['pn'][0], o['em'][0],
                       o['ad'][0], o['ad'][1], o['ad'][2],
                       o['ad'][3], o['ad'][4], o['ad'][5],
                       o['ph'][0], o['fx'][0], o['ch'][0]))
    assert self._dbc.rowcount == 1
  def fetch(self):
    assert self.id != None
    self._dbc.execute('SELECT handle,name,email,addr1,addr2,addr3,addr4,'
                      ' addr5,addr6,phone,fax,updated_on '
                      'FROM contacts WHERE id=%d', (self.id,))
    assert self._dbc.rowcount == 1
    d = {}
    (d['nic-hdl'], d['person'], d['e-mail'],
     d['addr',0], d['addr',1], d['addr',2],
     d['addr',3], d['addr',4], d['addr',5],
     d['phone'], d['fax'], d['changed']) = self._dbc.fetchone()
    self.d = d
  def display(self, title='person'):
    d = self.d
    if d['person'] != None:
	print "%-12s %s" % (title+':', d['person'])
    for i in ['nic-hdl']:
      if d.has_key(i) and d[i] != None:
        print "%-12s %s" % (i+':', d[i])
    for i in range(6):
      if d.has_key(('addr',i)) and d['addr',i] != None:
        print "address:     %s" % (d['addr',i])
    for i in ['phone', 'fax', 'e-mail', 'changed']:
      if d.has_key(i) and d[i] != None:
        print "%-12s %s" % (i+':', d[i])
  
class Domain:
  def __init__(self, dbc, id=None, fqdn=None, updated_on=None):
    self._dbc = dbc
    self.id = id
    self.fqdn = fqdn
    self.updated_on = updated_on
  def from_ripe(self, o):
    from_ripe(o, domainattrs)
    self.fqdn = o['dn'][0].upper()
    o['dn'][0] = self.fqdn
    self.d = o
  def insert(self):
    domain = self.fqdn
    o = self.d
    ambig, inval = 0, 0
    self._dbc.execute('INSERT INTO whoisdomains (fqdn,updated_on) '
                      'VALUES (%s, %s)', (domain, o['ch'][0]))
    assert self._dbc.rowcount == 1
    self._dbc.execute("SELECT currval('whoisdomains_id_seq')")
    assert self._dbc.rowcount == 1
    did, = self._dbc.fetchone()
    self.id = did

    # create domain_contact records linking to all contacts
    for i in [('tc','technical'), ('zc','zone'), ('ac','administrative')]:
      si, full = i
      if not si in o:
        continue
      for v in o[si]:
	if v == None: continue
        self._dbc.execute('INSERT INTO domain_contact '
                          '(whoisdomain_id,contact_id,contact_type_id) '
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
    if 'ad' in o:
	c['pn'] = o['ad'][:1]
	c['ad'] = o['ad'][1:]
    c['ch'] = o['ch']
    ct = Person(self._dbc)
    ct.from_ripe(c)
    ct.insert()
    self._dbc.execute("INSERT INTO domain_contact "
                      "(whoisdomain_id,contact_id,contact_type_id) "
                      "VALUES (%d,(SELECT currval('contacts_id_seq')),"
                      "(SELECT id FROM contact_types WHERE name=%s))",
                      (did, 'registrant'))
    return ambig, inval
  def get_contacts(self):
    self._dbc.execute('SELECT contact_id, contact_types.name,'
                      ' handle, contacts.name '
                      'FROM domain_contact, contact_types, contacts '
                      'WHERE contact_types.id=contact_type_id '
                      'AND contacts.id = contact_id '
                      'AND domain_contact.whoisdomain_id=%d', (self.id,))
    l = self._dbc.fetchall()
    dc = {}
    for id, type, handle, name in l:
      k = handle
      if k == None:
        k = name
      if not dc.has_key(type): dc[type] = []
      dc[type].append(Person(self._dbc, id, k))
    self.dc = dc
    return dc
  def display(self):
    print "%-12s %s" % ('domain:', self.fqdn)
    reg = self.dc['registrant'][0]
    reg.fetch()
    reg.display('address')
    for k, l in [('technical','tech-c'),
                 ('administrative','admin-c'),
                 ('zone','zone-c')]:
      if not (k in self.dc):
        continue
      for c in self.dc[k]:
        print "%-12s %s" % (l+':', c.key)

class Lookup:
  def __init__(self, dbc):
    self._dbc = dbc
  def _makelist(self):
    l = []
    for t in self._dbc.fetchall():
      id, = t
      l.append(Person(self._dbc, id))
    return l
  def persons_by_handle(self, handle):
    self._dbc.execute('SELECT id FROM contacts WHERE handle=%s',
                      (handle.upper(),))
    return self._makelist()
  def persons_by_name(self, name):
    self._dbc.execute('SELECT id FROM contacts WHERE lower(name)=%s',
                      (name.lower(),))
    return self._makelist()
  def domain_by_name(self, name):
    name = name.upper()
    self._dbc.execute('SELECT id, updated_on FROM whoisdomains WHERE fqdn=%s',
                      (name,))
    if self._dbc.rowcount == 0:
      return None
    assert self._dbc.rowcount == 1
    id, upon = self._dbc.fetchone()
    return Domain(self._dbc, id, name, upon)
  
class Main:
  comment_re = sre.compile('^\s*#')
  white_re = sre.compile('^\s*$')
  empty_re = sre.compile('^$')
  longattr_re = sre.compile('^([a-z-]+):\s*(.*\S)\s*$')
  shortattr_re = sre.compile('^\*([a-zA-Z][a-zA-Z]):\s*(.*\S)\s*$')
  def __init__(self, dbc):
    self.dom = {}
    self.ndom = 0
    self.nperson = 0
    self._dbc = dbc
    self.ambig = 0
    self.inval = 0
  def process(self, o):
    if o.has_key('XX'):
      # deleted object, ignore
      return
    if o.has_key('ch'):
	for i in range(len(o['ch'])):
	    o['ch'][i] = parse_changed(o['ch'][i])
    if o.has_key('dn'):
      # domain object
      self.dom[o['dn'][0].upper()] = o
      self.ndom += 1
    elif o.has_key('pn'):
      # person object
      assert o.has_key('em')
      self.nperson += 1
      ct = Person(self._dbc)
      ct.from_ripe(o)
      ct.insert()
    elif o.has_key('mt'):
      # maintainer object, ignore
      pass
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
        self.process(o)
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
        if not ripe_ltos.has_key(a):
          raise Error
        a = self.ripe_ltos[a]
      if o.has_key(a):
        o[a].append(v)
      else:
        o[a] = [v]
    if len(o):
      # end of file: insert last object
      self.process(o)
    # now that contacts are ready to be used, insert domain_contact records
    # from the domain list we gathered.
    for i in sorted(self.dom.keys()):
      wd = Domain(self._dbc)
      wd.from_ripe(self.dom[i])
      ambig, inval = wd.insert()
      self.ambig += ambig
      self.inval += inval
    print "Domains:", self.ndom
    print "Persons:", self.nperson
    print "Ambiguous contacts:", self.ambig
    print "Invalid contacts:", self.inval
    del self.dom
