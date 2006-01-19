#!/usr/local/bin/python

import sre
import sys

import mx

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
  return mx.DateTime.DateTime(y, m, d)

ripe_ltos = { 'person': 'pn', 'address': 'ad', 'tech-c': 'tc',
              'admin-c': 'ac', 'phone': 'ph', 'fax': 'fx', 'e-mail': 'em',
              'changed': 'ch', 'remark': 'rm', 'nic-hdl': 'nh',
              'notify': 'ny', 'mnt-by': 'mb', 'source': 'so',
              'upd-to': 'dt', 'auth': 'at', 'mntner': 'mt',
              'domain': 'dn' }
ripe_stol = dict((v, k) for k, v in ripe_ltos.iteritems())

domainattrs = {'dn': (1, 1), 'ad': (0,7),
               'tc': (0,3), 'ac': (1,3), 'zc': (0,3), 'ch': (1,1) }

personattrs = {'pn': (0,1), 'ad': (0,6),
               'ph': (0,1), 'fx': (0,1),
               'em': (0,1), 'ch': (1,1), 'nh': (0,1)}

contact_map = { 'technical': 'tc', 'administrative': 'ac', 'zone': 'zc',
                'registrant': 'rc' }
contact_map_rev = dict((v, k) for k, v in contact_map.iteritems())

def from_ripe(o, attrlist):
  # find ignored attributes, warn
  dlist = []
  for k in o:
    if not k in attrlist:
      dlist.append(k)
      if not k in ['so', 'mb']:
        print o
        print "ignoring attribute %s: %s" % (k, o[k])
  # cleanup ignored attributes
  for k in dlist:
    del o[k]
  # check attribute constraints
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
  def _set_key(self):
    if self.d['nh'][0] != None:
      self.key = self.d['nh'][0]
    else:
      self.key = self.d['pn'][0]
  def from_ripe(self, o):
    from_ripe(o, personattrs)
    self.d = o
    self._set_key()
  def insert(self, fetchid=False):
    o = self.d
    self._dbc.execute('INSERT INTO contacts (handle,name,email,addr1,'
                      'addr2,addr3,addr4,addr5,addr6,phone,fax,updated_on) '
                      'VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)',
                      (o['nh'][0], o['pn'][0], o['em'][0],
                       o['ad'][0], o['ad'][1], o['ad'][2],
                       o['ad'][3], o['ad'][4], o['ad'][5],
                       o['ph'][0], o['fx'][0], str(o['ch'][0])))
    assert self._dbc.rowcount == 1
    if fetchid:
      self._dbc.execute("SELECT currval('contacts_id_seq')")
      self.id, = self._dbc.fetchone()
      assert self._dbc.rowcount == 1
  def update(self):
    assert self.id != None
    o = self.d
    self._dbc.execute('UPDATE contacts SET handle=%s,name=%s,email=%s,'
                      'addr1=%s,addr2=%s,addr3=%s,addr4=%s,addr5=%s,addr6=%s,'
                      'phone=%s,fax=%s,updated_on=%s '
                      'WHERE id=%d',
                      (o['nh'][0], o['pn'][0], o['em'][0],
                       o['ad'][0], o['ad'][1], o['ad'][2],
                       o['ad'][3], o['ad'][4], o['ad'][5],
                       o['ph'][0], o['fx'][0], str(o['ch'][0]), self.id))
    assert self._dbc.rowcount == 1
  def fetch(self):
    assert self.id != None
    self._dbc.execute('SELECT handle,name,email,addr1,addr2,addr3,addr4,'
                      ' addr5,addr6,phone,fax,updated_on '
                      'FROM contacts WHERE id=%d', (self.id,))
    assert self._dbc.rowcount == 1
    d = {}
    (d['nh'], d['pn'], d['em'],
     addr1, addr2, addr3, addr4, addr5, addr6,
     d['ph'], d['fx'], d['ch']) = self._dbc.fetchone()
    for k in d.keys():
      d[k] = [ d[k] ]
    d['ad'] = [ addr1, addr2, addr3, addr4, addr5, addr6 ]
    self.d = d
    self._set_key()
  def display(self, title='person'):
    d = self.d
    for i in ['pn', 'nh', 'ad', 'ph', 'fx', 'em', 'ch']:
      if i == 'pn':
        l = title
      else:
        l = ripe_stol[i]
      for j in d[i]:
        if j != None:
          print "%-12s %s" % (l+':', j)
  
class Domain:
  def __init__(self, dbc, id=None, fqdn=None, updated_on=None):
    d = {}
    self._dbc = dbc
    if fqdn != None:
      d['dn'] = [ fqdn.upper() ]
    if updated_on != None:
      d['ch'] = [ updated_on ]
    self.d = d
    self.id = id
  def from_ripe(self, o):
    from_ripe(o, domainattrs)
    o['dn'][0] = o['dn'][0].upper()
    # Create a "registrant" contact, storing the address lines
    # of the RIPE-style domain object.
    c = {}
    if 'ad' in o:
	c['pn'] = o['ad'][:1]
	c['ad'] = o['ad'][1:]
        del o['ad']
    c['ch'] = o['ch']
    self.d = o
    self.ct = Person(self._dbc)
    self.ct.from_ripe(c)
    return self.resolve_contacts()
  def update(self):
    o = self.d
    assert self.id != None
    self._dbc.execute('UPDATE whoisdomains SET updated_on=NOW() WHERE id=%d',
                      (self.id,))
    print self.id
    print self._dbc.rowcount
    assert self._dbc.rowcount == 1
    # XXX: the line below assumes registrant contacts are not shared.
    # We'll get rid of this assumption when we drop the RIPE model.
    self.ct.update()
    self._dbc.execute('DELETE FROM domain_contact WHERE whoisdomain_id=%d',
                      (self.id,))
    self.insert_domain_contact()
  def insert_domain_contact(self):
    """Create domain_contact records linking to all contacts."""
    o = self.d
    for i in [('tc','technical'), ('zc','zone'), ('ac','administrative')]:
      si, full = i
      if not si in o:
        continue
      for v in o[si]:
	if v == None: continue
        self._dbc.execute('INSERT INTO domain_contact '
                          '(whoisdomain_id,contact_id,contact_type_id) '
                          'VALUES (%d,%d,'
                          ' (SELECT id FROM contact_types WHERE name=%s))',
                          (self.id, v, full))
        assert self._dbc.rowcount == 1
    self.ct.insert(fetchid=True)
    self._dbc.execute("INSERT INTO domain_contact "
                      "(whoisdomain_id,contact_id,contact_type_id) "
                      "VALUES (%d,%d,"
                      "(SELECT id FROM contact_types WHERE name=%s))",
                      (self.id, self.ct.id, 'registrant'))
    assert self._dbc.rowcount == 1
  def insert(self):
    o = self.d
    domain = o['dn'][0]
    self._dbc.execute('INSERT INTO whoisdomains (fqdn,updated_on) '
                      'VALUES (%s, %s)', (domain, str(o['ch'][0])))
    assert self._dbc.rowcount == 1
    self._dbc.execute("SELECT currval('whoisdomains_id_seq')")
    assert self._dbc.rowcount == 1
    did, = self._dbc.fetchone()
    self.id = did
    self.insert_domain_contact()
  def fetch(self):
    self._dbc.execute('SELECT fqdn, updated_on '
                      'FROM whoisdomains WHERE id=%d', (self.id,))
    assert self._dbc.rowcount == 1
    d = {}
    dn, ch = self._dbc.fetchone()
    d['dn'] = [ dn ]
    d['ch'] = [ ch ]
    self.d = d
    self.fetch_contacts()
    assert len(d['rc']) == 1
    ct = Person(self._dbc, id=d['rc'][0])
    del d['rc']
    ct.fetch()
    self.ct = ct
  def fetch_contacts(self):
    d = self.d
    self._dbc.execute('SELECT contact_id,contact_types.name '
                      'FROM domain_contact, contact_types '
                      'WHERE whoisdomain_id=%d '
                      'AND contact_types.id=contact_type_id', (self.id,))
    for k in 'tc', 'zc', 'ac', 'rc':
      d[k] = []
    l = self._dbc.fetchall()
    for id, type in l:
      cm = contact_map[type]
      d[cm].append(id)
    for k in 'tc', 'zc', 'ac', 'rc':
      d[k].sort()
    self.d = d
  def resolve_contacts(self):
    ambig, inval = 0, 0
    newd = {}
    for k in 'tc', 'zc', 'ac':
      newd[k] = [ ]
      for l in self.d[k]:
        if l == None: continue
        self._dbc.execute('SELECT id FROM contacts '
                          'WHERE (lower(contacts.name)=%s OR handle=%s) '
                          ' AND email IS NOT NULL',
                          (l.lower(), l.upper()))
        # check the returned number of found lines and
        # issue an approriate warning message if it differs from 1.
        if self._dbc.rowcount == 0:
          print "Invalid contact '%s' for domain %s" % (l, self.d['dn'][0])
          inval += 1
        elif self._dbc.rowcount > 1:
          print "Ambiguous contact '%s' for domain %s" % (l, self.d['dn'][0])
          ambig += 1
        lid = self._dbc.fetchall()
        for id, in lid:
          newd[k].append(id)
    for k in 'tc', 'zc', 'ac':
      newd[k].sort()
    self.d.update(newd)
    return ambig, inval
  def get_contacts(self):
    self.fetch_contacts()
    dc = {}
    for k in 'tc', 'zc', 'ac':
      type = contact_map_rev[k]
      dc[type] = []
      for id in self.d[k]:
        dc[type].append(Person(self._dbc, id))
    return dc
  def display(self):
    print "%-12s %s" % ('domain:', self.d['dn'][0])
    reg = Person(self._dbc, self.d['rc'][0])
    reg.fetch()
    reg.display('address')
    for t, l in [('tc','tech-c'),
                 ('ac','admin-c'),
                 ('zc','zone-c')]:
      if not (t in self.d):
        continue
      for c in self.d[t]:
        p = Person(self._dbc, c)
        p.fetch()
        print "%-12s %s" % (l+':', p.key)

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
    self._lookup = Lookup(dbc)
  def insert(self, o):
    if o.has_key('XX'):
      # deleted object, ignore
      return
    if o.has_key('ch'):
	for i in range(len(o['ch'])):
	    o['ch'][i] = parse_changed(o['ch'][i])
    if o.has_key('dn'):
      # domain object
      from_ripe(o, domainattrs)
      self.dom[o['dn'][0].upper()] = o
      self.ndom += 1
    elif o.has_key('pn'):
      # person object
      self.nperson += 1
      ct = Person(self._dbc)
      ct.from_ripe(o)
      if 'nh' in o and o['nh'][0] != None:
        # has a NIC handle, try to find if already in the base
        handle = o['nh'][0]
        lp = self._lookup.persons_by_handle(handle)
        assert len(lp) <= 1
        if len(lp) == 1:
          # found, compare
          lp[0].fetch()
          if lp[0].d != o:
            print "nic-hdl:", handle, "differ"
            print "old=", lp[0].d
            print "new=", o
            lp[0].d = o
            lp[0].update()
        else:
          # not found, simply insert
          ct.insert()
      else:
        assert 'pn' in o and o['pn'] != None
        # no handle, try to find by name
        name = o['pn'][0]
        lp = self._lookup.persons_by_name(name)
        if len(lp) == 0:
          # not found, insert
          ct.insert()
        else:
          for c in lp:
            c.fetch()
            # skip person objets with a NIC handle
            if c.d['nh'][0] != None:
              continue
            if c.d == o:
              # found, stop
              break
          else:
            # not found, insert
            print "No handle and not found by name"
            print "new=", o
            ct.insert()
    elif o.has_key('mt'):
      # maintainer object, ignore
      pass
    elif o.has_key('XX'):
      # deleted object, ignore
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
        if not ripe_ltos.has_key(a):
          raise Error
        a = ripe_ltos[a]
      if o.has_key(a):
        o[a].append(v)
      else:
        o[a] = [v]
    if len(o):
      # end of file: insert last object
      self.insert(o)
    # now that contacts are ready to be used, insert domain_contact records
    # from the domain list we gathered.
    for i in sorted(self.dom.keys()):
      ld = self._lookup.domain_by_name(i)
      if ld != None:
        ld.fetch()
        newdom = Domain(self._dbc, ld.id)
        newdom.from_ripe(self.dom[i])
        if ld.d != newdom.d or ld.ct.d['ad'] != newdom.ct.d['ad']:
          print "Update for", i, "to be done"
          print "ld.d=", ld.d
          print "dom.d=", newdom.d
          print "ld.ct.d=", ld.ct.d
          print "dom.ct.d=", newdom.ct.d
          newdom.ct.id = ld.ct.id
          newdom.update()
      else:
        ld = Domain(self._dbc)
        ambig, inval = ld.from_ripe(self.dom[i])
        ld.insert()
        self.ambig += ambig
        self.inval += inval
    print "Domains:", self.ndom
    print "Persons:", self.nperson
    print "Ambiguous contacts:", self.ambig
    print "Invalid contacts:", self.inval
    del self.dom
