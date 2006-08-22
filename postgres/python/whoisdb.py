#!/usr/local/bin/python

import sre

import mx

handlesuffix = '-FREE'

_tv6 = sre.compile('^(\S+)\s*(\d\d)(\d\d)(\d\d)$')
_tv8 = sre.compile('^(\S+)\s*(\d\d\d\d)(\d\d)(\d\d)$')

def parse_changed(changed):
  """Parse a RIPE-style changed: line."""
  ma = _tv6.search(changed)
  if ma:
    email, y, m, d = ma.groups()
    y = int(y)
    if y > 50:
      y += 1900
    else:
      y += 2000
  else:
    ma = _tv8.search(changed)
    if ma:
      email, y, m, d = ma.groups()
      y = int(y)
    else:
      print "Cannot parse_changed:", changed
      return None, None
  m = int(m)
  d = int(d)
  return email, mx.DateTime.DateTime(y, m, d)

def addrmake(a):
  """Make a newline-separated string from a list."""
  ta = ''
  for l in a:
    if l != None:
      ta += l + '\n'
  return ta

def addrsplit(ta):
  """Make a None-padded list of length 6 from a newline-separated string."""
  if ta.endswith('\n'):
    ta = ta[:-1]
  a = ta.split('\n')
  for i in range(len(a)):
    if a[i] == '': a[i] = None
  while len(a) < 6:
    a.append(None)
  return a

_lhandlesuffix = len(handlesuffix)

def suffixadd(h):
  return h + handlesuffix
def suffixstrip(h):
  return h[:-_lhandlesuffix]

ripe_ltos = { 'person': 'pn', 'address': 'ad', 'tech-c': 'tc',
              'admin-c': 'ac', 'phone': 'ph', 'fax': 'fx', 'e-mail': 'em',
              'changed': 'ch', 'remark': 'rm', 'nic-hdl': 'nh',
              'notify': 'ny', 'mnt-by': 'mb', 'source': 'so',
              'upd-to': 'dt', 'auth': 'at', 'mntner': 'mt',
              'domain': 'dn', 'ext-hdl': 'eh' }
ripe_stol = dict((v, k) for k, v in ripe_ltos.iteritems())

domainattrs = {'dn': (1, 1), 'ad': (0,7),
               'tc': (0,3), 'ac': (1,3), 'zc': (0,3), 'ch': (1,1) }

personattrs = {'pn': (0,1), 'ad': (0,6),
               'ph': (0,1), 'fx': (0,1),
               'em': (0,1), 'ch': (1,1), 'nh': (0,1), 'eh': (0, 1)}

contact_map = { 'technical': 'tc', 'administrative': 'ac', 'zone': 'zc',
                'registrant': 'rc' }
contact_map_rev = dict((v, k) for k, v in contact_map.iteritems())

def from_ripe(o, attrlist):
  """Check and convert from RIPE-style attributes."""
  # find ignored attributes, warn
  dlist = []
  for k in o:
    if not k in attrlist:
      dlist.append(k)
      if not k in ['so', 'mb']:
        print "Ignoring attribute %s: %s" % (k, o[k])
  # cleanup ignored attributes
  for k in dlist:
    del o[k]
  # move foreign NIC handle out of the way
  if 'nh' in o:
    if o['nh'][0].endswith(handlesuffix):
      o['nh'][0] = suffixstrip(o['nh'][0])
    else:
      o['eh'] = o['nh']
      del o['nh']
  # check attribute constraints
  ok = True
  for k, mm in attrlist.iteritems():
    minl, maxl = mm
    if not k in o:
      if minl > 0:
        print "Missing attribute %s" % ripe_stol[k]
	ok = False
      o[k] = [ None ]
    else:
      if not (minl <= len(o[k]) <= maxl):
        print "Attribute %s found %d times, should appear %d to %d time(s)" % \
              (ripe_stol[k], len(o[k]), minl, maxl)
        o[k] = o[k][:maxl]
  if len(o['ad']) < 6:
    o['ad'].extend([ None ] * (6-len(o['ad'])))
  return ok

_skipalnum = sre.compile('^[a-zA-Z0-9]+\s*(.*)')
_skipword = sre.compile('^\S+\s+(.*)')

def mkinitials(name):
  h = ''
  while len(h) < 3:
    if not name:
      break
    if 'A' <= name[0] <= 'Z':
      h += name[0]
    elif 'a' <= name[0] <= 'z':
      h += name[0].upper()
    else:
      name = name[1:]
      continue
    ma = _skipalnum.search(name)
    if not ma:
      ma = _skipword.search(name)
    if not ma:
      break
    name, = ma.groups()
  if h == '':
    h = 'ZZZ'
  return h

class _whoisobject(object):
  def __cmp__(self, other):
    """Customized compare function:
	- ignore 'ch' entries
	- case-insensitive compare on 'pn'
    """
    if not isinstance(other, type(self)):
      return id(self).__cmp__(id(other))
    d1 = self.d.copy()
    d2 = other.d.copy()
    del d1['ch']
    del d2['ch']
    if 'pn' in d1 and 'pn' in d2:
      d1['pn'] = [ d1['pn'][0].lower() ]
      d2['pn'] = [ d2['pn'][0].lower() ]
    return d1.__cmp__(d2)

class Person(_whoisobject):
  def __init__(self, dbc, id=None, key=None):
    self._dbc = dbc
    self.id = id
    self.key = key
    self.d = {}
  def _set_key(self):
    if self.d['nh'][0] != None:
      self.key = suffixadd(self.d['nh'][0])
    else:
      self.key = self.d['pn'][0]
  def from_ripe(self, o):
    """Fill from RIPE-style attributes."""
    if not from_ripe(o, personattrs):
      return False
    self.d = o
    self._set_key()
    return True
  def _allocate_handle(self):
    """Allocate ourselves a handle if we lack one."""
    if (not 'nh' in self.d) or self.d['nh'][0] == None:
      l = mkinitials(self.d['pn'][0])

      # Find the highest allocated handle with the same initials
      self._dbc.execute("SELECT CAST(SUBSTRING(handle FROM '[0-9]+') AS INT)"
			" FROM contacts WHERE handle SIMILAR TO '%s[0-9]+'"
			" ORDER BY CAST(SUBSTRING(handle FROM '[0-9]+') AS INT)"
			" DESC LIMIT 1" % (l,))
      assert 0 <= self._dbc.rowcount <= 1
      if self._dbc.rowcount == 0:
        i = 1
      else:
        i, = self._dbc.fetchone()
        i += 1
      h = "%s%d" % (l, i)
      id = self.id
      self.key = suffixadd(h)
      self.d['nh'] = [ h ]
      #print "Allocated handle", self.key, "for", self.d['pn'][0]
  def insert(self):
    """Create in database."""
    self._allocate_handle()
    o = self.d
    self._dbc.execute('INSERT INTO contacts (handle,exthandle,name,email,'
                      'addr,phone,fax,updated_by,updated_on) '
                      'VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)',
                      (o['nh'][0],o['eh'][0],o['pn'][0], o['em'][0],
                       addrmake(o['ad']), o['ph'][0], o['fx'][0],
                       o['ch'][0][0], str(o['ch'][0][1])))
    assert self._dbc.rowcount == 1
    self._dbc.execute("SELECT currval('contacts_id_seq')")
    self.id, = self._dbc.fetchone()
    assert self._dbc.rowcount == 1
  def _copyrecord(self):
    """Copy record to history."""
    assert self.id != None
    self._dbc.execute('SELECT * FROM contacts WHERE id=%d FOR UPDATE',
                      (self.id,))
    assert self._dbc.rowcount == 1
    self._dbc.execute('INSERT INTO contacts_hist '
                      ' (contact_id,handle,exthandle,name,email,addr,'
                      '  phone,fax,passwd,updated_by,updated_on,deleted_on)'
                      ' SELECT id,handle,exthandle,name,email,addr,'
                      '  phone,fax,passwd,updated_by,updated_on,NOW()'
                      ' FROM contacts WHERE id=%d', (self.id,))
    assert self._dbc.rowcount == 1
  def _update(self):
    """Write back to database."""
    o = self.d
    self._dbc.execute('UPDATE contacts SET handle=%s,exthandle=%s,'
		      'name=%s,email=%s,'
                      'addr=%s,phone=%s,fax=%s,updated_by=%s,updated_on=%s '
                      'WHERE id=%d',
                      (o['nh'][0], o['eh'][0], o['pn'][0], o['em'][0],
                       addrmake(o['ad']), o['ph'][0], o['fx'][0],
                       o['ch'][0][0], str(o['ch'][0][1]), self.id))
    assert self._dbc.rowcount == 1
  def update(self):
    """Write back to database, keeping history."""
    self._copyrecord()
    self._update()
  def delete(self):
    """Delete from database, keeping history."""
    self._copyrecord()
    self._dbc.execute('DELETE contacts WHERE id=%d', (self.id,))
    assert self._dbc.rowcount == 1
  def fetch(self):
    """Read from database."""
    assert self.id != None
    self._dbc.execute('SELECT handle,exthandle,name,email,addr,'
                      ' phone,fax,updated_by,updated_on '
                      'FROM contacts WHERE id=%d', (self.id,))
    assert self._dbc.rowcount == 1
    d = {}
    (d['nh'], d['eh'], d['pn'], d['em'],
     addr,
     d['ph'], d['fx'], chb, cho) = self._dbc.fetchone()
    for k in d.keys():
      d[k] = [ d[k] ]
    d['ad'] = addrsplit(addr)
    d['ch'] = [ (chb, cho) ]
    self.d = d
    self._set_key()
  def display(self, title='person', embed=False):
    """Display contact, RIPE-style.
       embed selects display within domain for a registrant contact.
    """
    d = self.d
    for i in ['pn', 'nh', 'eh', 'ad', 'ph', 'fx', 'em', 'ch']:
      if i == 'pn':
        l = title
      elif i in ['nh', 'eh'] and embed:
	continue
      else:
        l = ripe_stol[i]
      for j in d[i]:
        if i == 'ch':
          j = "%s %s" % j
        elif i == 'nh':
	  j = suffixadd(j)
        if j != None:
          print "%-12s %s" % (l+':', j)
    if not embed:
      print
  
class Domain(_whoisobject):
  def __init__(self, dbc, id=None, fqdn=None,
               updated_by=None, updated_on=None):
    d = {}
    self._dbc = dbc
    if fqdn != None:
      d['dn'] = [ fqdn.upper() ]
    if updated_on != None:
      d['ch'] = [ (updated_by, updated_on) ]
    self.d = d
    self.id = id
  def from_ripe(self, o, prefs=None):
    """Fill from RIPE-style attributes."""
    if not from_ripe(o, domainattrs):
      return None
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
    if not self.ct.from_ripe(c):
      return None
    return self.resolve_contacts(prefs)
  def _copyrecords(self):
    """Copy record to history."""
    self._dbc.execute('INSERT INTO domain_contact_hist'
                      ' (whoisdomain_id,contact_id,contact_type_id,'
                      '  created_on,deleted_on)'
                      ' SELECT whoisdomain_id,contact_id,contact_type_id,'
                      '  created_on,NOW()'
                      '  FROM domain_contact WHERE whoisdomain_id=%d',
                      (self.id,))
  def update(self):
    """Write back to database, keeping history."""
    assert self.id != None
    self._dbc.execute('SELECT * FROM whoisdomains WHERE id=%d FOR UPDATE',
                      (self.id,))
    assert self._dbc.rowcount == 1
    self._dbc.execute('UPDATE whoisdomains SET updated_on=NOW() WHERE id=%d',
                      (self.id,))
    assert self._dbc.rowcount == 1
    # XXX: the line below assumes registrant contacts are not shared.
    # We'll get rid of this assumption when we drop the RIPE model.
    self.ct.update()
    self._copyrecords()
    self._dbc.execute('DELETE FROM domain_contact WHERE whoisdomain_id=%d',
                      (self.id,))
    self._insert_domain_contact()
  def delete(self):
    """Delete from database, keeping history."""
    assert self.id != None
    self._dbc.execute('SELECT * FROM whoisdomains WHERE id=%d FOR UPDATE',
                      (self.id,))
    assert self._dbc.rowcount == 1
    self._copyrecords()
    self._dbc.execute('DELETE FROM domain_contact WHERE whoisdomain_id=%d',
                      (self.id,))
    self._dbc.execute('INSERT INTO whoisdomains_hist '
                      ' (whoisdomain_id,fqdn,created_on,deleted_on)'
                      ' SELECT id,fdqn,created_on,NOW()'
                      ' FROM whoisdomains WHERE whoisdomain_id=%d',
                      (self.id,))
    assert self._dbc.rowcount == 1
    self._dbc.execute('DELETE FROM whoisdomains WHERE id=%d',
                      (self.id,))
    assert self._dbc.rowcount == 1
  def _insert_domain_contact(self):
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
    self.ct.insert()
    self._dbc.execute("INSERT INTO domain_contact "
                      "(whoisdomain_id,contact_id,contact_type_id) "
                      "VALUES (%d,%d,"
                      "(SELECT id FROM contact_types WHERE name=%s))",
                      (self.id, self.ct.id, 'registrant'))
    assert self._dbc.rowcount == 1
  def insert(self):
    """Create in database."""
    o = self.d
    domain = o['dn'][0]
    self._dbc.execute('INSERT INTO whoisdomains (fqdn,updated_by,updated_on) '
                      'VALUES (%s, %s,%s)',
                      (domain, o['ch'][0][0], str(o['ch'][0][1])))
    assert self._dbc.rowcount == 1
    self._dbc.execute("SELECT currval('whoisdomains_id_seq')")
    assert self._dbc.rowcount == 1
    did, = self._dbc.fetchone()
    self.id = did
    self._insert_domain_contact()
  def fetch(self):
    self._dbc.execute('SELECT fqdn, updated_by, updated_on '
                      'FROM whoisdomains WHERE id=%d', (self.id,))
    assert self._dbc.rowcount == 1
    d = {}
    dn, chb, cho = self._dbc.fetchone()
    d['dn'] = [ dn ]
    d['ch'] = [ (chb, cho) ]
    self.d = d
    self._fetch_contacts()
    assert len(d['rc']) == 1
    ct = Person(self._dbc, id=d['rc'][0])
    del d['rc']
    ct.fetch()
    self.ct = ct
  def _fetch_contacts(self):
    d = self.d
    self._dbc.execute('SELECT contact_id,contact_types.name '
                      'FROM domain_contact, contact_types '
                      'WHERE whoisdomain_id=%d '
                      'AND contact_types.id=contact_type_id', (self.id,))
    for k in 'tc', 'zc', 'ac', 'rc':
      d[k] = []
    l = self._dbc.fetchall()
    for id, typ in l:
      cm = contact_map[typ]
      d[cm].append(id)
    for k in 'tc', 'zc', 'ac', 'rc':
      d[k].sort()
    self.d = d
  def resolve_contacts(self, prefs=None):
    """Resolve contact keys."""
    ambig, inval = 0, 0
    newd = {}
    for k in 'ac', 'tc', 'zc':
      newd[k] = [ ]
      for l in self.d[k]:
        if l == None: continue
	ll = l.lower()
	if ll in prefs:
	  id = prefs[ll][0].id
          newd[k].append(id)
	  # rotate prefs
          prefs[ll] = prefs[ll][1:] + prefs[ll][:1]
	  continue
	# XXX: "... AND email IS NOT NULL" is a hack
	# to exclude "registrant" contacts while (temporarily)
	# allowing regular contacts without an email.
        if l.upper().endswith(handlesuffix):
          self._dbc.execute('SELECT id FROM contacts'
                            ' WHERE (lower(contacts.name)=%s'
			    ' AND email IS NOT NULL) OR handle=%s',
                            (l.lower(), suffixstrip(l.upper())))
	else:
          self._dbc.execute('SELECT id FROM contacts'
                            ' WHERE (lower(contacts.name)=%s'
			    ' AND email IS NOT NULL) OR exthandle=%s',
                            (l.lower(), l.upper()))
        # check the returned number of found lines and
        # issue an approriate warning message if it differs from 1.
        if self._dbc.rowcount == 0:
          print "Invalid %s contact '%s' for domain %s" \
		% (contact_map_rev[k], l, self.d['dn'][0])
          inval += 1
        elif self._dbc.rowcount > 1:
          print "Ambiguous key '%s' for domain %s %s contact" \
		" resolves to %d records" % (l, self.d['dn'][0],
					     contact_map_rev[k],
					     self._dbc.rowcount)
          ambig += 1
        lid = self._dbc.fetchall()
        for id, in lid:
          newd[k].append(id)
    for k in 'tc', 'zc', 'ac':
      newd[k].sort()
    self.d.update(newd)
    return ambig, inval
  def get_contacts(self):
    self.fetch()
    dc = {}
    for k in 'tc', 'zc', 'ac':
      typ = contact_map_rev[k]
      dc[typ] = []
      for id in self.d[k]:
        dc[typ].append(Person(self._dbc, id))
    return dc
  def display(self):
    print "%-12s %s" % ('domain:', self.d['dn'][0])
    reg = Person(self._dbc, self.ct.id)
    reg.fetch()
    reg.display('address', embed=True)
    for t, l in [('tc','tech-c'),
                 ('ac','admin-c'),
                 ('zc','zone-c')]:
      if not (t in self.d):
        continue
      for c in self.d[t]:
        p = Person(self._dbc, c)
        p.fetch()
        print "%-12s %s" % (l+':', p.key)
    print

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
    if handle.upper().endswith(handlesuffix):
      self._dbc.execute('SELECT id FROM contacts WHERE handle=%s',
                        (suffixstrip(handle.upper()),))
    else:
      self._dbc.execute('SELECT id FROM contacts WHERE exthandle=%s',
                        (handle.upper(),))
    return self._makelist()
  def persons_by_name(self, name):
    self._dbc.execute('SELECT id FROM contacts WHERE lower(name)=%s' \
		      ' AND email IS NOT NULL', (name.lower(),))
    return self._makelist()
  def persons_by_email(self, email):
    self._dbc.execute('SELECT id FROM contacts WHERE lower(email)=%s',
		      (email.lower(),))
    return self._makelist()
  def domain_by_name(self, name):
    name = name.upper()
    self._dbc.execute('SELECT id, updated_by, updated_on'
                      ' FROM whoisdomains WHERE fqdn=%s',
                      (name,))
    if self._dbc.rowcount == 0:
      return None
    assert self._dbc.rowcount == 1
    id, upby, upon = self._dbc.fetchone()
    return Domain(self._dbc, id, name, upby, upon)
  
class Main:
  comment_re = sre.compile('^\s*#')
  white_re = sre.compile('^\s*$')
  empty_re = sre.compile('^$')
  longattr_re = sre.compile('^([a-z-]+):\s*(.*\S)\s*$')
  shortattr_re = sre.compile('^\*([a-zA-Z][a-zA-Z]):\s*(.*\S)\s*$')
  def _reset(self):
    self.ndom = 0
    self.nperson = 0
    self.ambig = 0
    self.inval = 0
  def __init__(self, dbh):
    self._dbh = dbh
    self._dbc = dbh.cursor()
    self._lookup = Lookup(self._dbc)
    self._reset()
  def process(self, o, dodel, persons=None, forcechanged=None):
    """Handle object creation/updating/deletion."""
    if persons == None:
      persons = {}
    if 'XX' in o:
      # deleted object, ignore
      return
    if forcechanged != None:
      o['ch'] = [ forcechanged ]
    elif 'ch' in o:
      for i in range(len(o['ch'])):
	email, t = parse_changed(o['ch'][i])
	if (email, t) == (None, None):
	  return
	o['ch'][i] = email, t
    if 'dn' in o:
      # domain object
      i = o['dn'][0].upper()
      if dodel:
        # XXX: compare!
        ld = self._lookup.domain_by_name(i)
        if ld != None:
	  print "Object deleted:"
	  ld.display()
          ld.delete()
	  return
      self.ndom += 1
      ld = self._lookup.domain_by_name(i)
      if ld != None:
	# domain already exists
        ld.fetch()
        newdom = Domain(self._dbc, ld.id)
        r = newdom.from_ripe(o, persons)
	if r == None:
	  # something incorrect in provided attributes
	  return
        ambig, inval = r
	# compare with new object
        if ld != newdom or ld.ct.d['ad'] != newdom.ct.d['ad']:
	  # they differ, update database
          print "Object updated from:"
	  ld.display()
          newdom.ct.id = ld.ct.id
          newdom.update()
          print "Object updated to:"
	  newdom.display()
          self.ambig += ambig
          self.inval += inval
	else:
	  print "Object already exists:"
	  ld.display()
      else:
	# make domain object
        ld = Domain(self._dbc)
        r = ld.from_ripe(o, persons)
	if r == None:
	  # something incorrect in provided attributes
	  return
        ambig, inval = r
	# store to database
        ld.insert()
        print "Object created:"
	ld.display()
        self.ambig += ambig
        self.inval += inval
    elif 'pn' in o:
      # person object
      self.nperson += 1
      ct = Person(self._dbc)
      if not ct.from_ripe(o):
	return
      name = o['pn'][0].lower()
      if not name in persons:
	persons[name] = []
      if 'nh' in o and o['nh'][0] != None:
        # has a NIC handle, try to find if already in the base
        handle = suffixadd(o['nh'][0]).lower()
	if not handle in persons:
	  persons[handle] = []
        lp = self._lookup.persons_by_handle(handle)
        assert len(lp) <= 1
        if len(lp) == 1:
	  c = lp[0]
          # found, compare
          c.fetch()
	  if dodel:
	    if ct != c:
              print "Cannot delete: not the same object"
	    else:
	      print "Object deleted:"
	      ct.display()
              ct.delete()
          else:
            if ct != c:
	      print "Object updated from:"
	      c.display()
	      print "Object updated to:"
	      ct.id = c.id
              ct.update()
            else:
	      ct = c
	      print "Object already exists:"
        else:
          # not found
          if dodel:
            print "Cannot delete: not found"
          else:
            ct.insert()
	    print "Object created:"
	if not dodel:
	  ct.display()
	  # keep for contact assignment
	  persons[handle].append(ct)
	  persons[name].append(ct)
      elif dodel:
	print "Cannot delete: no handle provided"
      else:
        # no handle, try to find by name
        lp = self._lookup.persons_by_name(name)
        # try to find if a similar object exists
        for c in lp:
            c.fetch()
            # temporarily copy handle from found object
            o['nh'] = c.d['nh']
            if ct == c:
              # found, stop
	      ct = c
	      print "Object already exists:"
              break
            # clear copied handle
            o['nh'] = [ None ];
        else:
            # not found, insert
            ct.insert()
	    print "Object created:"
	ct.display()
	# keep for contact assignment
	persons[name].append(ct)
    elif 'mt' in o:
      # maintainer object, ignore
      pass
    elif 'XX' in o:
      # deleted object, ignore
      pass
    else:
      print "Unknown object type"
      print str(o)

  def _order(self, o, dodel, persons, nohandle, domains, forcechanged):
    """Handle reordering."""
    if not dodel and 'pn' in o \
	and (not 'nh' in o or not o['nh'][0].endswith(handlesuffix)):
      # updating or creation of a person object, no handle yet.
      # keep for later allocation to avoid clashes
      nohandle.append(o)
    elif not dodel and 'dn' in o:
      # keep domains for handling at the end
      domains[o['dn'][0].upper()] = o
    else:
      # process everything else as we go
      self.process(o, dodel, persons, forcechanged)

  def parsefile(self, file, encoding='ISO-8859-1', commit=True, chkdup=False,
		forcechangedemail=None):
    """Parse file and reorder objects before calling process()."""
    o = {}
    persons = {}
    nohandle = []
    domains = {}
    dodel = False
    self._dbh.cursor().execute("SET client_encoding = '%s'" % encoding)
    self._dbh.autocommit(0)
    self._dbc.execute('START TRANSACTION ISOLATION LEVEL SERIALIZABLE')

    if forcechangedemail != None:
      # Get transaction date and build our changed: line from it.
      self._dbc.execute("SELECT NOW()")
      now, = self._dbc.fetchone()
      assert self._dbc.rowcount == 1
      forcechanged = (forcechangedemail, now)
    else:
      forcechanged = None

    for l in file:
      if self.comment_re.search(l):
        # skip comment
        continue
      if self.white_re.search(l) and len(o):
        # white line or empty line and o is not empty:
        # end of object, process then cleanup for next object.
	self._order(o, dodel, persons, nohandle, domains, forcechanged)
        o = {}
        dodel = False
        continue
      if self.empty_re.search(l):
        # empty line, no object in progress: skip
        continue
      # should be an attribute: value line
      m = self.shortattr_re.search(l)
      if m:
        a, v = m.groups()
      else:
        m = self.longattr_re.search(l)
	if not m:
	  print "Unrecognized line:", l
	  continue
        a, v = m.groups()
        if not a in ripe_ltos:
          print "Unrecognized attribute:", a
	  continue
        a = ripe_ltos[a]
      if a == 'delete':
	# mark for deletion
        dodel = True
      else:
        if a in o:
	  # multi-valued attribute
          o[a].append(v)
        else:
	  # new attribute
          o[a] = [v]
    # end of file
    if len(o):
      # end of file: process last object
      self._order(o, dodel, persons, nohandle, domains, forcechanged)

    for p in nohandle:
      self.process(p, False, persons, forcechanged)

    # XXX: special case: duplicate contact record for a new domain;
    # typically the first one is the administrative contact,
    # the second one is the technical contact.
    # Temporary debug code, just detect and warn.

    if chkdup:
      for x in persons:
        if len(persons[x]) > 1:
          print "Duplicate key %s" % x

    # now that contacts are ready to be used, insert domain_contact records
    # from the domain list we gathered.
    for i in sorted(domains.keys()):
      self.process(domains[i], False, persons, forcechanged)

    if commit:
	self._dbh.commit()
    else:
	self._dbh.rollback()

    print "Domains:", self.ndom
    print "Persons:", self.nperson
    if self.ambig:
      print "Ambiguous contacts:", self.ambig
    if self.inval:
      print "Invalid contacts:", self.inval
    self._reset()
