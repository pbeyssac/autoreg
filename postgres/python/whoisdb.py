#!/usr/local/bin/python

import sre
import sys

import mx

_tv6 = sre.compile('^(\S+)\s*(\d\d)(\d\d)(\d\d)$')
_tv8 = sre.compile('^(\S+)\s*(\d\d\d\d)(\d\d)(\d\d)$')

def parse_changed(timeval):
  ma = _tv6.search(timeval)
  if ma:
    email, y, m, d = ma.groups()
    y = int(y)
    if y > 50:
      y += 1900
    else:
      y += 2000
  else:
    ma = _tv8.search(timeval)
    if ma:
      email, y, m, d = ma.groups()
      y = int(y)
    else:
      print "Cannot parse_changed:", timeval
      raise Error
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
  a = ta.split('\n')
  for i in range(len(a)):
    if a[i] == '': a[i] = None
  while len(a) < 6:
    a.append(None)
  return a

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
        print "Ignoring attribute %s: %s" % (k, o[k])
  # cleanup ignored attributes
  for k in dlist:
    del o[k]
  # check attribute constraints
  for k, mm in attrlist.iteritems():
    minl, maxl = mm
    if not k in o:
      if minl > 0:
        print "Missing attribute %s" % ripe_stol[k]
        raise Error
      o[k] = [ None ]
    else:
      if not (minl <= len(o[k]) <= maxl):
        print "Attribute %s found %d times, should appear %d to %d time(s)" % \
              (ripe_stol[k], len(o[k]), minl, maxl)
        o[k] = o[k][:maxl]
  if len(o['ad']) < 6:
    o['ad'].extend([ None ] * (6-len(o['ad'])))

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
  _suffix = "-FREE"
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
  def allocate_handle(self):
    if (not 'nh' in self.d) or self.d['nh'][0] == None:
      l = mkinitials(self.d['pn'][0])

      # Find the highest allocated handle with the same initials
      self._dbc.execute("SELECT CAST(SUBSTRING(handle FROM '[0-9]+') AS INT)"
			" FROM contacts WHERE handle SIMILAR TO '%s[0-9]+%s'"
			" ORDER BY CAST(SUBSTRING(handle FROM '[0-9]+') AS INT)"
			" DESC LIMIT 1" % (l, self._suffix))
      assert 0 <= self._dbc.rowcount <= 1
      if self._dbc.rowcount == 0:
        i = 1
      else:
        i, = self._dbc.fetchone()
        i += 1
      h = "%s%d%s" % (l, i, self._suffix)
      id = self.id
      self.key = h
      self.d['nh'] = [ h ]
      #print "Allocated handle", h, "for", self.d['pn'][0]
  def insert(self):
    o = self.d
    self._dbc.execute('INSERT INTO contacts (handle,name,email,'
                      'addr,phone,fax,updated_by,updated_on) '
                      'VALUES (%s,%s,%s,%s,%s,%s,%s,%s)',
                      (o['nh'][0], o['pn'][0], o['em'][0],
                       addrmake(o['ad']), o['ph'][0], o['fx'][0],
                       o['ch'][0][0], str(o['ch'][0][1])))
    assert self._dbc.rowcount == 1
    self._dbc.execute("SELECT currval('contacts_id_seq')")
    self.id, = self._dbc.fetchone()
    assert self._dbc.rowcount == 1
  def _copyrecord(self):
    assert self.id != None
    self._dbc.execute('SELECT * FROM contacts WHERE id=%d FOR UPDATE',
                      (self.id,))
    assert self._dbc.rowcount == 1
    self._dbc.execute('INSERT INTO contacts_hist '
                      ' (contact_id,handle,name,email,addr,'
                      '  phone,fax,passwd,updated_by,updated_on,deleted_on)'
                      ' SELECT id,handle,name,email,addr,'
                      '  phone,fax,passwd,updated_by,updated_on,NOW()'
                      ' FROM contacts WHERE id=%d', (self.id,))
    assert self._dbc.rowcount == 1
  def _update(self):
    o = self.d
    self._dbc.execute('UPDATE contacts SET handle=%s,name=%s,email=%s,'
                      'addr=%s,phone=%s,fax=%s,updated_by=%s,updated_on=%s '
                      'WHERE id=%d',
                      (o['nh'][0], o['pn'][0], o['em'][0],
                       addrmake(o['ad']), o['ph'][0], o['fx'][0],
                       o['ch'][0][0], str(o['ch'][0][1]), self.id))
    assert self._dbc.rowcount == 1
  def update(self):
    self._copyrecord()
    self._update()
  def delete(self):
    self._copyrecord()
    self._dbc.execute('DELETE contacts WHERE id=%d', (self.id,))
    assert self._dbc.rowcount == 1
  def fetch(self):
    assert self.id != None
    self._dbc.execute('SELECT handle,name,email,addr,'
                      ' phone,fax,updated_by,updated_on '
                      'FROM contacts WHERE id=%d', (self.id,))
    assert self._dbc.rowcount == 1
    d = {}
    (d['nh'], d['pn'], d['em'],
     addr,
     d['ph'], d['fx'], chb, cho) = self._dbc.fetchone()
    for k in d.keys():
      d[k] = [ d[k] ]
    d['ad'] = addrsplit(addr)
    d['ch'] = [ (chb, cho) ]
    self.d = d
    self._set_key()
  def display(self, out=sys.stdout, title='person'):
    d = self.d
    for i in ['pn', 'nh', 'ad', 'ph', 'fx', 'em', 'ch']:
      if i == 'pn':
        l = title
      else:
        l = ripe_stol[i]
      for j in d[i]:
        if i == 'ch':
          j = "%s %s" % j
        if j != None:
          print >>out, "%-12s %s" % (l+':', j)
  
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
    return self.resolve_contacts(prefs)
  def _copyrecords(self):
    self._dbc.execute('INSERT INTO domain_contact_hist'
                      ' (whoisdomain_id,contact_id,contact_type_id,'
                      '  created_on,deleted_on)'
                      ' SELECT whoisdomain_id,contact_id,contact_type_id,'
                      '  created_on,NOW()'
                      '  FROM domain_contact WHERE whoisdomain_id=%d',
                      (self.id,))
  def update(self):
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
    self.insert_domain_contact()
  def delete(self):
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
    self.ct.insert()
    self._dbc.execute("INSERT INTO domain_contact "
                      "(whoisdomain_id,contact_id,contact_type_id) "
                      "VALUES (%d,%d,"
                      "(SELECT id FROM contact_types WHERE name=%s))",
                      (self.id, self.ct.id, 'registrant'))
    assert self._dbc.rowcount == 1
  def insert(self):
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
    self.insert_domain_contact()
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
	  break
	# XXX: "... AND email IS NOT NULL" is a hack
	# to exclude "registrant" contacts while (temporarily)
	# allowing regular contacts without an email.
        self._dbc.execute('SELECT id FROM contacts'
                          ' WHERE (lower(contacts.name)=%s'
			  ' AND email IS NOT NULL) OR handle=%s',
                          (l.lower(), l.upper()))
        # check the returned number of found lines and
        # issue an approriate warning message if it differs from 1.
        if self._dbc.rowcount == 0:
          print "Invalid %s contact '%s' for domain %s" % (contact_map_rev[k],
							   l, self.d['dn'][0])
          inval += 1
        elif self._dbc.rowcount > 1:
          print "Ambiguous key '%s' for domain %s %s contact"\
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
  def display(self, out=sys.stdout):
    print >>out, "%-12s %s" % ('domain:', self.d['dn'][0])
    reg = Person(self._dbc, self.ct.id)
    reg.fetch()
    reg.display(out, 'address')
    for t, l in [('tc','tech-c'),
                 ('ac','admin-c'),
                 ('zc','zone-c')]:
      if not (t in self.d):
        continue
      for c in self.d[t]:
        p = Person(self._dbc, c)
        p.fetch()
        print >>out, "%-12s %s" % (l+':', p.key)

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
    self.dom = {}
    self.ndom = 0
    self.nperson = 0
    self.ambig = 0
    self.inval = 0
  def __init__(self, dbh):
    self._dbh = dbh
    self._dbc = dbh.cursor()
    self._lookup = Lookup(self._dbc)
    self._reset()
  def process(self, o, dodel, persons=None):
    if persons == None:
      persons = {}
    if o.has_key('XX'):
      # deleted object, ignore
      return
    if o.has_key('ch'):
	for i in range(len(o['ch'])):
	    o['ch'][i] = parse_changed(o['ch'][i])
    if o.has_key('dn'):
      # domain object
      if dodel:
        # XXX: compare!
        ld = self._lookup.domain_by_name(o['dn'])
        if ld != None:
	  print "Object deleted:"
	  ld.display()
          ld.delete()
      else:
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
        handle = o['nh'][0].lower()
	name = o['pn'][0].lower()
	if not name in persons:
	  persons[name] = []
	if not handle in persons:
	  persons[handle] = []
        lp = self._lookup.persons_by_handle(handle)
        assert len(lp) <= 1
        if len(lp) == 1:
          # found, compare
          lp[0].fetch()
          if lp[0] != ct:
            if not dodel:
	      print "Object updated from:"
	      lp[0].display()
	      print "Object updated to:"
	      ct.id = lp[0].id
	      ct.display()
              ct.update()
	      # keep for contact assignment
	      persons[handle].append(ct)
	      persons[name].append(ct)
            else:
              print "Cannot delete: not the same object"
          else:
            if dodel:
	      print "Object deleted:"
	      lp[0].display()
              lp[0].delete()
	    else:
	      print "Object already exists:"
	      lp[0].display()
	      persons[handle].append(lp[0])
	      persons[name].append(lp[0])
        else:
          # not found
          if dodel:
            print "Cannot delete: not found"
          else:
            ct.insert()
	    print "Object created:"
	    ct.display()
	    # keep for contact assignment
	    persons[handle].append(ct)
	    persons[name].append(ct)
      else:
        assert 'pn' in o and o['pn'] != None
        # no handle, try to find by name
        name = o['pn'][0].lower()
	if not name in persons:
	  persons[name] = []
        lp = self._lookup.persons_by_name(name)
        if len(lp) == 0:
          # not found, insert
	  ct.allocate_handle()
          ct.insert()
	  print "Object created:"
	  ct.display()
	  # keep for contact assignment
	  persons[name].append(ct)
        else:
          # try to find if a similar object exists
          for c in lp:
            c.fetch()
            # temporarily copy handle from found object
            o['nh'] = c.d['nh']
            if ct == c:
              # found, stop
	      # keep for contact assignment
	      persons[name].append(c)
	      print "Object already exists:"
	      c.display()
              break
            # clear copied handle
            o['nh'] = [ None ];
          else:
            # not found, insert
            ct.allocate_handle()
            ct.insert()
	    print "Object created:"
	    ct.display()
	    # keep for contact assignment
	    persons[name].append(ct)
    elif o.has_key('mt'):
      # maintainer object, ignore
      pass
    elif o.has_key('XX'):
      # deleted object, ignore
      pass
    else:
      print >>sys.stderr, "Unknown object type"
      print str(o)

  def parsefile(self, file, encoding='ISO-8859-1', commit=True, chkdup=False):
    o = {}
    persons = {}
    nohandle = []
    dodel = False
    self._dbh.cursor().execute("SET client_encoding = '%s'" % encoding)
    self._dbh.autocommit(0)
    self._dbc.execute('START TRANSACTION ISOLATION LEVEL SERIALIZABLE')

    for l in file:
      if self.comment_re.search(l):
        # skip comment
        continue
      if self.white_re.search(l) and len(o):
        # white line or empty line and o is not empty:
        # end of object, process then cleanup for next object.
	if not dodel and 'pn' in o and not 'nh' in o:
	  # keep for later allocation to avoid clashes
	  nohandle.append(o)
	else:
          self.process(o, dodel, persons)
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
        assert m
        a, v = m.groups()
        if not ripe_ltos.has_key(a):
          raise Error
        a = ripe_ltos[a]
      if a == 'delete':
	# mark for deletion
        dodel = True
      else:
        if o.has_key(a):
	  # multi-valued attribute
          o[a].append(v)
        else:
	  # new attribute
          o[a] = [v]
    # end of file
    if len(o):
      # end of file: process last object
      if not dodel and 'pn' in o and not 'nh' in o:
	# keep for later allocation to avoid clashes
	nohandle.append(o)
      else:
        self.process(o, dodel, persons)

    for p in nohandle:
      self.process(p, False, persons)

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
    for i in sorted(self.dom.keys()):
      ld = self._lookup.domain_by_name(i)
      if ld != None:
	# domain already exists
        ld.fetch()
        newdom = Domain(self._dbc, ld.id)
        newdom.from_ripe(self.dom[i], persons)
	# compare with new object
        if ld.d != newdom.d or ld.ct.d['ad'] != newdom.ct.d['ad']:
	  # they differ, update database
          print "Object updated from:"
	  ld.display()
          newdom.ct.id = ld.ct.id
          newdom.update()
          print "Object updated to:"
	  newdom.display()
      else:
	# make domain object
        ld = Domain(self._dbc)
        ambig, inval = ld.from_ripe(self.dom[i], persons)
	# store to database
        ld.insert()
        print "Object created:"
	ld.display()
        self.ambig += ambig
        self.inval += inval

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
