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

class Person:
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
      #self._dbc.execute('START TRANSACTION ISOLATION LEVEL SERIALIZABLE')
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
      self._dbc.execute('UPDATE contacts SET handle=%s WHERE id=%d', (h, id))
      assert self._dbc.rowcount == 1
      #self._dbc.execute('COMMIT TRANSACTION')
      print "Allocated handle", h, "for", self.d['pn'][0]
  def insert(self):
    o = self.d
    self._dbc.execute('INSERT INTO contacts (handle,name,email,addr1,'
                      'addr2,addr3,addr4,addr5,addr6,phone,fax,'
                      'updated_by,updated_on) '
                      'VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)',
                      (o['nh'][0], o['pn'][0], o['em'][0],
                       o['ad'][0], o['ad'][1], o['ad'][2],
                       o['ad'][3], o['ad'][4], o['ad'][5],
                       o['ph'][0], o['fx'][0],
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
                      ' (contact_id,handle,name,email,'
                      '  addr1,addr2,addr3,addr4,addr5,addr6,'
                      '  phone,fax,passwd,updated_by,updated_on,deleted_on)'
                      ' SELECT id,handle,name,email,'
                      '  addr1,addr2,addr3,addr4,addr5,addr6,'
                      '  phone,fax,passwd,updated_by,updated_on,NOW()'
                      ' FROM contacts WHERE id=%d', (self.id,))
    assert self._dbc.rowcount == 1
  def _update(self):
    o = self.d
    self._dbc.execute('UPDATE contacts SET handle=%s,name=%s,email=%s,'
                      'addr1=%s,addr2=%s,addr3=%s,addr4=%s,addr5=%s,addr6=%s,'
                      'phone=%s,fax=%s,updated_by=%s,updated_on=%s '
                      'WHERE id=%d',
                      (o['nh'][0], o['pn'][0], o['em'][0],
                       o['ad'][0], o['ad'][1], o['ad'][2],
                       o['ad'][3], o['ad'][4], o['ad'][5],
                       o['ph'][0], o['fx'][0],
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
    self._dbc.execute('SELECT handle,name,email,addr1,addr2,addr3,addr4,'
                      ' addr5,addr6,phone,fax,updated_by,updated_on '
                      'FROM contacts WHERE id=%d', (self.id,))
    assert self._dbc.rowcount == 1
    d = {}
    (d['nh'], d['pn'], d['em'],
     addr1, addr2, addr3, addr4, addr5, addr6,
     d['ph'], d['fx'], chb, cho) = self._dbc.fetchone()
    for k in d.keys():
      d[k] = [ d[k] ]
    d['ad'] = [ addr1, addr2, addr3, addr4, addr5, addr6 ]
    d['ch'] = [ (chb, cho) ]
    self.d = d
    self._set_key()
  def display(self, out, title='person'):
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
  
class Domain:
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
  def from_ripe(self, o, pref_id=None):
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
    return self.resolve_contacts(pref_id)
  def _copyrecords(self):
    self._dbc.execute('INSERT INTO domain_contact_hist'
                      ' (whoisdomain_id,contact_id,contact_type_id,'
                      '  created_on,deleted_on)'
                      ' SELECT whoisdomain_id,contact_id,contact_type_id,'
                      '  created_on,NOW()'
                      '  FROM domain_contact WHERE whoisdomain_id=%d',
                      (self.id,))
  def update(self):
    o = self.d
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
  def resolve_contacts(self, pref_id=None):
    """Resolve contact keys."""
    ambig, inval = 0, 0
    newd = {}
    for k in 'ac', 'tc', 'zc':
      newd[k] = [ ]
      for l in self.d[k]:
        if l == None: continue
	# XXX: "email IS NOT NULL" is a hack to exclude "registrant" contacts
        self._dbc.execute('SELECT id FROM contacts '
                          'WHERE (lower(contacts.name)=%s OR handle=%s) '
                          ' AND email IS NOT NULL',
                          (l.lower(), l.upper()))
        # check the returned number of found lines and
        # issue an approriate warning message if it differs from 1.
	dolimit = False
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
	  dolimit = True
        lid = self._dbc.fetchall()
        for id, in lid:
	  if dolimit and pref_id != None:
	    if id in pref_id:
              pref_id.remove(id)
              newd[k].append(id)
              break
          else:
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
  def display(self, out):
    print >>out, "%-12s %s" % ('domain:', self.d['dn'][0])
    reg = Person(self._dbc, self.d['rc'][0])
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
  def process(self, o, dodel, halloc):
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
            if not dodel:
              lp[0].update()
            else:
              print "Cannot delete: not the same object"
          else:
            if dodel:
              lp.delete()
        else:
          # not found
          if dodel:
            print "Cannot delete: not found"
          else:
            ct.insert()
      else:
        assert 'pn' in o and o['pn'] != None
        # no handle, try to find by name
        name = o['pn'][0]
        lp = self._lookup.persons_by_name(name)
        if len(lp) == 0:
          # not found, insert
          ct.insert()
	  # keep for handle allocation
	  halloc.append(ct)
        else:
          # try to find if a similar object exists
          for c in lp:
            c.fetch()
            # temporarily copy handle from found object
            o['nh'] = c.d['nh']
            if c.d == o:
              # found, stop
              break
            # clear copied handle
            o['nh'] = [ None ];
          else:
            # not found, insert
            print "No handle and not found by name"
            print "new=", o
            ct.insert()
	    # keep for handle allocation
	    halloc.append(ct)
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
    halloc = []
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
        self.process(o, dodel, halloc)
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
      self.process(o, dodel, halloc)

    # XXX: special case: duplicate contact record for a new domain;
    # typically the first one is the administrative contact,
    # the second one is the technical contact.
    # Temporary debug code, just detect and warn.

    if chkdup:
      print "chkdup on", len(halloc), "records"
      halloc_keys = []
      for x in halloc:
        if x.key.lower() in halloc_keys:
          print "Duplicate key %s" % x.key
        halloc_keys.append(x.key.lower())

    xid = [x.id for x in halloc]

    # now that contacts are ready to be used, insert domain_contact records
    # from the domain list we gathered.
    for i in sorted(self.dom.keys()):
      ld = self._lookup.domain_by_name(i)
      if ld != None:
	# domain already exists
        ld.fetch()
        newdom = Domain(self._dbc, ld.id)
        newdom.from_ripe(self.dom[i])
	# compare with new object
        if ld.d != newdom.d or ld.ct.d['ad'] != newdom.ct.d['ad']:
	  # they differ, update database
          print "Update for", i, "to be done"
          print "ld.d=", ld.d
          print "dom.d=", newdom.d
          print "ld.ct.d=", ld.ct.d
          print "dom.ct.d=", newdom.ct.d
          newdom.ct.id = ld.ct.id
          newdom.update()
      else:
	# make domain object
        ld = Domain(self._dbc)
        ambig, inval = ld.from_ripe(self.dom[i], xid)
	# store to database
        ld.insert()
        self.ambig += ambig
        self.inval += inval

    # now allocate missing handles
    for i in halloc:
      i.allocate_handle()

    if commit:
	self._dbh.commit()
    else:
	self._dbh.rollback()

    print "Domains:", self.ndom
    print "Persons:", self.nperson
    print "Ambiguous contacts:", self.ambig
    print "Invalid contacts:", self.inval
    self._reset()
