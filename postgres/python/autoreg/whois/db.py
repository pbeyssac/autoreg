#!/usr/local/bin/python
# $Id$

import re
import sha
import sys

import mx

handlesuffix = '-FREE'

_tv68 = re.compile('^(\S+)\s*(?:(\d\d))?(\d\d)(\d\d)(\d\d)$')
_tv = re.compile('^(\d\d\d\d)-(\d\d)-(\d\d) (\d\d):(\d\d):(\d\d)(?:\.(\d\d))?$')
_notv = re.compile('^(\S+)\s*$')

DBENCODING = None
DEFAULTENCODING = 'ISO-8859-1'

def fetch_dbencoding(dbc):
  """Get the current client encoding on the database connection."""
  global DBENCODING
  if DBENCODING == None:
    dbc.execute('SHOW client_encoding')
    assert dbc.rowcount == 1
    DBENCODING, = dbc.fetchone()
  return DBENCODING

def _todb(atuple):
  """Convert Unicode strings in the tuple for use in a database request."""
  newlist = []
  for i in atuple:
    if type(i) == unicode:
      i = i.encode(DBENCODING)
    newlist.append(i)
  return tuple(newlist)

def _fromdb(atuple):
  """Convert to Unicode any strings returned by the database."""
  newlist = []
  for i in atuple:
    if type(i) == str:
      i = unicode(i, DBENCODING)
    newlist.append(i)
  return tuple(newlist)

def parse_changed(changed):
  """Parse a RIPE-style changed: line."""

  # syntax extension: accept a changed line without a date
  ma = _notv.search(changed)
  if ma:
    # no date, just an email
    return ma.groups()[0], None

  ma = _tv68.search(changed)
  if ma:
    email, c, y, m, d = ma.groups()
    y = int(y)
    if c:
      y += int(c)*100
    else:
      if y > 50:
        y += 1900
      else:
        y += 2000
  else:
    ma = _tv.search(changed)
    if ma:
      y, m, d, h, m, s, fs = ma.groups()
      y = int(y)
      email = None
    else:
      print "ERROR: Cannot parse_changed:", changed
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

registrantattrs = {'pn': (0,1), 'ad': (0,6),
                   'ph': (0,1), 'fx': (0,1),
                   'em': (0,1), 'ch': (1,1), 'nh': (0,1), 'eh': (0, 1)}

personattrs = {'pn': (1,1), 'ad': (0,6),
               'ph': (0,1), 'fx': (0,1),
               'em': (1,1), 'ch': (1,1), 'nh': (0,1), 'eh': (0, 1)}

contact_map = { 'technical': 'tc', 'administrative': 'ac', 'zone': 'zc',
                'registrant': 'rc' }
contact_map_rev = dict((v, k) for k, v in contact_map.iteritems())

_skipalnum = re.compile('^[a-zA-Z0-9]+\s*(.*)')
_skipword = re.compile('^\S+\s+(.*)')

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
  elif len(h) == 1:
    # forbid 1-letter handles
    h += 'Z'
  return h

class _whoisobject(object):
  re_map = {
    'em': [60, re.compile('^[a-zA-Z0-9\-+\.\_\/\=%]+'
                          '@[a-zA-Z0-9\-]+(?:\.[a-zA-Z0-9\-]+)+$')],
    'ph': [40, re.compile('^\+?[\d\s#\-\(\)\[\]\.]+$')],
    'fx': [40, re.compile('^\+?[\d\s#\-\(\)\[\]\.]+$')],
    'pn': [80, re.compile('^[^\x00-\x1f]*$')],
    'nh': [20, re.compile('^[A-Z]{1,3}\d+$', re.IGNORECASE)],
    'eh': [20, re.compile('^[A-Z]+\d*(?:-[A-Z0-9]+)?$', re.IGNORECASE)],
    'dn': [255, re.compile('^[A-Z0-9][A-Z0-9-]*(?:\.[A-Z0-9][A-Z0-9-]*)*'
                           '\.[A-Z]+$',
                           re.IGNORECASE|re.MULTILINE)],
    'ad': [80, re.compile('^[^\x00-\x1f]*$')]
    }
  
  def check(self, o, attrlist):
    """Check and convert from RIPE-style attributes."""
    self.d = o
    warn = []
    err = []
    # obtain encoding for strings stored in o
    encoding = o.get('encoding', DEFAULTENCODING)
    # find ignored attributes, warn
    dlist = []
    for k in o:
      if not k in attrlist:
        dlist.append(k)
        if not k in ['so', 'mb', 'encoding', 'err', 'warn']:
          for v in o[k]:
            warn.append([k, "Ignoring"])
    # cleanup ignored attributes
    for k in dlist:
      del o[k]
    # convert strings to Unicode
    for k in o:
      # only strings stored in database, skip 'err' and 'warn'
      if len(k) != 2:
        continue
      r = []
      for s in o[k]:
        if type(s) == str:
          s = unicode(s, encoding)
        r.append(s)
      o[k] = r
    # move foreign NIC handle out of the way
    if 'nh' in o:
      if o['nh'][0].endswith(handlesuffix):
        o['nh'][0] = suffixstrip(o['nh'][0])
      else:
        o['eh'] = o['nh']
        del o['nh']
    # check syntax
    for k in o:
      if k in self.re_map:
        maxlen, regex = self.re_map[k]
        i = 1
        for l in o[k]:
          if l == None:
            continue
          if len(l) > maxlen:
            err.append([k + str(i), "value too long"])
          elif not regex.match(l):
            err.append([k + str(i), "Invalid syntax: %s" % l])
          i += 1
    if 'ad' in o and len(addrmake(o['ad'])) > 400:
      err.append(['ad', "Address too long"])
    #if 'ad' in o and len(addrmake(o['ad'])) < 20:
    #  err.append(['ad', "Address too short"])
    # check attribute constraints
    for k, mm in attrlist.iteritems():
      minl, maxl = mm
      if not k in o:
        if minl > 0:
          err.append([k, "Missing"])
        o[k] = [ None ]
      else:
        if not (minl <= len(o[k]) <= maxl):
          warn.append([k, "Found %d times instead of %d to %d time(s)" \
                      % (len(o[k]), minl, maxl)])
          o[k] = o[k][:maxl]
    # convert address
    if len(o['ad']) < 6:
      o['ad'].extend([ None ] * (6-len(o['ad'])))
    # If no created_on date, set from updated_on date
    if 'ch' in o and not 'cr' in o:
      o['cr'] = [ o['ch'][0][1] ]
    # hide lists of errors/warnings in the returned attributes...
    if len(err):
      o['err'] = err
    if len(warn):
      o['warn'] = warn
    return len(err) == 0 and len(warn) == 0
  def get_msgs(self):
    return self.d.get('err', []), self.d.get('warn', [])
  def format_msgs(self):
    o = self.d
    text = ''
    for i in ('err', 'warn'):
      if i in o:
        for j in o[i]:
          if i == 'err':
            text += 'ERROR'
          else:
            text += 'WARN'
          text += ': ' + j[0] + '/' + ripe_stol.get(j[0], j[0]) + ': ' + j[1] + '\n'
    return text
  def __cmp__(self, other):
    """Customized compare function:
        - ignore 'ch' and 'cr' entries
        - case-insensitive compare on 'pn'
    """
    if not isinstance(other, type(self)):
      return id(self).__cmp__(id(other))
    d1 = self.d.copy()
    d2 = other.d.copy()
    for i in 'ch', 'cr', 'encoding', 'warn', 'err':
      if i in d1:
        del d1[i]
      if i in d2:
        del d2[i]
    if 'pn' in d1 and 'pn' in d2:
      d1['pn'] = [ d1['pn'][0].lower() ]
      d2['pn'] = [ d2['pn'][0].lower() ]
    return d1.__cmp__(d2)

class Person(_whoisobject):
  def __init__(self, dbc, cid=None, key=None):
    fetch_dbencoding(dbc)
    self._dbc = dbc
    self.cid = cid
    self.key = key
    self.d = {}
  def _set_key(self):
    if self.d['nh'][0] != None:
      self.key = suffixadd(self.d['nh'][0])
    else:
      self.key = self.d['pn'][0]
  def _from_ripe(self, o, attrs):
    """Fill from RIPE-style attributes."""
    if not self.check(o, attrs):
      return False
    self._set_key()
    return True
  def registrant_from_ripe(self, o):
    """Fill a registrant from RIPE-style attributes."""
    return self._from_ripe(o, registrantattrs)
  def from_ripe(self, o):
    """Fill from RIPE-style attributes."""
    return self._from_ripe(o, personattrs)
  def _allocate_handle(self):
    """Allocate ourselves a handle if we lack one."""
    if (not 'nh' in self.d) or self.d['nh'][0] == None:
      l = mkinitials(self.d['pn'][0])

      # Find the highest allocated handle with the same initials
      self._dbc.execute("SELECT CAST(SUBSTRING(handle FROM '[0-9]+') AS INT)"
                        " FROM contacts WHERE handle SIMILAR TO '%s[0-9]+'"
                        " ORDER BY CAST(SUBSTRING(handle FROM '[0-9]+') AS INT)"
                        " DESC LIMIT 1" % _todb((l,)))
      assert 0 <= self._dbc.rowcount <= 1
      if self._dbc.rowcount == 0:
        i = 1
      else:
        i, = _fromdb(self._dbc.fetchone())
        i += 1
      h = u"%s%d" % (l, i)
      self.key = suffixadd(h)
      self.d['nh'] = [ h ]
      #print "Allocated handle", self.key, "for", self.d['pn'][0]
  def gethandle(self):
    return suffixadd(self.d['nh'][0])
  def insert(self):
    """Create in database."""
    # lock the table real good to avoid any race condition at
    # handle allocation or insertion.
    self._dbc.execute("LOCK TABLE contacts IN ACCESS EXCLUSIVE MODE")

    self._allocate_handle()
    o = self.d
    if o['ch'][0][1] == None:
      self._dbc.execute('SELECT NOW()')
      assert self._dbc.rowcount == 1
      now, = self._dbc.fetchone()
      o['ch'] = [(o['ch'][0][0], now)]
      o['cr'] = [now]
    self._dbc.execute('INSERT INTO contacts (handle,exthandle,name,email,'
                      'addr,phone,fax,created_on,updated_by,updated_on) '
                      'VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)',
                   _todb(
                      (o['nh'][0],o['eh'][0],o['pn'][0], o['em'][0],
                       addrmake(o['ad']), o['ph'][0], o['fx'][0],
                       str(o['cr'][0]), o['ch'][0][0], str(o['ch'][0][1]))))
    assert self._dbc.rowcount == 1
    self._dbc.execute("SELECT currval('contacts_id_seq')")
    self.cid, = self._dbc.fetchone()
    assert self._dbc.rowcount == 1
  def _copyrecord(self):
    """Copy record to history."""
    assert self.cid != None
    self._dbc.execute('SELECT * FROM contacts WHERE id=%d FOR UPDATE',
                      (self.cid,))
    assert self._dbc.rowcount == 1
    self._dbc.execute('INSERT INTO contacts_hist '
                      ' (contact_id,handle,exthandle,name,email,addr,'
                      '  phone,fax,passwd,'
                      '  created_on,updated_by,updated_on,deleted_on)'
                      ' SELECT id,handle,exthandle,name,email,addr,'
                      '  phone,fax,passwd,'
                      '  created_on,updated_by,updated_on,NOW()'
                      ' FROM contacts WHERE id=%d', (self.cid,))
    assert self._dbc.rowcount == 1
  def _update(self):
    """Write back to database."""
    o = self.d
    self._dbc.execute('UPDATE contacts SET handle=%s,exthandle=%s,'
                      'name=%s,email=%s,'
                      'addr=%s,phone=%s,fax=%s,updated_by=%s,updated_on=NOW() '
                      'WHERE id=%d',
                   _todb(
                      (o['nh'][0], o['eh'][0], o['pn'][0], o['em'][0],
                       addrmake(o['ad']), o['ph'][0], o['fx'][0],
                       o['ch'][0][0], self.cid)))
    assert self._dbc.rowcount == 1
  def update(self):
    """Write back to database, keeping history."""
    self._copyrecord()
    self._update()
  def delete(self):
    """Delete from database, keeping history."""
    self._copyrecord()
    self._dbc.execute('DELETE contacts WHERE id=%d', (self.cid,))
    assert self._dbc.rowcount == 1
  def fetch(self):
    """Read from database."""
    assert self.cid != None
    self._dbc.execute('SELECT handle,exthandle,name,email,addr,'
                      ' phone,fax,created_on,updated_by,updated_on '
                      'FROM contacts WHERE id=%d', (self.cid,))
    assert self._dbc.rowcount == 1
    d = {}
    (d['nh'], d['eh'], d['pn'], d['em'],
     addr,
     d['ph'], d['fx'], d['cr'], chb, cho) = _fromdb(self._dbc.fetchone())
    for k in d.keys():
      d[k] = [ d[k] ]
    d['ad'] = addrsplit(addr)
    d['ch'] = [ (chb, cho) ]
    self.d = d
    self._set_key()
  def digest(self, seed=''):
    self.fetch()
    return sha.new(seed + self.key.lower()).hexdigest()[:8]
  def __str__(self, title='person', embed=False):
    """Convert to string, RIPE-style.
       embed selects display within domain for a registrant contact.
    """
    s = u''
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
          j = str(j[1])
        elif i == 'nh':
          j = suffixadd(j)
        if j != None:
          s += "%-12s %s\n" % (l+':', j)
    return s
  
class Domain(_whoisobject):
  def __init__(self, dbc, did=None, fqdn=None,
               updated_by=None, updated_on=None):
    fetch_dbencoding(dbc)
    d = {}
    self._dbc = dbc
    if fqdn != None:
      d['dn'] = [ fqdn.upper() ]
    if updated_on != None:
      d['ch'] = [ (updated_by, updated_on) ]
    self.d = d
    self.did = did
  def from_ripe(self, o, prefs=None):
    """Fill from RIPE-style attributes."""
    if not self.check(o, domainattrs):
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
    self.ct = Person(self._dbc)
    if not self.ct.registrant_from_ripe(c):
      o['err'] = c.get('err', [])
      o['warn'] = c.get('warn', [])
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
                      (self.did,))
  def update(self):
    """Write back to database, keeping history."""
    assert self.did != None
    self._dbc.execute('SELECT * FROM whoisdomains WHERE id=%d FOR UPDATE',
                      (self.did,))
    assert self._dbc.rowcount == 1
    self._dbc.execute('UPDATE whoisdomains SET updated_on=NOW() WHERE id=%d',
                      (self.did,))
    assert self._dbc.rowcount == 1
    # XXX: the line below assumes registrant contacts are not shared.
    # We'll get rid of this assumption when we drop the RIPE model.
    self.ct.update()
    self._copyrecords()
    self._dbc.execute('DELETE FROM domain_contact WHERE whoisdomain_id=%d',
                      (self.did,))
    self._insert_domain_contact()
  def delete(self):
    """Delete from database, keeping history."""
    assert self.did != None
    self._dbc.execute('SELECT * FROM whoisdomains WHERE id=%d FOR UPDATE',
                      (self.did,))
    assert self._dbc.rowcount == 1
    self._copyrecords()
    self._dbc.execute('DELETE FROM domain_contact WHERE whoisdomain_id=%d',
                      (self.did,))
    self._dbc.execute('INSERT INTO whoisdomains_hist '
                      ' (whoisdomain_id,fqdn,created_on,deleted_on)'
                      ' SELECT id,fqdn,created_on,NOW()'
                      ' FROM whoisdomains WHERE id=%d',
                      (self.did,))
    assert self._dbc.rowcount == 1
    self._dbc.execute('DELETE FROM whoisdomains WHERE id=%d',
                      (self.did,))
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
                          (self.did, v, full))
        assert self._dbc.rowcount == 1
    self.ct.insert()
    self._dbc.execute("INSERT INTO domain_contact "
                      "(whoisdomain_id,contact_id,contact_type_id) "
                      "VALUES (%d,%d,"
                      "(SELECT id FROM contact_types WHERE name=%s))",
                      (self.did, self.ct.cid, 'registrant'))
    assert self._dbc.rowcount == 1
  def insert(self):
    """Create in database."""
    o = self.d
    domain = o['dn'][0]
    self._dbc.execute('INSERT INTO whoisdomains'
                      ' (fqdn,created_on,updated_by,updated_on) '
                      'VALUES (%s,%s,%s,%s)',
                   _todb(
                      (domain, str(o['cr'][0]),
                       o['ch'][0][0], str(o['ch'][0][1]))))
    assert self._dbc.rowcount == 1
    self._dbc.execute("SELECT currval('whoisdomains_id_seq')")
    assert self._dbc.rowcount == 1
    did, = self._dbc.fetchone()
    self.did = did
    self._insert_domain_contact()
  def fetch(self):
    self._dbc.execute('SELECT fqdn, created_on, updated_by, updated_on '
                      'FROM whoisdomains WHERE id=%d', (self.did,))
    assert self._dbc.rowcount == 1
    d = {}
    dn, cr, chb, cho = _fromdb(self._dbc.fetchone())
    d['dn'] = [ dn ]
    d['cr'] = [ cr ]
    d['ch'] = [ (chb, cho) ]
    self.d = d
    self._fetch_contacts()
    assert len(d['rc']) == 1
    ct = Person(self._dbc, cid=d['rc'][0])
    del d['rc']
    ct.fetch()
    self.ct = ct
  def _fetch_contacts(self):
    d = self.d
    self._dbc.execute('SELECT contact_id,contact_types.name '
                      'FROM domain_contact, contact_types '
                      'WHERE whoisdomain_id=%d '
                      'AND contact_types.id=contact_type_id', (self.did,))
    for k in 'tc', 'zc', 'ac', 'rc':
      d[k] = []
    l = self._dbc.fetchall()
    for cid, typ in l:
      cm = contact_map[typ]
      d[cm].append(cid)
    for k in 'tc', 'zc', 'ac', 'rc':
      d[k].sort()
    self.d = d
  def resolve_contacts(self, prefs=None):
    """Resolve contact keys."""
    ambig, inval = 0, 0
    newd = {}
    err = []
    for k in 'ac', 'tc', 'zc':
      newd[k] = [ ]
      for l in self.d[k]:
        if l == None: continue
        ll = l.lower()
        if ll in prefs and len(prefs[ll]):
          cid = prefs[ll][0].cid
          newd[k].append(cid)
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
                            _todb((l.lower(), suffixstrip(l.upper()))))
        else:
          self._dbc.execute('SELECT id FROM contacts'
                            ' WHERE (lower(contacts.name)=%s'
                            ' AND email IS NOT NULL) OR exthandle=%s',
                            _todb((l.lower(), l.upper())))
        # check the returned number of found lines and
        # issue an approriate warning message if it differs from 1.
        if self._dbc.rowcount == 0:
          err.append(['**', "Invalid %s contact '%s' for domain %s" \
                     % (contact_map_rev[k], l, self.d['dn'][0])])
          inval += 1
        elif self._dbc.rowcount > 1:
          err.append(['**', "Ambiguous key '%s' for domain %s %s contact" \
                     " resolves to %d records" % (l, self.d['dn'][0],
                                                  contact_map_rev[k],
                                                  self._dbc.rowcount)])
          ambig += 1
        lid = self._dbc.fetchall()
        for cid, in lid:
          newd[k].append(cid)
    for k in 'tc', 'zc', 'ac':
      newd[k].sort()
    if ambig == 0 and inval == 0:
      self.d.update(newd)
    else:
      self.d.setdefault('err', []).extend(err)
    return ambig, inval
  def get_contacts(self):
    self.fetch()
    dc = {}
    for k in 'tc', 'zc', 'ac':
      typ = contact_map_rev[k]
      dc[typ] = [ Person(self._dbc, cid) for cid in self.d[k] ]
    return dc
  def __str__(self):
    s = u"%-12s %s\n" % ('domain:', self.d['dn'][0])
    reg = Person(self._dbc, self.ct.cid)
    reg.fetch()
    s += reg.__str__('address', embed=True)
    for t, l in [('tc','tech-c'),
                 ('ac','admin-c'),
                 ('zc','zone-c')]:
      for c in self.d.get(t, []):
        p = Person(self._dbc, c)
        p.fetch()
        s += "%-12s %s\n" % (l+':', p.key)
    return s

class Lookup:
  def __init__(self, dbc):
    fetch_dbencoding(dbc)
    self._dbc = dbc
  def _makeplist(self):
    l = [ Person(self._dbc, t[0]) for t in self._dbc.fetchall() ]
    return l
  def _makedlist(self):
    l = [ Domain(self._dbc, t[0]) for t in self._dbc.fetchall() ]
    return l
  def persons_by_handle(self, handle):
    if handle.upper().endswith(handlesuffix):
      self._dbc.execute('SELECT id FROM contacts WHERE handle=%s',
                        _todb((suffixstrip(handle.upper()),)))
    else:
      self._dbc.execute('SELECT id FROM contacts WHERE exthandle=%s',
                        _todb((handle.upper(),)))
    return self._makeplist()
  def persons_by_name(self, name):
    self._dbc.execute('SELECT id FROM contacts WHERE lower(name)=%s' \
                      ' AND email IS NOT NULL', _todb((name.lower(),)))
    return self._makeplist()
  def persons_by_email(self, email):
    self._dbc.execute('SELECT id FROM contacts WHERE lower(email)=%s',
                      _todb((email.lower(),)))
    return self._makeplist()
  def domain_by_name(self, name):
    name = name.upper()
    self._dbc.execute('SELECT id, updated_by, updated_on'
                      ' FROM whoisdomains WHERE fqdn=%s',
                      _todb((name,)))
    if self._dbc.rowcount == 0:
      return None
    assert self._dbc.rowcount == 1
    did, upby, upon = _fromdb(self._dbc.fetchone())
    return Domain(self._dbc, did, name, upby, upon)
  def domains_by_handle(self, handle):
    if not handle.upper().endswith(handlesuffix):
      # external handle
      self._dbc.execute('SELECT DISTINCT(whoisdomains.id) FROM '
                        ' whoisdomains, contacts, domain_contact'
                        ' WHERE contacts.exthandle=%s'
                        ' AND contacts.id = domain_contact.contact_id'
                        ' AND whoisdomains.id = domain_contact.whoisdomain_id',
                        _todb((handle.upper(),)))
    else:
      self._dbc.execute('SELECT DISTINCT(whoisdomains.id) FROM '
                        ' whoisdomains, contacts, domain_contact'
                        ' WHERE contacts.handle=%s'
                        ' AND contacts.id = domain_contact.contact_id'
                        ' AND whoisdomains.id = domain_contact.whoisdomain_id',
                        _todb((suffixstrip(handle.upper()),)))
    return self._makedlist()
  
class Main:
  comment_re = re.compile('^\s*(?:#|%)')
  white_re = re.compile('^\s*$')
  empty_re = re.compile('^$')
  longattr_re = re.compile('^([a-z-]+):\s*(.*\S)\s*$')
  shortattr_re = re.compile('^\*([a-zA-Z][a-zA-Z]):\s*(.*\S)\s*$')
  def _reset(self):
    self.ndom = 0
    self.nperson = 0
    self.ambig = 0
    self.inval = 0
  def __init__(self, dbh):
    self._dbh = dbh
    self._dbc = dbh.cursor()
    fetch_dbencoding(self._dbc)
    self._lookup = Lookup(self._dbc)
    self._reset()
  def process(self, o, dodel, persons=None, forcechanged=None):
    """Handle object creation/updating/deletion.
       Return True if ok, False otherwise.
    """
    if persons == None:
      persons = {}
    if 'XX' in o:
      # deleted object, ignore
      return True
    encoding = o['encoding']
    if forcechanged != None:
      o['ch'] = [ forcechanged ]
    elif 'ch' in o:
      for i in range(len(o['ch'])):
        email, t = parse_changed(o['ch'][i])
        if (email, t) == (None, None):
          return False
        if t == None:
          # "changed:" line without a date
          t = self.now
        o['ch'][i] = email, t
    if 'dn' in o:
      # domain object
      i = o['dn'][0].upper()
      if dodel:
        # XXX: compare!
        ld = self._lookup.domain_by_name(i)
        if ld != None:
          ld.delete()
          print "Object deleted:"
          print ld
          return True
      self.ndom += 1
      ld = self._lookup.domain_by_name(i)
      if ld != None:
        # domain already exists
        ld.fetch()
        newdom = Domain(self._dbc, ld.did)
        r = newdom.from_ripe(o, persons)
        sys.stdout.write(newdom.format_msgs().encode(encoding))
        if r == None:
          # something incorrect in provided attributes
          return False
        ambig, inval = r
        if ambig or inval:
          return False
        # compare with new object
        if ld != newdom or ld.ct.d['ad'] != newdom.ct.d['ad']:
          # they differ, update database
          print "Object updated from:"
          print ld.__str__().encode(encoding)
          newdom.ct.cid = ld.ct.cid
          newdom.update()
          print "Object updated to:"
          print newdom.__str__().encode(encoding)
          self.ambig += ambig
          self.inval += inval
        else:
          print "Object already exists:"
          print ld.__str__().encode(encoding)
      else:
        # make domain object
        ld = Domain(self._dbc)
        r = ld.from_ripe(o, persons)
        sys.stdout.write(ld.format_msgs().encode(encoding))
        if r == None:
          # something incorrect in provided attributes
          return False
        ambig, inval = r
        if ambig or inval:
          return False
        # store to database
        ld.insert()
        print "Object created:"
        print ld.__str__().encode(encoding)
        self.ambig += ambig
        self.inval += inval
    elif 'pn' in o:
      # person object
      self.nperson += 1
      ct = Person(self._dbc)
      r = ct.from_ripe(o)
      sys.stdout.write(ct.format_msgs().encode(encoding))
      if not r:
        return False
      name = o['pn'][0].lower()
      if 'eh' in o and o['eh'][0] != None:
        ehandle = o['eh'][0].lower()
      else:
        ehandle = None
      if 'nh' in o and o['nh'][0] != None:
        # has a NIC handle, try to find if already in the base
        handle = suffixadd(o['nh'][0]).lower()
        lp = self._lookup.persons_by_handle(handle)
        assert len(lp) <= 1
        if len(lp) == 1:
          c = lp[0]
          # found, compare
          c.fetch()
          if dodel:
            if ct != c:
              print "ERROR: Cannot delete: not the same object"
              return False
            else:
              print "Object deleted:"
              print ct.__str__().encode(encoding)
              ct.delete()
          else:
            if ct != c:
              print "Object updated from:"
              print c.__str__().encode(encoding)
              print "Object updated to:"
              ct.cid = c.cid
              ct.update()
            else:
              ct = c
              print "Object already exists:"
        else:
          # not found
          if dodel:
            print "ERROR: Cannot delete: not found"
            return False
          else:
            ct.insert()
            print "Object created:"
        if not dodel:
          print ct.__str__().encode(encoding)
          # keep for contact assignment
          persons.setdefault(handle, []).append(ct)
          persons.setdefault(name, []).append(ct)
          persons.setdefault(ehandle, []).append(ct)
      elif dodel:
        print "ERROR: Cannot delete: no handle provided"
        return False
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
        print ct.__str__().encode(encoding)
        # keep for contact assignment
        persons.setdefault(name, []).append(ct)
        persons.setdefault(ehandle, []).append(ct)
    elif 'mt' in o:
      # maintainer object, ignore
      pass
    elif 'XX' in o:
      # deleted object, ignore
      pass
    else:
      print "ERROR: Unknown object type"
      print str(o)
      return False
    return True

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
      return self.process(o, dodel, persons, forcechanged)
    return True

  def parsefile(self, file, encoding=DEFAULTENCODING, commit=True,
                forcechangedemail=None):
    """Parse file and reorder objects before calling process()."""
    o = { 'encoding': encoding }
    persons = {}
    nohandle = []
    domains = {}
    dodel = False
    err = 0

    self._dbh.autocommit(0)
    self._dbc.execute('START TRANSACTION')

    # Get transaction date
    self._dbc.execute("SELECT NOW()")
    assert self._dbc.rowcount == 1
    self.now, = self._dbc.fetchone()

    if forcechangedemail != None:
      forcechanged = (forcechangedemail, self.now)
    else:
      forcechanged = None

    # lock contact table from the start;
    # this is necessary to avoid deadlocks if we need to allocate handles:
    #  - p1 does a SELECT on contact c1
    #  - p2 does a SELECT on contact c2
    #  - p1 blocks waiting for a lock on the full contact table
    #  - p2 blocks waiting for a lock on the full contact table
    self._dbc.execute("LOCK TABLE contacts IN ACCESS EXCLUSIVE MODE")

    for l in file:
      if self.comment_re.search(l):
        # skip comment
        continue
      if self.white_re.search(l) and len(o) > 1:
        # white line or empty line and o is not empty:
        # end of object, process then cleanup for next object.
        if not self._order(o, dodel, persons, nohandle, domains, forcechanged):
          err += 1
        o = { 'encoding': encoding }
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
          print "ERROR: Unrecognized line:", l
          err += 1
          continue
        a, v = m.groups()
        if not a in ripe_ltos:
          print "ERROR: Unrecognized attribute \"%s\"" % a
          err += 1
          continue
        a = ripe_ltos[a]
      if a == 'delete':
        # mark for deletion
        dodel = True
      else:
        # new or multi-valued attribute
        o.setdefault(a, []).append(v)
    # end of file
    if len(o) > 1:
      # end of file: process last object
      if not self._order(o, dodel, persons, nohandle, domains, forcechanged):
        err += 1

    for p in nohandle:
      if not self.process(p, False, persons, forcechanged):
        err += 1

    # now that contacts are ready to be used, insert domain_contact records
    # from the domain list we gathered.
    for i in sorted(domains.keys()):
      if not self.process(domains[i], False, persons, forcechanged):
        err += 1

    if commit and err == 0:
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
    if err:
      print err, "error(s), aborting"
    return err == 0
