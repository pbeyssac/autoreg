#!/usr/local/bin/python
# $Id$

from __future__ import absolute_import
from __future__ import print_function
from __future__ import unicode_literals

import datetime
import io
import sys
import time

import six

# local modules
from autoreg.conf import DEFAULT_GRACE_DAYS
import autoreg.zauth as zauth
from . import check
from . import parser

class DnsDbError(Exception):
    pass
class DomainError(DnsDbError):
    DNOTFOUND = 'Domain not found'
    ZNOTFOUND = 'Zone not found'
    ZNOTHERE = 'Zone not found or not managed here'
    ZEXISTS = 'Zone already exists'
    DEXISTS = 'Domain already exists'
    NOTINDOM = 'Label value not in domain'
    NODOT = 'Resource-record value not dot-terminated'
    RRUNSUP = 'Unsupported resource-record type'
    DINVALID = 'Invalid domain name'
    pass
class AccessError(DnsDbError):
    DLENSHORT = 'Domain length too short'
    DLENLONG = 'Domain length too long'
    DLOCKED = 'Domain is locked'
    DHELD = 'Domain is held'
    DNOTDELETED = 'Domain has not been deleted'
    DINTERNAL = 'Domain is internal'
    NOAUTH = 'Not authorized for zone'
    ILLRR = 'Illegal record type in zone'
    UNKLOGIN = 'Unknown login'
    NOTLOGGED = 'Not logged in'
    pass

_dotted_rr = ['CNAME', 'DNAME', 'MX', 'NS', 'PTR']

def undot_value(rrtype, value):
    if rrtype in _dotted_rr:
        value = value.rstrip('.')
    return value

def redot_value(rrtype, value):
    if rrtype in _dotted_rr:
        return value + '.'
    return value

class _Zone:
    def __init__(self, dbc, name=None, id=None):
	self._dbc = dbc
	self.name = name
	self.id = id
    def set_updateserial(self):
	"""Mark zone for serial update in SOA."""
	assert self.id is not None
	self._updateserial = True
	self._dbc.execute('UPDATE zones SET updateserial=TRUE WHERE id=%s',
			  (self.id,))
    def soa(self, forceincr=False):
	"""Update serial for zone in SOA if necessary or forceincr is True."""
	zid = self.id
	serial = self._soaserial
	assert zid is not None and serial is not None
	if not self._updateserial and not forceincr: return (False, serial)
	year, month, day, h, m, s, wd, yd, dst = time.localtime()
	newserial = int("%04d%02d%02d00"%(year,month,day))
	if serial < newserial:
	    serial = newserial
	else:
	    serial += 1
	self._soaserial = serial
	self._updateserial = False
	self._dbc.execute('UPDATE zones SET soaserial=%s, updateserial=FALSE '
			  'WHERE id=%s', (serial,zid))
	return (True, serial)
    def fetch(self, wlock=True):
	"""Fetch zone info from database, using self.name as a key.

	Lock zone row for update if wlock is True.
	"""
	q='SELECT id,ttl,soaserial,soarefresh,soaretry,soaexpires,' \
	  'soaminimum,soaprimary,soaemail,updateserial,minlen,maxlen ' \
	  'FROM zones WHERE name=%s'
	if wlock: q += ' FOR UPDATE'
	self._dbc.execute(q, (self.name,))
	if self._dbc.rowcount == 0:
	    raise DomainError(DomainError.ZNOTFOUND, self.name)
	assert self._dbc.rowcount == 1
	(self.id, self._ttl, self._soaserial,
	 self._soarefresh,self._soaretry, self._soaexpires, self._soaminimum,
	 self._soaprimary, self._soaemail, self._updateserial,
	 self.minlen, self.maxlen) = self._dbc.fetchone()
    def checktype(self, rrtype):
	"""Check rrtype is allowed in zone."""
	if rrtype is None: return
	zid = self.id
	self._dbc.execute('SELECT zone_id,rrtype_id FROM allowed_rr '
		'WHERE allowed_rr.zone_id=%s '
		'AND allowed_rr.rrtype_id='
		'(SELECT id FROM rrtypes WHERE rrtypes.label=%s)',
		(zid, rrtype))
	if self._dbc.rowcount == 1: return
	assert self._dbc.rowcount == 0
	raise AccessError(AccessError.ILLRR, rrtype, zid)
    def cat(self):
	"""Output zone file to stdout."""
	print("; zone name=%s id=%d" % (self.name, self.id))
	if self._ttl is not None: print('$TTL', self._ttl)
	print("@\tSOA\t%s %s %d %d %d %d %d" %
	    (self._soaprimary, self._soaemail, self._soaserial,
	     self._soarefresh, self._soaretry,
	     self._soaexpires, self._soaminimum))

	self._dbc.execute(
	    'SELECT rrs.label,domains.name,rrs.ttl,rrtypes.label,rrs.value '
	    'FROM domains,rrs,rrtypes '
	    'WHERE domains.zone_id=%s AND domains.registry_hold=FALSE '
	    'AND domains.id=rrs.domain_id AND rrtypes.id=rrs.rrtype_id '
	    'ORDER BY domains.name,rrs.label,rrtypes.label,rrs.value',
	    (self.id,))

	# Loop over returned rows, printing as we go.
	t = self._dbc.fetchone()
	lastlabel = '@'
	while t:
	    (label, domain, ttl, typ, value) = t
	    # "uncompress"
	    value = redot_value(typ, value)
	    # prepare label
	    if label != '' and domain != '':
		l = label + '.' + domain
	    elif label+domain == '':
		l = self.name + '.'
	    else:
		l = label + domain
	    if l == self.name+'.':
		l = '@'
	    if ttl is None: ttl = ''
	    else: ttl = str(ttl)+'\t'
	    # print line, removing label if possible
	    # for compactness and clarity
	    if l == lastlabel:
		l = ''
	    else:
		lastlabel = l
	    print("%s\t%s%s\t%s" % (l, ttl, typ, value))
	    t = self._dbc.fetchone()
    def lock(self):
	"""Lock zone row for update."""
	assert self.id is not None
	self._dbc.execute('SELECT NULL FROM zones WHERE id=%s FOR UPDATE',
			  (self.id,))

class _Domain:
    def __init__(self, dbc, id=None, name=None, zone_name=None):
	self._dbc = dbc
	self.id = id
	self.name = name
	self._zone_name = zone_name
    def new(self, z, login_id, internal=False):
	self._dbc.execute(
	  'INSERT INTO domains '
	  '(name,zone_id,created_by,created_on,updated_by,updated_on,internal)'
	  ' VALUES (%s,%s,%s,NOW(),%s,NOW(),%s)',
	  (self.name, z.id, login_id, login_id, internal))
	self._dbc.execute("SELECT currval('domains_id_seq')")
	assert self._dbc.rowcount == 1
	self.id, = self._dbc.fetchone()
    def fetch(self, wlock=False):
	"""Fetch domain information in memory.

	wlock: if set, take a write lock on the domain and zone records
	"""
	did = self.id
	if wlock: fud=' FOR UPDATE'
	else: fud=''
	self._dbc.execute('SELECT domains.name, zones.name, registry_hold, '
			  'registry_lock, internal, zone_id, registrar_id, '
			  'created_by, created_on, updated_by, updated_on, '
			  'end_grace_period '
			  'FROM domains, zones '
			  'WHERE domains.id=%s AND zones.id=domains.zone_id'
			  +fud, (did,))
	if self._dbc.rowcount == 0:
	    raise DomainError('Domain id not found', did)
	assert self._dbc.rowcount == 1
	(self.name, self._zone_name, self._registry_hold, self._registry_lock,
	 self._internal, self._zone_id, self._registrar_id,
	 idcr, self._created_on, idup, self._updated_on,
         self._end_grace_period) = self._dbc.fetchone()
        if six.PY2:
          self._zone_name = unicode(self._zone_name)
          self.name = unicode(self.name)
	# "GRANT SELECT" perms do not allow "SELECT ... FOR UPDATE",
	# hence the request below is done separately from the request above.
	self._dbc.execute('SELECT ad1.login, ad2.login '
			  'FROM admins AS ad1, admins AS ad2 '
			  'WHERE ad1.id=%s AND ad2.id=%s', (idcr, idup))
	assert self._dbc.rowcount == 1
	self._created_by, self._updated_by = self._dbc.fetchone()
	return True
    def mod_rr(self, f, delete=False):
	"""Add/remove resource records to domain from file.

	f: resource records in zone file format
	domain_name, zone_name and domain_id should be set.
	"""
	dom, zone, did = self.name, self._zone_name, self.id
	assert dom is not None and zone is not None and did is not None
	dp = parser.DnsParser()
	# convenient default label if none provided on first line of file
	label = ''
	rowcount = 0
	for l in f:
	    t = dp.parseline(l)
	    if t is None:
		# Was a comment or empty line
		continue
	    newlabel, ttl, typ, value = t
	    if newlabel != '':
		label = newlabel
		if label.endswith('.'):
		    if label.endswith('.'+zone+'.'):
			label = label[:-len(zone)-2]
		    elif label == zone+'.':
			label = ''
		    else:
			raise DomainError(DomainError.NOTINDOM, label, zone)
		if label.endswith('.'+dom):
		    label = label[:-len(dom)-1]
		elif label == dom:
		    label = ''
	    # More tests which do not belong in the parser.
	    # Check & "compress" the value field somewhat.
	    if typ in _dotted_rr:
		if not value.endswith('.'):
		    raise DomainError(DomainError.NODOT, value)
		value = value[:-1]
	    elif typ in ['A', 'AAAA', 'DLV', 'DNSKEY', 'DS', 'HINFO',
			 'RRSIG', 'SSHFP', 'SRV', 'TLSA', 'TXT']:
		pass
	    else:
		raise DomainError(DomainError.RRUNSUP, typ)
	    if not delete:
	      self._dbc.execute('INSERT INTO rrs '
		'(domain_id,label,ttl,rrtype_id,value) '
		'VALUES (%s,%s,%s,(SELECT id FROM rrtypes WHERE label=%s),%s)',
		(did, label, ttl, typ, value))
	    else:
	      self._dbc.execute('DELETE FROM rrs '
		'WHERE domain_id=%s AND label=%s '
		'AND rrtype_id IN (SELECT id FROM rrtypes WHERE label=%s) '
		'AND value = %s',
		(did, label, typ, value))
	    rowcount += self._dbc.rowcount
	return rowcount

    def queryrr(self, label, rrtype):
        """Query records of a given label and type.
        label can be None for *
        rrtype can be None for ANY
        """
        if rrtype is not None:
          rrtype = rrtype.upper()
        self._dbc.execute("SELECT rrs.label, ttl, rrtypes.label, value"
            " FROM rrs, rrtypes"
            " WHERE (rrtype_id=(SELECT id FROM rrtypes WHERE label=%s)"
                  " OR %s IS NULL)"
            " AND rrtypes.id = rrs.rrtype_id"
            " AND domain_id=%s AND (rrs.label=%s OR %s is NULL)"
            " ORDER BY (rrs.label, rrtypes.label, value, ttl)",
            (rrtype, rrtype, self.id, label, label));
        return [ (rr[0], rr[1], rr[2], redot_value(rr[2], rr[3]))
                 for rr in self._dbc.fetchall() ]

    def existsrr(self, label, rrtype):
        """Count records of a given label and type"""
        rrtype = rrtype.upper()
        self._dbc.execute("SELECT EXISTS (SELECT 1 FROM rrs"
            " WHERE rrtype_id=(SELECT id FROM rrtypes WHERE label=%s)"
            " AND domain_id=%s AND label=%s)", (rrtype, self.id, label));
        assert self._dbc.rowcount == 1
        n, = self._dbc.fetchone()
        return n

    def addrr(self, label, ttl, rrtype, value):
        """Add records of a given label, TTL, type and value"""
        dp = parser.DnsParser()
        label, ttl, rrtype, value = dp.normalizeline(label, ttl, rrtype, value)
        self._dbc.execute("INSERT INTO rrs"
            " (domain_id, label, ttl, rrtype_id, value) "
            " VALUES (%s, %s, %s, (SELECT id FROM rrtypes WHERE label=%s), %s)",
             (self.id, label, ttl, rrtype, undot_value(rrtype, value)));
        assert self._dbc.rowcount == 1

    def delrr(self, label, rrtype, value):
        """Delete at most 1 record of a given label, type and value."""
        rrtype = rrtype.upper()
        # This is like a (non-existing) DELETE ... LIMIT 1,
        # using hidden-field ctid.
        self._dbc.execute("DELETE FROM rrs WHERE ctid = (SELECT ctid FROM rrs"
            " WHERE rrtype_id=(SELECT id FROM rrtypes WHERE label=%s)"
            " AND domain_id=%s AND label=%s AND value=%s LIMIT 1)",
             (rrtype, self.id, label, undot_value(rrtype, value)));
        return self._dbc.rowcount

    def set_updated_by(self, login_id):
        """Set updated_by and updated_on."""
        self._dbc.execute('UPDATE domains '
                          'SET updated_by=%s, updated_on=NOW() '
                          'WHERE id=%s', (login_id, self.id))
    def move_hist(self, login_id, domains=False, keepds=False, onlyds=False):
	"""Move resource records to history tables, as a side effect
	(triggers) of deleting them.

        The following flags are exclusive of each other:
          keepds: if set, move all but DS records.
          onlyds: if set, only move DS records.
	  domains: if set, also move domain and associated contact records.
	"""
	did = self.id
        if keepds:
	  self._dbc.execute("DELETE FROM rrs WHERE domain_id=%s"
            " AND"
            " rrtype_id<>(SELECT id FROM rrtypes WHERE rrtypes.label='DS')",
            (did,))
        elif onlyds:
	  self._dbc.execute("DELETE FROM rrs WHERE domain_id=%s"
            " AND"
            " rrtype_id=(SELECT id FROM rrtypes WHERE rrtypes.label='DS')",
            (did,))
        else:
	  self._dbc.execute('DELETE FROM rrs WHERE domain_id=%s', (did,))
	if domains:
	    self._dbc.execute('DELETE FROM domains WHERE id=%s', (did,))
    def show_head(self, outfile=sys.stdout):
	"""Show administrative data for domain."""
	print(u"; zone", self._zone_name, file=outfile)
	if self.name == '':
	    print(u"; domain", self._zone_name, file=outfile)
	else:
	    print(u"; domain", '.'.join((self.name,self._zone_name)),
                  file=outfile)
	if self._created_on:
	    print(u"; created: by %s, %s"
                   % (self._created_by, self._created_on), file=outfile)
	if self._updated_on:
	    print(u"; updated: by %s, %s"
                   % (self._updated_by, self._updated_on), file=outfile)
	if self._registry_lock: print(u"; registry_lock", file=outfile)
	if self._registry_hold: print(u"; registry_hold", file=outfile)
	if self._internal: print(u"; internal", file=outfile)
	if self._end_grace_period:
	    print(u"; end_grace_period: %s"
                   % self._end_grace_period, file=outfile)
    def show_rrs(self, outfile=sys.stdout):
	"""List all resource records for domain."""
	self._dbc.execute(
	    'SELECT rrs.label,domains.name,rrs.ttl,rrtypes.label,rrs.value '
	    'FROM domains,rrs,rrtypes '
	    'WHERE domains.id=%s AND domains.id=rrs.domain_id '
	    'AND rrtypes.id=rrs.rrtype_id '
	    'ORDER BY domains.name,rrs.label,rrtypes.label,rrs.value',
	    (self.id,))
	lastlabel = ''
	t = self._dbc.fetchone()
	while t:
	    label, dom, ttl, typ, value = t

	    # "uncompress"
	    value = redot_value(typ, value)

	    # handle label
	    if label != '' and dom != '':
		l = label + '.' + dom
	    else:
		l = label + dom
	    if l == lastlabel: l = ''
	    else: lastlabel = l 

	    # tabulate output
	    if len(l) > 15: pass
	    elif len(l) > 7: l += '\t'
	    else: l += "\t\t"
	    if ttl is None: ttl = ''
	    else: ttl = str(ttl)

	    print(u"\t".join((l, ttl, typ, value)), file=outfile)
	    t = self._dbc.fetchone()
	if self._dbc.rowcount == 0:
	    print(u'; (NO RECORD)', file=outfile)
    def show(self, rrs_only=False, outfile=sys.stdout):
	"""Shorthand to call show_head() then show_rrs()."""
        if not rrs_only:
	  self.show_head(outfile)
	self.show_rrs(outfile)
    def set_registry_lock(self, val):
	"""Set value of boolean registry_lock."""
	self._registry_lock = val
	self._dbc.execute('UPDATE domains SET registry_lock=%s WHERE id=%s',
			  (val, self.id))
    def set_registry_hold(self, val):
	"""Set value of boolean registry_hold."""
	self._registry_hold = val
	self._dbc.execute('UPDATE domains SET registry_hold=%s WHERE id=%s',
			  (val, self.id))
    def set_end_grace_period(self, val):
	"""Set value of the end time of the grace period and registry_hold,
        or remove if val is None."""
        if val is None:
          d = None
          hold = False
        else:
          d = datetime.datetime.fromtimestamp(val)
          hold = True
	self._end_grace_period = d
        # do it in one update to avoid generating two lines in domains_hist
	self._dbc.execute('UPDATE domains'
                          ' SET registry_hold=%s, end_grace_period=%s'
                          ' WHERE id=%s',
			  (hold, d, self.id))

class _ZoneList:
    """Cache zone list from database."""
    def __init__(self, dbc):
        self._dbc = dbc
	self.zones = {}
	self._dbc.execute('SELECT name, id FROM zones')
	t = self._dbc.fetchone()
	while t:
	    name, zid = t
            if six.PY2:
              name = unicode(name)
	    self.zones[name] = _Zone(dbc, id=zid, name=name)
	    t = self._dbc.fetchone()
    def newzone(self, name):
	"""Create a new zone."""
	name = name.upper()
	if name in self.zones:
	    raise DomainError(DomainError.ZEXISTS, self.name)
	self._dbc.execute(
	  'INSERT INTO zones '
	  '(name,minlen,maxlen,ttl,updateserial,'
	  'soaserial,soarefresh,soaretry,soaexpires,soaminimum,'
	  'soaprimary,soaemail)'
	  ' VALUES (%s,2,24,259200,FALSE,1,3600,1800,12096000,259200,'
	  '%s,%s)',
	  (name, 'ns.eu.org.', 'hostmaster.eu.org.'))
	self._dbc.execute("SELECT currval('zones_id_seq')")
	assert self._dbc.rowcount == 1
	zid, = self._dbc.fetchone()
	self.zones[name] = _Zone(self._dbc, id=zid, name=name)
	return self.zones[name]
    def get(self):
        """Return list of all known zones except root."""
        zonelist = self.zones.keys()
        zonelist.remove('')
        zonelist.sort()
        return zonelist
    def split(self, domain, zone=None):
	"""Split domain name according to known zones."""
	domain = domain.upper()
	if zone is not None:
            # zone name is provided, just check it exists
	    zone = zone.upper()
	    if zone not in self.zones:
		return (None, None)
	    if domain.endswith('.'+zone):
		dom = domain[:-len(zone)-1]
	    elif domain == zone:
		dom = ''
	    else:
		return (None, None)
	    return (dom, self.zones[zone])

        # try to find the right zone
	n = domain.split('.')
	for i in range(1, len(n)):
	    zone = '.'.join(n[i:])
	    if zone in self.zones:
		dom = '.'.join(n[:i])
		return (dom, self.zones[zone])

        # try domain as a zone name as a last resort
        if domain in self.zones:
          return ('', self.zones[domain])

	return (None, None)
    def find(self, domain, zone, wlock=False, raise_nf=True):
	"""Find domain and zone id.

	If not found and raise_nf is True, raise an exception.
	Lock zone and domain for update if wlock is True.
	Return _Domain object, _Zone object.
	"""
	dname, z = self.split(domain, zone)
	if z is None:
            if '.' in domain:
              z = domain.split('.', 1)[1]
            else:
              z = domain
	    raise DomainError(DomainError.ZNOTFOUND, z)
	if wlock:
	    fu = ' FOR UPDATE'
	    z.lock()
	else:
	    fu = ''
	self._dbc.execute('SELECT id FROM domains WHERE name=%s AND zone_id=%s'
			  +fu, (dname, z.id))
	if self._dbc.rowcount == 0:
	    if raise_nf:
		raise DomainError(DomainError.DNOTFOUND, domain)
	    d = _Domain(self._dbc, id=None, name=dname, zone_name=z.name)
	    return (d, z)
	assert self._dbc.rowcount == 1
	did, = self._dbc.fetchone()
	d = _Domain(self._dbc, id=did, name=dname, zone_name=z.name)
	return (d, z)

class db:
    def __init__(self, dbhandle, nowrite=False):
        # At once, set transaction isolation level to READ COMMITTED.
        # (see autoreg.whois.db for details)
        dbhandle.set_isolation_level(1)
	self._dbh = dbhandle
	self._dbc = dbhandle.cursor()
	self._za = zauth.ZAuth(self._dbc)
	self._nowrite = nowrite
	self._login_id = None
        self._zl = _ZoneList(self._dbc)
    def login(self, login):
	"""Login requested user."""
        if login == 'DNSADMIN':
	  self._login_id = 0
	  self._login = login
	  return self._login_id
	self._dbc.execute('SELECT id FROM admins WHERE login=%s', (login,))
	if self._dbc.rowcount == 0:
	    raise AccessError(AccessError.UNKLOGIN, login)
	assert self._dbc.rowcount == 1
	lid, = self._dbc.fetchone()
	self._login_id = lid
	self._login = login
	return self._login_id
    def _check_login_perm(self, zone=None):
	"""Check someone has logged-in and has permission for the zone."""
	if self._login_id is None:
	    raise AccessError(AccessError.NOTLOGGED)
	if self._nowrite:
	    return
	if zone is not None and not self._za.check(zone, self._login):
	    raise AccessError(AccessError.NOAUTH, self._login, zone)
    def logout(self):
	"""Logout current user."""
	self._check_login_perm()
	self._login_id = None
    def show(self, domain, zone, rrs_only=False, outfile=sys.stdout):
	"""Show a pretty-printed zone excerpt for domain."""
	d, z = self._zl.find(domain, zone)
	self._check_login_perm(z.name)
	d.fetch()
	d.show(rrs_only=rrs_only, outfile=outfile)
    def delete(self, domain, zone, override_internal=False,
               grace_days=DEFAULT_GRACE_DAYS,
               commit=True):
	"""Delete domain.

	domain: FQDN of domain name
	override_internal: if set, allow modifications to internal domains
	"""
	d, z = self._zl.find(domain, zone, wlock=True)
	self._check_login_perm(z.name)
	d.fetch(wlock=True)
	if d._registry_lock:
	    raise AccessError(AccessError.DLOCKED)
	if d._internal and not override_internal:
	    raise AccessError(AccessError.DINTERNAL)
	if d._registry_hold \
          and (d._end_grace_period is None or grace_days != 0):
	    raise AccessError(AccessError.DHELD)
	if self._nowrite: return
        if grace_days != 0:
	    d.set_end_grace_period(time.time()+grace_days*86400)
        else:
	    d.move_hist(login_id=self._login_id, domains=True)
	z.set_updateserial()
        if commit:
	    self._dbh.commit()
    def undelete(self, domain, zone, override_internal=False, commit=True):
	"""Undelete domain.

	domain: FQDN of domain name
	override_internal: if set, allow modifications to internal domains
	"""
	d, z = self._zl.find(domain, zone, wlock=True)
	self._check_login_perm(z.name)
	d.fetch(wlock=True)
	if d._registry_lock:
	    raise AccessError(AccessError.DLOCKED)
	if d._internal and not override_internal:
	    raise AccessError(AccessError.DINTERNAL)
	if not d._registry_hold or not d._end_grace_period:
	    raise AccessError(AccessError.DNOTDELETED)
	if self._nowrite: return
	d.set_end_grace_period(None)
	z.set_updateserial()
        if commit:
	    self._dbh.commit()
    def modify(self, domain, zone, typ, file, override_internal=False,
	       replace=True, delete=False, keepds=True, _commit=True):
	"""Modify domain.

	domain: FQDN of domain name
	file: RR records in zone file format
	typ: string; if set, check zone allows this resource-record type
	override_internal: if set, allow modifications to internal domains
	_commit: default True, can be set to False to skip the DB commit
	"""
	d, z = self._zl.find(domain, zone, wlock=True)
	self._check_login_perm(z.name)
	z.checktype(typ)
	d.fetch(wlock=True)
	if d._registry_lock:
	    raise AccessError(AccessError.DLOCKED)
	if d._internal and not override_internal:
	    raise AccessError(AccessError.DINTERNAL)
	if self._nowrite: return
	if replace and not delete:
	  d.move_hist(login_id=self._login_id, domains=False, keepds=keepds)
	# add new resource records
	d.mod_rr(file, delete=delete)
	d.set_updated_by(self._login_id)
	z.set_updateserial()
	if _commit:
	    self._dbh.commit()
    def modifydeleg(self, domain, file, override_internal=False,
		    replace=True, delete=False):
	"""Modify a domain delegation in the child and the parent at the
	same time.

	domain: FQDN of domain name
	file: RR records in zone file format
	override_internal: if set, allow modifications to internal domains
	"""
	records = ''.join([l for l in file])
        if '.' not in domain:
	    raise DomainError(DomainError.DNOTFOUND)
	label, parent = domain.split('.', 1)
	rrfile = io.StringIO(unicode(records))
	self.modify(domain, parent, None, rrfile,
		    override_internal, replace, delete, _commit=False)
	rrfile = io.StringIO(unicode(records))
	self.modify(domain, domain, None, rrfile,
		    override_internal, replace, delete, _commit=True)
    def queryrr(self, domain, zone, label, rrtype):
	"""Query within domain for records with rrtype and that label.
	domain: FQDN of domain name
        zone: zone to look into. Mostly relevant for NS and glue.
        label: record label
        rrtype: resource record type ('MX', etc, uppercase text)
	"""
	d, z = self._zl.find(domain, zone)
	self._check_login_perm(z.name)
	d.fetch()
        return d.queryrr(label, rrtype)
    def addrr(self, domain, zone, label, ttl, rrtype, value, _commit=True):
        """Add records of a given label, TTL, type and value"""
	d, z = self._zl.find(domain, zone)
	self._check_login_perm(z.name)
	d.fetch()
	if self._nowrite:
	    return
        d.addrr(label, ttl, rrtype, value)
	z.set_updateserial()
	if _commit:
	    self._dbh.commit()
    def delrr(self, domain, zone, label, rrtype, value, _commit=True):
        """Delete records of a given label, type and value"""
	d, z = self._zl.find(domain, zone)
	self._check_login_perm(z.name)
	d.fetch()
	if self._nowrite:
	    return 0
        n = d.delrr(label, rrtype, value)
        if n:
	    z.set_updateserial()
	if _commit:
	    self._dbh.commit()
        return n
    def checkds(self, domain, zone):
        """Check whether domain is eligible for DS records
        domain: FQDN of domain name
        """
        d, z = self._zl.find(domain, zone)
        self._check_login_perm(z.name)
        try:
            z.checktype('DS')
        except AccessError as e:
            return False, e[0]
        d.fetch()
        nns = d.existsrr('', 'NS')
        if nns:
            return True, None
        return False, "No NS records for domain"
    def commit(self):
        """Commit pending transaction."""
	self._dbh.commit()
    def new(self, domain, zone, typ, file=None, internal=False, commit=True):
	"""Create domain.

	domain: full domain name
	file: RR records in zone file format
	typ: string; if set, check zone allows this resource-record type
	internal: if set, protect domain from user requests and bypass
		length checks.
	"""
        if not check.checkfqdn(domain):
	  raise DomainError(DomainError.DINVALID, domain)
	d, z = self._zl.find(domain, zone, wlock=True, raise_nf=False)
	self._check_login_perm(z.name)
	if d.id is not None:
	    raise DomainError(DomainError.DEXISTS, domain)
        if '.' in d.name:
	    raise DomainError(DomainError.ZNOTHERE, domain.split('.', 1)[1])
	z.checktype(typ)
	z.fetch()
	if len(d.name) < z.minlen and not internal:
	    raise AccessError(AccessError.DLENSHORT, (z.name, z.minlen))
	if len(d.name) > z.maxlen and not internal:
	    raise AccessError(AccessError.DLENLONG, (z.name, z.maxlen))
	if self._nowrite: return
        d.new(z, self._login_id, internal)
	# add resource records, if provided
	if file:
	    d.mod_rr(file)
	z.set_updateserial()
        if commit:
	    self._dbh.commit()
    def set_registry_lock(self, domain, zone, val):
	"""Set registry_lock flag for domain."""
	d, z = self._zl.find(domain, zone, wlock=True)
	self._check_login_perm(z.name)
	if self._nowrite: return
	d.set_registry_lock(val)
	self._dbh.commit()
    def set_registry_hold(self, domain, zone, val):
	"""Set registry_hold flag for domain."""
	d, z = self._zl.find(domain, zone, wlock=True)
	self._check_login_perm(z.name)
	if self._nowrite: return
	d.set_registry_hold(val)
	z.set_updateserial()
	self._dbh.commit()
    def soa(self, zone, forceincr=False):
	"""Update SOA serial for zone if necessary or forceincr is True."""
	z = self._zl.zones[zone.upper()]
	z.fetch()
	(r, serial) = z.soa(forceincr)
	self._dbh.commit()
        return r, serial
    def cat(self, zone):
	"""Output zone file to stdout."""
	z = self._zl.zones[zone.upper()]
	z.fetch()
	z.cat()
    def zonelist(self):
        """Return zone list."""
        return self._zl.get()
    def newzone(self, zone, commit=True):
	"""Create a new zone for which we are master."""
	z = self._zl.newzone(zone.upper())
        if commit:
	  self._dbh.commit()
    def expired(self, now=False):
        """List domains in grace period."""
        if not now:
          self._dbc.execute('SELECT domains.name, zones.name, end_grace_period'
                            ' FROM domains, zones'
                            ' WHERE domains.zone_id=zones.id'
                            ' AND end_grace_period IS NOT NULL'
                            ' ORDER BY end_grace_period')
        else:
          self._dbc.execute('SELECT domains.name, zones.name, end_grace_period'
                            ' FROM domains, zones'
                            ' WHERE domains.zone_id=zones.id'
                            ' AND end_grace_period < NOW()'
                            ' ORDER BY end_grace_period')
        return self._dbc.fetchall()
