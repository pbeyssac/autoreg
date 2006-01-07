#!/usr/local/bin/python
# $Id$

import sre
import string
import time

# local modules
import dnsparser
import zauth

class DnsDbError(Exception):
    pass
class DomainError(DnsDbError):
    DNOTFOUND = 'Domain not found'
    ZNOTFOUND = 'Zone not found'
    DEXISTS = 'Domain already exists'
    NOTINDOM = 'Label value not in domain'
    NODOT = 'Resource-record value not dot-terminated'
    RRUNSUP = 'Unsupported resource-record type'
    pass
class AccessError(DnsDbError):
    DLENSHORT = 'Domain length too short'
    DLENLONG = 'Domain length too long'
    DLOCKED = 'Domain is locked'
    DINTERNAL = 'Domain is internal'
    pass

class _Zone:
    def __init__(self, dbc, name=None, id=None, nowrite=False):
	self._dbc = dbc
	self._name = name
	self._id = id
	self._nowrite = nowrite
    def set_updateserial(self):
	"""Mark zone for serial update in SOA."""
	assert self._id != None
	if self._nowrite: return
	self._updateserial = True
	self._dbc.execute('UPDATE zones SET updateserial=TRUE WHERE id=%d',
			  (self._id,))
    def soa(self):
	"""Update serial for zone in SOA if flagged as such."""
	zid = self._id
	serial = self._soaserial
	assert zid != None and serial != None
	if not self._updateserial: return
	if self._nowrite: return
	year, month, day, h, m, s, wd, yd, dst = time.localtime()
	newserial = int("%04d%02d%02d00"%(year,month,day))
	if serial < newserial:
	    serial = newserial
	else:
	    serial += 1
	self._soaserial = serial
	self._updateserial = False
	self._dbc.execute('UPDATE zones SET soaserial=%d, updateserial=FALSE '
			  'WHERE id=%d', (serial,zid))
    def fetch(self, wlock=True):
	"""Fetch zone info from database, using self._name as a key.

	Lock zone row for update if wlock is True.
	"""
	q='SELECT id,ttl,soaserial,soarefresh,soaretry,soaexpires,' \
	  'soaminimum,soaprimary,soaemail,updateserial,minlen,maxlen ' \
	  'FROM zones WHERE name=%s'
	if wlock: q += ' FOR UPDATE'
	self._dbc.execute(q, (self._name,))
	if self._dbc.rowcount == 0:
	    raise DomainError(DomainError.ZNOTFOUND, self._name)
	assert self._dbc.rowcount == 1
	(self._id, self._ttl, self._soaserial,
	 self._soarefresh,self._soaretry, self._soaexpires, self._soaminimum,
	 self._soaprimary, self._soaemail, self._updateserial,
	 self._minlen, self._maxlen) = self._dbc.fetchone()
    def checktype(self, rrtype):
	"""Check rrtype is allowed in zone."""
	if rrtype == None: return
	zid = self._id
	self._dbc.execute('SELECT zone_id,rrtype_id FROM allowed_rr '
		'WHERE allowed_rr.zone_id=%d '
		'AND allowed_rr.rrtype_id='
		'(SELECT id FROM rrtypes WHERE rrtypes.label=%s)',
		(zid, rrtype))
	if self._dbc.rowcount == 1: return
	assert self._dbc.rowcount == 0
	raise AccessError('Illegal record type in zone', rrtype, zid)
    def cat(self):
	"""Output zone file to stdout."""
	print "; zone name=%s id=%d" % (self._name, self._id)
	if self._ttl != None: print '$TTL', self._ttl
	print ("@\tSOA\t%s %s %d %d %d %d %d" %
	    (self._soaprimary, self._soaemail, self._soaserial,
	     self._soarefresh, self._soaretry,
	     self._soaexpires, self._soaminimum))

	self._dbc.execute(
	    'SELECT rrs.label,domains.name,rrs.ttl,rrtypes.label,rrs.value '
	    'FROM domains,rrs,rrtypes '
	    'WHERE domains.zone_id=%d AND domains.registry_hold=FALSE '
	    'AND domains.id=rrs.domain_id AND rrtypes.id=rrs.rrtype_id '
	    'ORDER BY domains.name,rrs.label,rrtypes.label,rrs.value',
	    (self._id,))

	# Loop over returned rows, printing as we go.
	t = self._dbc.fetchone()
	lastlabel = '@'
	while t:
	    (label, domain, ttl, type, value) = t
	    # "uncompress"
	    if type in ['CNAME', 'MX', 'NS']: value += '.'
	    # prepare label
	    if label != '' and domain != '':
		l = label + '.' + domain
	    elif label+domain == '':
		l = self._name + '.'
	    else:
		l = label + domain
	    if l == self._name+'.':
		l = '@'
	    if ttl == None: ttl = ''
	    else: ttl = str(ttl)
	    # print line, removing label if possible
	    # for compactness and clarity
	    if l == lastlabel:
		l = ''
	    else:
		lastlabel = l
	    print "%s\t%s%s\t%s" % (l, ttl, type, value)
	    t = self._dbc.fetchone()
	print "_EU-ORG-END-MARKER\tTXT\t\"%s\"" % self._soaserial
    def lock(self):
	"""Lock zone row for update."""
	assert self._id != None
	self._dbc.execute('SELECT NULL FROM zones WHERE id=%d FOR UPDATE',
			  (self._id,))

class _Domain:
    def __init__(self, dbc, id=None, name=None, zone_name=None):
	self._dbc = dbc
	self._id = id
	self._name = name
	self._zone_name = zone_name
    def fetch(self, wlock=False):
	"""Fetch domain information in memory.

	wlock: if set, take a write lock on the domain and zone records
	"""
	did = self._id
	if wlock: fud=' FOR UPDATE'
	else: fud=''
	self._dbc.execute('SELECT domains.name, zones.name, registry_hold, '
			  'registry_lock, internal, zone_id, registrar_id, '
			  'ad1.login, created_on, ad2.login, updated_on '
			  'FROM domains, zones, admins AS ad1, admins AS ad2 '
			  'WHERE domains.id=%d AND zones.id=domains.zone_id '
			  'AND created_by=ad1.id AND updated_by=ad2.id'
			  +fud, (did,))
	if self._dbc.rowcount == 0:
	    raise DomainError('Domain id not found', did)
	assert self._dbc.rowcount == 1
	(self._name, self._zone_name, self._registry_hold, self._registry_lock,
	 self._internal, self._zone_id, self._registrar_id,
	 self._created_by, self._created_on,
	 self._updated_by, self._updated_on) = self._dbc.fetchone()
	return True
    def add_rr(self, f):
	"""Add resource records to domain from file.

	f: resource records in zone file format
	domain_name, zone_name and domain_id should be set.
	"""
	dom, zone, did = self._name, self._zone_name, self._id
	assert dom != None and zone != None and did != None
	dp = dnsparser.DnsParser()
	# convenient default label if none provided on first line of file
	label = '.'.join((self._name, self._zone_name)) + '.'
	for l in f:
	    t = dp.parseline(l)
	    if t == None:
		# Was a comment or empty line
		continue
	    newlabel, ttl, type, value = t
	    if newlabel != '':
		label = newlabel
		if label.endswith('.'):
		    if label.endswith('.'+zone+'.'):
			label = label[:-len(zone)-2]
		    elif label == zone+'.':
			label = ''
		    else:
			raise DomainError(Domain.NOTINDOM, label, zone)
		if label.endswith('.'+dom):
		    label = label[:-len(dom)-1]
		elif label == dom:
		    label = ''
	    # More tests which do not belong in the parser.
	    # Check & "compress" the value field somewhat.
	    if type in ['CNAME', 'MX', 'NS']:
		if not value.endswith('.'):
		    raise DomainError(Domain.NODOT, value)
		value = value[:-1]
	    elif type in ['A', 'AAAA', 'SRV', 'TXT']:
		pass
	    else:
		raise DomainError(Domain.RRUNSUP, type)
	    print (did, label, ttl, type, value)
	    self._dbc.execute('INSERT INTO rrs '
		'(domain_id,label,ttl,rrtype_id,value) '
		'VALUES (%d,%s,%s,(SELECT id FROM rrtypes WHERE label=%s),%s)',
		(did, label, ttl, type, value))
    def move_hist(self, login_id, domains=False):
	"""Move resource records to history tables, deleting
	original records after copy.

	domains: if set, also move domain and associated contact records.
	"""
	did = self._id
	if domains:
	    # get a lock on contact information we're going to delete
	    self._dbc.execute('SELECT NULL FROM domain_contact'
		'WHERE domain_id=%d FOR UPDATE', (did,))
	self._dbc.execute('INSERT INTO rrs_hist '
		'(domain_id,ttl,rrtype_id,created_on,label,value,deleted_on) '
		'SELECT domain_id,ttl,rrtype_id,created_on,label,value,NOW() '
		'FROM rrs WHERE domain_id=%d', (did,))
	if domains:
	    self._dbc.execute('INSERT INTO domains_hist '
		'(id,name,zone_id,registrar_id,created_by,created_on,deleted_by,deleted_on) '
		'SELECT id,name,zone_id,registrar_id,created_by,created_on,%d,NOW() '
		'FROM domains WHERE id=%d', (login_id, did))
	    self._dbc.execute('INSERT INTO domain_contact_hist '
		'(domain_id,contact_id,contact_type_id,created_on) '
		'SELECT domain_id,contact_id,contact_type_id,created_on '
		'FROM domain_contact WHERE domain_id=%d', (did,))
	    self._dbc.execute('DELETE FROM domain_contact '
		'WHERE domain_id=%d', (did,))
	self._dbc.execute('DELETE FROM rrs WHERE domain_id=%d', (did,))
	if domains:
	    self._dbc.execute('DELETE FROM domains WHERE id=%d', (did,))
    def show_head(self):
	"""Show administrative data for domain."""
	print "; zone", self._zone_name
	if self._name == '':
	    print "; domain", self._zone_name
	else:
	    print "; domain", '.'.join((self._name,self._zone_name))
	if self._created_on:
	    print "; created: by %s, %s" % (self._created_by, self._created_on)
	if self._updated_on:
	    print "; updated: by %s, %s" % (self._updated_by, self._updated_on)
	if self._registry_lock: print "; registry_lock"
	if self._registry_hold: print "; registry_hold"
	if self._internal: print "; internal"
    def show_rrs(self):
	"""List all resource records for domain."""
	self._dbc.execute(
	    'SELECT rrs.label,domains.name,rrs.ttl,rrtypes.label,rrs.value '
	    'FROM domains,rrs,rrtypes '
	    'WHERE domains.id=%d AND domains.id=rrs.domain_id '
	    'AND rrtypes.id=rrs.rrtype_id '
	    'ORDER BY domains.name,rrs.label,rrtypes.label,rrs.value',
	    (self._id,))
	lastlabel = ''
	t = self._dbc.fetchone()
	while t:
	    label, dom, ttl, type, val = t

	    # "uncompress"
	    if type in ['CNAME', 'MX', 'NS']: val += '.'

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
	    if ttl == None: ttl = ''
	    else: ttl = str(ttl)

	    print "\t".join((l, ttl, type, val))
	    t = self._dbc.fetchone()
	if self._dbc.rowcount == 0:
	    print '; (NO RECORD)'
    def show(self):
	"""Shorthand to call show_head() then show_rrs()."""
	self.show_head()
	self.show_rrs()
    def set_registry_lock(self, val):
	"""Set value of boolean registry_lock."""
	self._registry_lock = val
	self._dbc.execute('UPDATE domains SET registry_lock=%s WHERE id=%d',
			  (val, self._id))
    def set_registry_hold(self, val):
	"""Set value of boolean registry_hold."""
	self._registry_hold = val
	self._dbc.execute('UPDATE domains SET registry_hold=%s WHERE id=%d',
			  (val, self._id))

class db:
    def __init__(self, dbhandle, nowrite=False):
	self._za = zauth.ZAuth()
	self._dbh = dbhandle
	self._dbc = dbhandle.cursor()
	self._nowrite = nowrite
	self._login_id = None
	# Cache zone data from database
	# XXX: this stuff does not really belong here
	self._zone_id = {}
	self._zone_minlen = {}
	self._zone_maxlen = {}
	self._dbc.execute('SELECT name, id, minlen, maxlen FROM zones')
	t = self._dbc.fetchone()
	while t:
	    name, id, minlen, maxlen = t
	    self._zone_id[name] = id
	    self._zone_minlen[name] = minlen
	    self._zone_maxlen[name] = maxlen
	    t = self._dbc.fetchone()
    def _split(self, domain, zone=None):
	"""Split domain name according to known zones."""
	domain = domain.upper()
	if zone != None:
	    zone = zone.upper()
	    if not zone in self._zone_id:
		return (None, None, None)
	    if domain.endswith('.'+zone):
		dom = domain[:-len(zone)-1]
	    elif domain == zone:
		dom = ''
	    else:
		return (None, None, None)
	    return (dom, zone, self._zone_id[zone])

	n = domain.split('.')
	for i in range(1, len(n)):
	    zone = '.'.join(n[i:])
	    if zone in self._zone_id:
		dom = '.'.join(n[:i])
		return (dom, zone, self._zone_id[zone])
	return (None, None, None)
    def _find(self, domain, zone, wlock=False, raise_nf=True):
	"""Find domain and zone id.

	If not found and raise_nf is True, raise an exception.
	Lock zone and domain for update if wlock is True.
	Return domain_name, zone_name, domain_id, zone_id.
	"""
	d, z, zid = self._split(domain, zone)
	if z == None or zid == None:
	    raise DomainError(DomainError.ZNOTFOUND, domain)
	if wlock:
	    fu = ' FOR UPDATE'
	    _Zone(self._dbc, id=zid, nowrite=self._nowrite).lock()
	else:
	    fu = ''
	self._dbc.execute('SELECT id FROM domains WHERE name=%s AND zone_id=%d'
			  +fu, (d, zid))
	if self._dbc.rowcount == 0:
	    if raise_nf:
		raise DomainError(DomainError.DNOTFOUND, domain)
	    return (d, z, None, zid)
	assert self._dbc.rowcount == 1
	did, = self._dbc.fetchone()
	return (d, z, did, zid)
    def login(self, login):
	"""Login requested user."""
	self._dbc.execute('SELECT id FROM admins WHERE login=%s', (login,))
	if self._dbc.rowcount == 0:
	    raise AccessError('Unknown login', login)
	assert self._dbc.rowcount == 1
	id, = self._dbc.fetchone()
	self._login_id = id
	self._login = login
	return id
    def _check_login_perm(self, zone=None):
	"""Check someone has logged-in and has permission for the zone."""
	if self._login_id == None:
	    raise AccessError('Not logged in')
	if self._nowrite:
	    return
	if zone != None and not self._za.check(zone, self._login):
	    raise AccessError('Not authorized for zone', self._login, zone)
    def logout(self):
	"""Logout current user."""
	self._check_login_perm()
	self._login_id = None
    def show(self, domain, zone):
	"""Show a pretty-printed zone excerpt for domain."""
	d, z, did, zid = self._find(domain, zone)
	self._check_login_perm(z)
	dom = _Domain(self._dbc, did)
	dom.fetch()
	dom.show()
    def delete(self, domain, zone, override_internal=False):
	"""Delete domain.

	domain: FQDN of domain name
	override_internal: if set, allow modifications to internal domains
	"""
	d, z, did, zid = self._find(domain, zone, wlock=True)
	self._check_login_perm(z)
	dom = _Domain(self._dbc, did)
	dom.fetch(wlock=True)
	if dom._registry_lock:
	    raise AccessError(AccessError.DLOCKED)
	if dom._internal and not override_internal:
	    raise AccessError(AccessError.DINTERNAL)
	dom.move_hist(login_id=self._login_id, domains=True)
	_Zone(self._dbc, id=zid, nowrite=self._nowrite).set_updateserial()
	self._dbh.commit()
    def modify(self, domain, zone, type, file, override_internal=False):
	"""Modify domain.

	domain: FQDN of domain name
	file: RR records in zone file format
	type: string; if set, check zone allows this resource-record type
	override_internal: if set, allow modifications to internal domains
	"""
	dname, zname, did, zid = self._find(domain, zone, wlock=True)
	self._check_login_perm(zone)
	z = _Zone(self._dbc, id=zid, name=zname, nowrite=self._nowrite)
	z.checktype(type)
	d = _Domain(self._dbc, id=did, name=dname, zone_name=zname)
	d.fetch(wlock=True)
	if d._registry_lock:
	    raise AccessError(AccessError.DLOCKED)
	if d._internal and not override_internal:
	    raise AccessError(AccessError.DINTERNAL)
	d.move_hist(login_id=self._login_id, domains=False)
	# add new resource records
	d.add_rr(file)
	z.set_updateserial()
	self._dbh.commit()
    def new(self, domain, zone, type, file=None, internal=False):
	"""Create domain.

	domain: full domain name
	file: RR records in zone file format
	type: string; if set, check zone allows this resource-record type
	internal: if set, protect domain from user requests
	"""
	dname, zname, did, zid = self._find(domain, zone, wlock=True, raise_nf=False)
	self._check_login_perm(zname)
	if did != None:
	    raise DomainError(DomainError.DEXISTS, domain)
	z = _Zone(self._dbc, id=zid, name=zname, nowrite=self._nowrite)
	z.checktype(type)
	z.fetch()
	if len(dname) < self._zone_minlen[zname]:
	    raise AccessError(AccessError.DLENSHORT)
	if len(dname) > self._zone_maxlen[zname]:
	    raise AccessError(AccessError.DLENLONG)
	if self._nowrite: return
	self._dbc.execute(
	  'INSERT INTO domains '
	  '(name,zone_id,created_by,created_on,updated_by,updated_on,internal)'
	  ' VALUES (%s,%d,%d,NOW(),%d,NOW(),%s)',
	  (dname, zid, self._login_id, self._login_id, internal))
	self._dbc.execute("SELECT currval('domains_id_seq')")
	assert self._dbc.rowcount == 1
	did, = self._dbc.fetchone()
	# add resource records, if provided
	if file:
	    d = _Domain(self._dbc, id=did, name=dname, zone_name=zname)
	    d.add_rr(file)
	z.set_updateserial()
	self._dbh.commit()
    def set_registry_lock(self, domain, zone, val):
	"""Set registry_lock flag for domain."""
	d, z, did, zid = self._find(domain, zone, wlock=True)
	self._check_login_perm(z)
	if self._nowrite: return
	dom = _Domain(self._dbc, did)
	dom.set_registry_lock(val)
	self._dbh.commit()
    def set_registry_hold(self, domain, zone, val):
	"""Set registry_hold flag for domain."""
	d, z, did, zid = self._find(domain, zone, wlock=True)
	self._check_login_perm(z)
	if self._nowrite: return
	dom = _Domain(self._dbc, did)
	dom.set_registry_hold(val)
	_Zone(self._dbc, id=zid, nowrite=self._nowrite).set_updateserial()
	self._dbh.commit()
    def soa(self, zone):
	"""Update SOA serial for zone if necessary."""
	z = _Zone(self._dbc, name=zone.upper(), nowrite=self._nowrite)
	z.fetch()
	z.soa()
	self._dbh.commit()
    def cat(self, zone):
	"""Output zone file to stdout."""
	z = _Zone(self._dbc, name=zone.upper())
	z.fetch()
	z.cat()
