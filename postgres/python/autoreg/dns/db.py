#!/usr/local/bin/python
# $Id$

import time

# local modules
import parser
import autoreg.zauth as zauth

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
    NOAUTH = 'Not authorized for zone'
    ILLRR = 'Illegal record type in zone'
    UNKLOGIN = 'Unknown login'
    NOTLOGGED = 'Not logged in'
    pass

class _Zone:
    def __init__(self, dbc, name=None, id=None):
	self._dbc = dbc
	self.name = name
	self.id = id
    def set_updateserial(self):
	"""Mark zone for serial update in SOA."""
	assert self.id != None
	self._updateserial = True
	self._dbc.execute('UPDATE zones SET updateserial=TRUE WHERE id=%d',
			  (self.id,))
    def soa(self):
	"""Update serial for zone in SOA if flagged as such."""
	zid = self.id
	serial = self._soaserial
	assert zid != None and serial != None
	if not self._updateserial: return (False, serial)
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
	if rrtype == None: return
	zid = self.id
	self._dbc.execute('SELECT zone_id,rrtype_id FROM allowed_rr '
		'WHERE allowed_rr.zone_id=%d '
		'AND allowed_rr.rrtype_id='
		'(SELECT id FROM rrtypes WHERE rrtypes.label=%s)',
		(zid, rrtype))
	if self._dbc.rowcount == 1: return
	assert self._dbc.rowcount == 0
	raise AccessError(AccessError.ILLRR, rrtype, zid)
    def cat(self):
	"""Output zone file to stdout."""
	print "; zone name=%s id=%d" % (self.name, self.id)
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
	    (self.id,))

	# Loop over returned rows, printing as we go.
	t = self._dbc.fetchone()
	lastlabel = '@'
	while t:
	    (label, domain, ttl, typ, value) = t
	    # "uncompress"
	    if typ in ['CNAME', 'MX', 'NS']: value += '.'
	    # prepare label
	    if label != '' and domain != '':
		l = label + '.' + domain
	    elif label+domain == '':
		l = self.name + '.'
	    else:
		l = label + domain
	    if l == self.name+'.':
		l = '@'
	    if ttl == None: ttl = ''
	    else: ttl = str(ttl)+'\t'
	    # print line, removing label if possible
	    # for compactness and clarity
	    if l == lastlabel:
		l = ''
	    else:
		lastlabel = l
	    print "%s\t%s%s\t%s" % (l, ttl, typ, value)
	    t = self._dbc.fetchone()
	print "_EU-ORG-END-MARKER\tTXT\t\"%s\"" % self._soaserial
    def lock(self):
	"""Lock zone row for update."""
	assert self.id != None
	self._dbc.execute('SELECT NULL FROM zones WHERE id=%d FOR UPDATE',
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
	  ' VALUES (%s,%d,%d,NOW(),%d,NOW(),%s)',
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
			  'created_by, created_on, updated_by, updated_on '
			  'FROM domains, zones '
			  'WHERE domains.id=%d AND zones.id=domains.zone_id'
			  +fud, (did,))
	if self._dbc.rowcount == 0:
	    raise DomainError('Domain id not found', did)
	assert self._dbc.rowcount == 1
	(self.name, self._zone_name, self._registry_hold, self._registry_lock,
	 self._internal, self._zone_id, self._registrar_id,
	 idcr, self._created_on, idup, self._updated_on) = self._dbc.fetchone()
	# "GRANT SELECT" perms do not allow "SELECT ... FOR UPDATE",
	# hence the request below is done separately from the request above.
	self._dbc.execute('SELECT ad1.login, ad2.login '
			  'FROM admins AS ad1, admins AS ad2 '
			  'WHERE ad1.id=%d AND ad2.id=%d', (idcr, idup))
	assert self._dbc.rowcount == 1
	self._created_by, self._updated_by = self._dbc.fetchone()
	return True
    def add_rr(self, f):
	"""Add resource records to domain from file.

	f: resource records in zone file format
	domain_name, zone_name and domain_id should be set.
	"""
	dom, zone, did = self.name, self._zone_name, self.id
	assert dom != None and zone != None and did != None
	dp = parser.DnsParser()
	# convenient default label if none provided on first line of file
	label = ''
	for l in f:
	    t = dp.parseline(l)
	    if t == None:
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
	    if typ in ['CNAME', 'MX', 'NS']:
		if not value.endswith('.'):
		    raise DomainError(DomainError.NODOT, value)
		value = value[:-1]
	    elif typ in ['A', 'AAAA', 'SRV', 'TXT']:
		pass
	    else:
		raise DomainError(DomainError.RRUNSUP, typ)
	    self._dbc.execute('INSERT INTO rrs '
		'(domain_id,label,ttl,rrtype_id,value) '
		'VALUES (%d,%s,%s,(SELECT id FROM rrtypes WHERE label=%s),%s)',
		(did, label, ttl, typ, value))
    def set_updated_by(self, login_id):
        """Set updated_by and updated_on."""
        self._dbc.execute('UPDATE domains '
                          'SET updated_by=%d, updated_on=NOW() '
                          'WHERE id=%d', (login_id, self.id))
    def move_hist(self, login_id, domains=False):
	"""Move resource records to history tables, as a side effect
	(triggers) of deleting them.

	domains: if set, also move domain and associated contact records.
	"""
	did = self.id
	self._dbc.execute('DELETE FROM rrs WHERE domain_id=%d', (did,))
	if domains:
	    self._dbc.execute('DELETE FROM domains WHERE id=%d', (did,))
    def show_head(self):
	"""Show administrative data for domain."""
	print "; zone", self._zone_name
	if self.name == '':
	    print "; domain", self._zone_name
	else:
	    print "; domain", '.'.join((self.name,self._zone_name))
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
	    (self.id,))
	lastlabel = ''
	t = self._dbc.fetchone()
	while t:
	    label, dom, ttl, typ, val = t

	    # "uncompress"
	    if typ in ['CNAME', 'MX', 'NS']: val += '.'

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

	    print "\t".join((l, ttl, typ, val))
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
			  (val, self.id))
    def set_registry_hold(self, val):
	"""Set value of boolean registry_hold."""
	self._registry_hold = val
	self._dbc.execute('UPDATE domains SET registry_hold=%s WHERE id=%d',
			  (val, self.id))

class _ZoneList:
    """Cache zone list from database."""
    def __init__(self, dbc):
        self._dbc = dbc
	self.zones = {}
	self._dbc.execute('SELECT name, id FROM zones')
	t = self._dbc.fetchone()
	while t:
	    name, zid = t
	    self.zones[name] = _Zone(dbc, id=zid, name=name)
	    t = self._dbc.fetchone()
    def split(self, domain, zone=None):
	"""Split domain name according to known zones."""
	domain = domain.upper()
	if zone != None:
            # zone name is provided, just check it exists
	    zone = zone.upper()
	    if not zone in self.zones:
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
	if z == None:
	    raise DomainError(DomainError.ZNOTFOUND, domain)
	if wlock:
	    fu = ' FOR UPDATE'
	    z.lock()
	else:
	    fu = ''
	self._dbc.execute('SELECT id FROM domains WHERE name=%s AND zone_id=%d'
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
	self._za = zauth.ZAuth()
	self._dbh = dbhandle
	self._dbc = dbhandle.cursor()
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
	if self._login_id == None:
	    raise AccessError(AccessError.NOTLOGGED)
	if self._nowrite:
	    return
	if zone != None and not self._za.check(zone, self._login):
	    raise AccessError(AccessError.NOAUTH, self._login, zone)
    def logout(self):
	"""Logout current user."""
	self._check_login_perm()
	self._login_id = None
    def show(self, domain, zone):
	"""Show a pretty-printed zone excerpt for domain."""
	d, z = self._zl.find(domain, zone)
	self._check_login_perm(z.name)
	d.fetch()
	d.show()
    def delete(self, domain, zone, override_internal=False):
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
	if self._nowrite: return
	d.move_hist(login_id=self._login_id, domains=True)
	z.set_updateserial()
	self._dbh.commit()
    def modify(self, domain, zone, typ, file, override_internal=False):
	"""Modify domain.

	domain: FQDN of domain name
	file: RR records in zone file format
	typ: string; if set, check zone allows this resource-record type
	override_internal: if set, allow modifications to internal domains
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
	d.move_hist(login_id=self._login_id, domains=False)
	# add new resource records
	d.add_rr(file)
	d.set_updated_by(self._login_id)
	z.set_updateserial()
	self._dbh.commit()
    def new(self, domain, zone, typ, file=None, internal=False):
	"""Create domain.

	domain: full domain name
	file: RR records in zone file format
	typ: string; if set, check zone allows this resource-record type
	internal: if set, protect domain from user requests and bypass
		length checks.
	"""
	d, z = self._zl.find(domain, zone, wlock=True, raise_nf=False)
	self._check_login_perm(z.name)
	if d.id != None:
	    raise DomainError(DomainError.DEXISTS, domain)
	z.checktype(typ)
	z.fetch()
	if len(d.name) < z.minlen and not internal:
	    raise AccessError(AccessError.DLENSHORT, (domain, z.minlen))
	if len(d.name) > z.maxlen and not internal:
	    raise AccessError(AccessError.DLENLONG, (domain, z.maxlen))
	if self._nowrite: return
        d.new(z, self._login_id, internal)
	# add resource records, if provided
	if file:
	    d.add_rr(file)
	z.set_updateserial()
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
    def soa(self, zone):
	"""Update SOA serial for zone if necessary."""
	z = self._zl.zones[zone.upper()]
	z.fetch()
	(r, serial) = z.soa()
	self._dbh.commit()
        return r, serial
    def cat(self, zone):
	"""Output zone file to stdout."""
	z = self._zl.zones[zone.upper()]
	z.fetch()
	z.cat()
