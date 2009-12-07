#!/usr/local/bin/python
# $Id$
#

"""Usage:
	access-zone [-ci] [-t type] [-z zone] [-u user] -a action domainname

-c: check only, don't update any file (used for request check)
-a: action, one of:
	new:	create the entry for domainname in the parent zone,
		if not already there; use resource records on stdin.
	modify: modify the entry for domainname in the parent zone,
		if already there; use resource records on stdin.
	delete: delete the entry for domainname in the parent zone,
		if already there.
	cat:	print the zone file on stdout.
	soa:	update the SOA serial for domainname in the zonefile of
		the same name, if the file has previously changed
		due to one of the above actions.
		Print the serial in any case.
	show:	display entry for domainname.
        hold:	put domain on hold.
        unhold:	unhold domain.
        lock:	protect domain from 'modify' or 'delete' unless forced with -i.
        unlock:	unprotect domain.
	list:	show list of known zones.

-u: username, used to check access permissions with respect to the
    zones-auth config file. Defaults to USER environment variable.
-t: type of resource record (for 'new' or 'modify'), checked with respect to
    allowed record types in the zone.
-z: specify zone, in case there is an ambiguity with respect to handled zones.
-i: in 'modify' and 'delete', allow handling of "internal" domains.
    in 'new', set "internal" flag.
"""

# standard modules
import getopt
import logging
import os
import psycopg2
import sys

# local modules
import autoreg
import autoreg.conf as conf
import autoreg.dns
import autoreg.dns.db as dnsdb
import autoreg.msg as msg

logging.basicConfig(filename='/tmp/access-zone.log', filemode='a+',
		    format='%(asctime)s %(levelname)-8s %(message)s',
		    datefmt="%Y%m%d %H:%M:%S")

action_list = ['cat', 'delete', 'lock', 'modify', 'unlock',
		'hold', 'unhold',
		'new', 'show', 'soa', 'list']
def usage():
    print >> sys.stderr, __doc__

def errexit(msg, args):
    """Print a formatted error message on stderr and exit(1)."""
    print >> sys.stderr, amsg.f(msg, args),
    sys.exit(1)

try:
    opts, args = getopt.getopt(sys.argv[1:], "a:cit:u:z:")
except getopt.GetoptError:
    usage()
    sys.exit(1)

action, type, zone = None, None, None
nowrite, internal = False, False
user = os.getenv('USER', None)
lang = os.getenv('LANG', '')

amsg = msg.Msg('msg-access', lang)

for o, a in opts:
    if o == "-a":
	action = a.lower()
    elif o == "-c":
	nowrite = True
	user = 'DNSADMIN'
    elif o == "-i":
	internal = True
    elif o == "-t":
	type = a.upper()
    elif o == "-u":
	user = a
    elif o == "-z":
	zone = a.upper()

if action == None or user == None:
    usage()
    sys.exit(1)
if action == 'list':
    if len(args) != 0:
        usage()
        sys.exit(1)
    domain = None
elif len(args) != 1:
    usage()
    sys.exit(1)
else:
    domain = args[0].upper()

if action.startswith('n'): action='new'
elif action.startswith('m'): action='modify'
elif action.startswith('d'): action='delete'

if action not in action_list:
    usage()
    sys.exit(1)

dbh = psycopg2.connect(conf.dbstring)
dd = dnsdb.db(dbh, nowrite)

dd.login(user)

r = 0
try:
  if action == 'show':
    dd.show(domain, zone)
  elif action == 'new':
    dd.new(domain, zone, type, file=sys.stdin, internal=internal)
  elif action == 'modify':
    dd.modify(domain, zone, type, file=sys.stdin, override_internal=internal)
  elif action == 'delete':
    dd.delete(domain, zone, override_internal=internal)
  elif action == 'lock':
    dd.set_registry_lock(domain, zone, True)
  elif action == 'unlock':
    dd.set_registry_lock(domain, zone, False)
  elif action == 'hold':
    dd.set_registry_hold(domain, zone, True)
  elif action == 'unhold':
    dd.set_registry_hold(domain, zone, False)
  elif action == 'cat':
    dd.cat(domain)
  elif action == 'soa':
    (updated, serial) = dd.soa(domain)
    if not updated:
	r = 1
    print serial
  elif action == 'list':
    for zone in dd.zonelist():
        print zone
  else:
    usage()
    r = 1
except dnsdb.AccessError, e:
  if e.args[0] == dnsdb.AccessError.NOAUTH:
    errexit('MSG_NUSER', (user))
  if e.args[0] == dnsdb.AccessError.UNKLOGIN:
    errexit('MSG_NUSER', (user))
  if e.args[0] == dnsdb.AccessError.NOTLOGGED:
    errexit('MSG_NUSER', (user))
  if e.args[0] == dnsdb.AccessError.DLOCKED:
    errexit('MSG_LOCKD', (domain))
  if e.args[0] == dnsdb.AccessError.DINTERNAL:
    errexit('MSG_LOCKD', (domain))
  if e.args[0] == dnsdb.AccessError.ILLRR:
    errexit('MSG_NOTYP', (type))
  if e.args[0] == dnsdb.AccessError.DLENSHORT:
    errexit('MSG_SHORT', e.args[1])
  if e.args[0] == dnsdb.AccessError.DLENLONG:
    errexit('MSG_LONG', e.args[1])
  logging.exception("Unexpected exception in access-zone:\n")
  logging.error("variables:\n%s", str(locals()))
  raise
except dnsdb.DomainError, e:
  if e.args[0] == dnsdb.DomainError.DNOTFOUND:
    errexit('MSG_NODOM', (domain, action))
  if e.args[0] == dnsdb.DomainError.ZNOTFOUND:
    errexit('MSG_NODOM', (domain, action))
  if e.args[0] == dnsdb.DomainError.DEXISTS:
    errexit('MSG_ALLOC', (domain))
  logging.exception("Unexpected exception in access-zone:\n")
  logging.error("variables:\n%s", str(locals()))
  raise
except:
  logging.exception("Unexpected exception in access-zone:\n")
  logging.error("variables:\n%s", str(locals()))
  raise
else:
  sys.exit(r)
