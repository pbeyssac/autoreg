#!/usr/bin/env python
# $Id$
#
# Usage:
#  access-zone [-c] [-t type] -u user
#		-a{cat|soa|new|modify|delete|show} domainname
#
# -c -> check only, don't update any file (used for request check)
# -a -> action.
#		cat:	just print out the zone file
#		new:	create the entry for domainname in the parent zone,
#			if not already there
#		modify: modify the entry for domainname in the parent zone,
#			if already there
#		delete: delete the entry for domainname in the parent zone,
#			if already there
#		soa:	update the SOA for domainname in the zonefile of
#			the same name, if the file has previously changed
#			with one of the above actions
#		show:	display the entry for domainname in the parent zone
#
# -u -> username, used to check access permissions with respect to the
#	zones-auth config file
# -t -> type of record (for "new" or "modify"), checked with respect to
#	the types of allowed records in the zone.
# -z -> domainname is a zone name, access records related to the zone itself.
# -i -> in 'modify' and 'delete', allow handling of "internal" domains.
#	in 'new', set "internal" flag.
#
# For actions "new" and "modify", the records to be inserted are provided
# on stdin.
#

# standard modules
import getopt
import os
import psycopg
import sys

# local modules
import conf
import dnsdb
import msg

action_list = ['cat', 'delete', 'lock', 'modify', 'unlock',
		'new', 'show', 'soa']
def usage():
    print >> sys.stderr, "Usage: access-zone -a action -u user [-t type] [-ci] [-z zone] domain"

try:
    opts, args = getopt.getopt(sys.argv[1:], "a:cit:u:z:")
except getopt.GetoptError:
    usage()
    sys.exit(1)

action, type, zone = None, None, None
nowrite, internal = False, False
user = os.getenv('USER', None)
lang=os.getenv('LANG', '')

amsg = msg.Msg('msg-access', lang)

for o, a in opts:
    if o == "-a":
	action = a.lower()
    elif o == "-c":
	nowrite = True
    elif o == "-i":
	internal = True
    elif o == "-t":
	type = a.upper()
    elif o == "-u":
	user = a
    elif o == "-z":
	zone = a.upper()

if action == None or user == None or len(args) != 1:
    usage()
    sys.exit(1)

if action.startswith('n'): action='new'
elif action.startswith('m'): action='modify'
elif action.startswith('d'): action='delete'

if action not in action_list:
    usage()
    sys.exit(1)

dbh = psycopg.connect(conf.dbstring)
dd = dnsdb.db(dbh, nowrite)

domain = args[0].upper()

dd.login(user)

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
  elif action == 'cat':
    dd.cat(domain)
  elif action == 'soa':
    dd.soa(domain)
  else:
    usage()
    sys.exit(1)
except dnsdb.DomainError, e:
    if e.args[0] == dnsdb.DomainError.DNOTFOUND:
	print >> sys.stderr, amsg.f('MSG_NODOM', (domain, action)),
	sys.exit(1)
