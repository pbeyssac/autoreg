#!/usr/local/bin/python
# $Id$
#

"""Usage:
        access-zone [-cdi] [-t type] [-z zone] [-u user] -a action [domainname]

-c: check only, don't update any file (used for request check)
-a: action, one of:
        new:	create the entry for domainname in the parent zone,
                if not already there; use resource records on stdin.
        modify: modify the entry for domainname in the parent zone,
                if already there; use resource records on stdin.
        modnods: same as 'modify', but keep existing DS records for the zone.
        delete: delete domain, respecting grace period.
        undelete: undelete domain.
        cat:	print the zone file on stdout.
        soa:	update the SOA serial for domainname in the zonefile of
                the same name, if any update in the zone occurred.
                Print the serial in any case.
        show:	display entry for domainname.
        showstubs:	display delegation data for all zones.
        cmpstubs:	check consistency of delegation data for all zones.
        hold:	put domain(s) on hold.
        unhold:	unhold domain(s).
        lock:	protect domain(s) from 'modify' or 'delete'
                unless forced with -i.
        unlock:	unprotect domain(s).
        list:	show list of known zones.
        newzone:	create a new zone.
        addrr:	add resource records
        delrr:	delete resource records
        expire:	list expired domains

'hold', 'unhold', 'lock', 'unlock' can work on a stdin-provided
domain list for better performance.

-d: in 'modify', 'addrr', 'delrr', 'show': apply both on the domain
    and the parent zone.
-u: username, used to check access permissions with respect to the
    zone permissions. Defaults to USER environment variable.
-t: type of resource record (for 'new' or 'modify'), checked with respect to
    allowed record types in the zone.
-z: specify zone, in case there is an ambiguity with respect to handled zones.
-i: in 'modify' and 'delete', allow handling of "internal" domains.
    in 'new', set "internal" flag.
-s: force incrementation of serial in 'soa', regardless of any zone updates.
"""

from __future__ import absolute_import
from __future__ import print_function
from __future__ import unicode_literals

# standard modules
import difflib
import getopt
import io
import logging
import os
import psycopg2
import sys


import six


# local modules
import autoreg
import autoreg.conf as conf
import autoreg.dns
import autoreg.dns.db as dnsdb

logging.basicConfig(filename='/tmp/access-zone.log', filemode='a+',
                    format='%(asctime)s %(levelname)-8s %(message)s',
                    datefmt="%Y%m%d %H:%M:%S")

action_list = ['addrr', 'cat', 'delete', 'undelete',
                'delrr', 'lock', 'modify', 'unlock',
                'hold', 'unhold',
                'new', 'show', 'soa', 'list', 'showstubs', 'cmpstubs',
                'newzone', 'expire']

MSG_ALLOC="Error: domain %s is already allocated."
MSG_SHORT="Error: minimal length for subdomains in %s is %d."
MSG_LONG="Error: maximal length for subdomains in %s is %d."
MSG_LOCKD="Error: domain %s is locked."
MSG_EXIST="Error: domain %s already exists, cannot create."
MSG_NODOM="Error: domain %s not found, cannot %s."
MSG_NOTYP="Error: %s records are not permitted in this zone."
MSG_NUSER="Error: user %s is not permitted to modify zone."

def usage():
    print(__doc__, file=sys.stderr)

def errexit(msg, args):
    """Print a formatted error message on stderr and exit(1)."""
    print(msg % args, file=sys.stderr)
    sys.exit(1)

def main(argv=sys.argv, infile=sys.stdin, outfile=sys.stdout):
  try:
      opts, args = getopt.getopt(argv[1:], "a:cdist:u:z:")
  except getopt.GetoptError:
      usage()
      sys.exit(1)

  action, type, zone = None, None, None
  keepds = False
  nowrite, internal, deleg, forceincr = False, False, False, False
  user = os.getenv('USER', None)
  lang = os.getenv('LANG', '')

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
      elif o == "-d":
        deleg = True
      elif o == "-s":
        forceincr = True

  if action == None or user == None:
      usage()
      return 1
  if action == 'hold' or action == 'unhold' \
     or action == 'lock' or action == 'unlock':
      if len(args) == 0:
        domainlist = [line[:-1].upper() for line in infile.readlines()]
      elif len(args) == 1:
        domainlist = [args[0].upper()]
      else:
        usage()
        return 1
  elif action == 'list' or action == 'showstubs' or action == 'cmpstubs' \
      or action == 'expire':
      if len(args) != 0:
          usage()
          return 1
      domain = None
  elif len(args) != 1:
      usage()
      return 1
  else:
      domain = args[0].upper()

  if action == 'modnods':
    action = 'modify'
    keepds = True
  elif action == 'mod':
    action = 'modify'

  if action not in action_list:
      usage()
      return 1

  dbh = psycopg2.connect(conf.dbstring)
  dd = dnsdb.db(dbh, nowrite)

  dd.login(user)

  if deleg and '.' in domain:
    dummy, zone = domain.split('.', 1)

  r = 0
  try:
    if action == 'show':
      dd.show(domain, zone)
      if deleg:
        dd.show(domain, domain)
    elif action == 'new':
      dd.new(domain, zone, type, file=sys.stdin, internal=internal)
    elif action == 'modify':
      if deleg:
        dd.modifydeleg(domain, file=sys.stdin, override_internal=internal,
                       keepds=keepds)
      else:
        dd.modify(domain, zone, type, file=sys.stdin, override_internal=internal,
                  keepds=keepds)
    elif action == 'addrr':
      if deleg:
        dd.modifydeleg(domain, file=sys.stdin, override_internal=internal,
                    replace=False)
      else:
        dd.modify(domain, zone, type, file=sys.stdin, override_internal=internal,
                replace=False)
    elif action == 'delrr':
      if deleg:
        dd.modifydeleg(domain, file=sys.stdin, override_internal=internal,
                     replace=False, delete=True)
      else:
        dd.modify(domain, zone, type, file=sys.stdin, override_internal=internal,
                replace=False, delete=True)
    elif action == 'delete':
      dd.delete(domain, zone, override_internal=internal)
    elif action == 'undelete':
      dd.undelete(domain, zone, override_internal=internal)
    elif action == 'lock':
      for domain in domainlist:
        dd.set_registry_lock(domain, zone, True)
    elif action == 'unlock':
      for domain in domainlist:
        dd.set_registry_lock(domain, zone, False)
    elif action == 'hold':
      for domain in domainlist:
        dd.set_registry_hold(domain, zone, True)
    elif action == 'unhold':
      for domain in domainlist:
        dd.set_registry_hold(domain, zone, False)
    elif action == 'cat':
      dd.cat(domain, outfile=outfile)
    elif action == 'soa':
      (updated, serial) = dd.soa(domain, forceincr)
      if not updated:
        r = 1
      print(serial, file=outfile)
    elif action == 'list':
      for zone in dd.zonelist():
          print(zone, file=outfile)
    elif action == 'showstubs':
      zones = dd.zonelist()
      for domain in zones:
        dummy, zone = domain.split('.', 1)
        if zone in zones:
          dd.show(domain, zone)
        dd.show(domain, domain)
    elif action == 'cmpstubs':
      zones = dd.zonelist()
      for domain in zones:
        dummy, zone = domain.split('.', 1)
        if zone not in zones:
          continue
        parent_out = io.StringIO()
        zone_out = io.StringIO()
        dd.show(domain, six.text_type(zone), rrs_only=True, outfile=parent_out)
        dd.show(domain, six.text_type(domain), rrs_only=True, outfile=zone_out)
        p_out = parent_out.getvalue().split('\n')

        # drop initial label in parent zone
        if not p_out[0].startswith('\t'):
          p_out[0] = '\t' + p_out[0].split('\t', 1)[1]

        # drop DS records in parent zone
        p_out = [line for line in p_out if '\tDS\t' not in line]

        z_out = zone_out.getvalue().split('\n')
        if p_out != z_out:
          print(zone, domain, 'differ', file=outfile)
          for line in difflib.unified_diff(p_out, z_out,
                                           fromfile='parent zone '+zone,
                                           tofile='zone '+domain,
                                           lineterm=''):
            print(line, file=outfile)
    elif action == 'newzone':
      dd.newzone(domain, autoreg.conf.SOA_MASTER, autoreg.conf.SOA_EMAIL)

      if '.' in domain:
        dummy, parent = domain.split('.', 1)
      else:
        parent = None

      dd.login('autoreg')

      records = io.StringIO('\tNS\t' + autoreg.conf.SOA_MASTER + '.')
      dd.new(domain, domain, typ=None, file=records, internal=True)

      records = io.StringIO('\tTXT\t"end mark"')
      dd.new('_END-MARK.'+domain, domain, typ=None,
             file=records, internal=True)

      if parent in dd.zonelist():
        records = io.StringIO('\tNS\t' + autoreg.conf.SOA_MASTER + '.')
        dd.new(domain, parent, typ=None, file=records, internal=True)

    elif action == 'expire':
      for dom, zone, dateexp in dd.expired():
        print('%s %s.%s' % (dateexp, dom, zone), file=outfile)
    else:
      usage()
      r = 1
  except dnsdb.AccessError as e:
    if e.args[0] == dnsdb.AccessError.NOAUTH:
      return errexit(MSG_NUSER, (user))
    if e.args[0] == dnsdb.AccessError.UNKLOGIN:
      return errexit(MSG_NUSER, (user))
    if e.args[0] == dnsdb.AccessError.NOTLOGGED:
      return errexit(MSG_NUSER, (user))
    if e.args[0] == dnsdb.AccessError.DLOCKED:
      return errexit(MSG_LOCKD, (domain))
    if e.args[0] == dnsdb.AccessError.DINTERNAL:
      return errexit(MSG_LOCKD, (domain))
    if e.args[0] == dnsdb.AccessError.ILLRR:
      return errexit(MSG_NOTYP, (type))
    if e.args[0] == dnsdb.AccessError.DLENSHORT:
      return errexit(MSG_SHORT, e.args[1])
    if e.args[0] == dnsdb.AccessError.DLENLONG:
      return errexit(MSG_LONG, e.args[1])
    logging.exception("Unexpected exception in access-zone:\n")
    logging.error("variables:\n%s", str(locals()))
    raise
  except dnsdb.DomainError as e:
    if e.args[0] == dnsdb.DomainError.DNOTFOUND:
      return errexit(MSG_NODOM, (domain, action))
    if e.args[0] == dnsdb.DomainError.ZNOTFOUND:
      return errexit(MSG_NODOM, (domain, action))
    if e.args[0] == dnsdb.DomainError.DEXISTS:
      return errexit(MSG_ALLOC, (domain))
    logging.exception("Unexpected exception in access-zone:\n")
    logging.error("variables:\n%s", str(locals()))
    raise
  except:
    logging.exception("Unexpected exception in access-zone:\n")
    logging.error("variables:\n%s", str(locals()))
    raise
  else:
    return r

if __name__ == "__main__":
  main()
