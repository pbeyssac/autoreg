#!/usr/local/bin/python

from __future__ import absolute_import
from __future__ import unicode_literals
from __future__ import print_function


import getopt
import io
import os
import pwd
import socket
import sys


import dns.exception
import dns.name
import dns.query
import dns.rdatatype
import psycopg2


import autoreg.conf
import autoreg.dns.access
import autoreg.dns.db
import autoreg.dns.parser


def axfr(nameserver, domain, default_ttl, dry_run=True):
  ns = socket.gethostbyname(nameserver)

  domain = domain.upper()
  if not domain.endswith('.'):
    domain += '.'

  q = dns.query.xfr(ns, domain)

  p = autoreg.dns.parser.DnsParser()

  lasttype = None
  lastlabel = None
  lastdom = None
  curdom = None
  gotsoa = False

  origin = dns.name.Name(domain.split('.'))

  rrs = io.StringIO()

  dbh = psycopg2.connect(autoreg.conf.dbstring)
  print("autocommit", dbh.autocommit)
  dbh.autocommit = False
  dd = autoreg.dns.db.db(dbh, nowrite=False)

  dd.login('autoreg')

  for m in q:
    for rrset in m.answer:
      # skip DNSSEC records
      if rrset.rdtype in [dns.rdatatype.DNSKEY,
                          dns.rdatatype.RRSIG,
                          dns.rdatatype.NSEC,
                          dns.rdatatype.NSEC3PARAM,
                          dns.rdatatype.NSEC3]:
        continue
      lasttype = rrset.rdtype
      lastrrs = rrset
      if rrset.rdtype == dns.rdatatype.SOA:
        if gotsoa:
          continue
        gotsoa = True
      line = rrset.to_text(origin=origin, relativize=False)

      for line1 in line.split('\n'):
        label, ttl, type, args = p.parse1line(line1)
        ttl = int(ttl)
        if label.endswith('.'+domain):
          label = label[:-1-len(domain)]
          if '.' in label:
            curdom = label.rsplit('.', 1)[1]
          else:
            curdom = label

        if lastdom != curdom and curdom:
          # check ascending order
          if lastdom and lastdom > curdom:
            print(lastdom, "followed by", curdom, "not ascending, aborting")
            return 1
          print("; ", lastdom)
          print(rrs.getvalue(), end='')

          rrs.seek(0)
          if lastdom is None:
            # records at the apex of the domain, except for the SOA.
            dd.new(domain[:-1], domain[:-1], typ=None,
                   file=rrs, internal=True, commit=False)
          else:
            dd.new(lastdom+'.'+domain[:-1], domain[:-1], typ=None,
                   file=rrs, internal=False, commit=False)
          lastdom = curdom
          rrs = io.StringIO()

        if lastlabel != label:
          #print(label, end='', file=rrs)
          lastlabel = label
        else:
          print('\t', end='', file=rrs)
        if ttl != default_ttl:
          print('\t%s' % ttl, end='', file=rrs)
        print('\t', type, args, file=rrs)

        if type == 'SOA':
          args = args.split()
          args[2:] = [int(i) for i in args[2:]]
          master, email, serial, refresh, retry, expire, \
          minimum = args
          print("newzone", domain[:-1], master[:-1], email[:-1])
          dd.newzone(domain[:-1], master[:-1], email[:-1],
                     soaserial=serial, soarefresh=refresh,
                     soaretry=retry, soaexpires=expire,
                     soaminimum=minimum,
                     commit=False)

  if lasttype != dns.rdatatype.SOA:
    print("AXFR is incomplete, aborting")
    dbh.cancel()
    return 1

  print("; ", curdom)
  print(rrs.getvalue(), end='')
  rrs.seek(0)
  dd.new(curdom+'.'+domain[:-1], domain[:-1], typ=None,
         file=rrs, internal=False, commit=False)

  records = io.StringIO('\tTXT\t"end mark"')
  dd.new('_END-MARK.'+domain[:-1], domain[:-1], typ=None,
         file=records, internal=True, commit=False)

  if not dry_run:
    dbh.commit()
    filename = os.path.join(autoreg.conf.ZONEFILES_DIR, domain[:-1])
    with open(filename, 'w+') as file:
      dd.cat(domain[:-1], outfile=file)
  else:
    dbh.cancel()

def transfer(argv=sys.argv):
  try:
    opts, args = getopt.getopt(argv[1:], "n")
  except getopt.GetoptError:
    usage()
    return 1

  dry_run = False

  for o, a in opts:
      if o == "-n":
        dry_run = True

  if len(args) == 3:
    default_ttl = int(args[2])
  else:
    default_ttl = 86400
  axfr(args[0], args[1], default_ttl, dry_run=dry_run)


def create():
  if len(sys.argv) != 2:
    print("Usage: %s domain" % sys.argv[0])
    return 1
  domain = sys.argv[1].upper()

  pwent = pwd.getpwnam('autoreg')
  if os.getuid() != pwent.pw_uid:
    print("Please run as user autoreg")
    return 1

  exitcode = autoreg.dns.access.main(['access-zone', '-anewzone', domain])
  if exitcode != 0:
    return 1

  filename = os.path.join(autoreg.conf.ZONEFILES_DIR, domain)
  with open(filename, 'w+') as file:
    autoreg.dns.access.main(['access-zone', '-acat', domain], outfile=file)

  dbh = psycopg2.connect(autoreg.conf.dbstring)
  dbc = dbh.cursor()
  dbc.execute("INSERT INTO admin_zone"
              " SELECT id AS admin_id, "
                      "(SELECT id FROM zones WHERE name = %s) AS zone_id"
              " FROM admins WHERE admins.id != 0", (domain.upper()));
  nadm = dbc.rowcount
  dbh.commit()
  print('Allowed zone %s to %d administrators' % (domain, nadm))

  print('Add the following to your BIND configuration file:')
  print('zone "%s" { type master; file \"%s\"; allow-transfer {}; };'
        % (domain, filename))
  print("Then run 'rndc reconfig'")


if __name__ == "__main__":
    transfer()
