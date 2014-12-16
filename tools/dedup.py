#!/usr/local/bin/python
# $Id$

from __future__ import print_function

import getopt
import sys

import psycopg2

import autoreg.conf

#dbstring = 'dbname=eudevel'
dbstring = autoreg.conf.dbstring

def usage(argv):
  print("Usage: %s" % argv[0])

def main():
  dbh = psycopg2.connect(dbstring)
  dbc = dbh.cursor()

  try:
    optlist, args = getopt.getopt(sys.argv[1:], 'Une:')
  except getopt.GetoptError as err:
    print(str(err))
    usage(sys.argv)
    sys.exit(2)

  commit = True
  for opt, val in optlist:
    if opt == '-n':
      # Dry run
      commit = False

  dbc.execute("SELECT tmp.fqdn, tmp.count FROM (SELECT fqdn, count(fqdn) FROM requests WHERE state != 'WaitAck' GROUP BY fqdn ORDER BY fqdn) AS tmp WHERE tmp.count > 1 ORDER BY count ASC")
  dom = dbc.fetchall()
  doms = []
  sum = 0
  for fqdn, count in dom:
    doms.append(fqdn)
    sum += count
  print("Sum:", sum)

  dup = 0
  dels = 0
  for fqdn in doms:
    dbc.execute("SELECT id, email, action, state, zonerecord, whoisrecord FROM requests WHERE fqdn=%s ORDER BY id", (fqdn,))
    rq = dbc.fetchall()
    oemail, oaction, ostate, ozonerecord, owhoisrecord \
	= None, None, None, None, None
    rqdel = []
    rqtuples = []
    for id, email, action, state, zonerecord, whoisrecord in rq:
      ntuple = (email, action, state, zonerecord, whoisrecord)
      for oid, otuple in rqtuples:
        if otuple == ntuple:
          print(oid, '==', id, fqdn)
          rqdel.append(id)
          break
        if otuple[:3] == ntuple[:3] and otuple[-1] == ntuple[-1]:
          print(oid, 'DNS diff', id, fqdn)
          print(otuple[3])
          print(ntuple[3])
          if oid not in rqdel:
            rqdel.append(oid)
          break
      else:
        rqtuples.append((id, ntuple))
    if rqdel:
      print("DEL", fqdn, rqdel)
      for id in rqdel:
        print("Deleting", id)
        #dbc.execute("UPDATE requests SET state='Rej' WHERE id=%s", (id,))
        #dbc.execute("DELETE FROM requests WHERE id=%s", (id,))
        #dbh.commit()
        dels += 1
  print("Dels", dels, "Dups", dup)

if __name__ == "__main__":
  main()
