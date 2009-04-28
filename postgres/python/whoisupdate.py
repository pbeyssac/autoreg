#!/usr/local/bin/python
# $Id$

import psycopg2
import sys

import autoreg.conf
import autoreg.whois.db as whoisdb

def main():
  dbh = psycopg2.connect(autoreg.conf.dbstring)
  w = whoisdb.Main(dbh)

  # to avoid deadlock, read everything on input first
  lines = sys.stdin.readlines()

  if len(sys.argv) >= 2 and sys.argv[1] == '-n':
    # Dry run
    commit = False
  else:
    commit = True

  if w.parsefile(lines, 'ISO-8859-1', commit):
    print "STATUS OK"
  else:
    print "STATUS ERR"

if __name__ == "__main__":
  main()
