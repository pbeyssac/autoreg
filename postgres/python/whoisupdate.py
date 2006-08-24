#!/usr/local/bin/python
# $Id$

import psycopg
import sys

import conf
import whoisdb

def main():
  dbh = psycopg.connect(conf.dbstring)
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
