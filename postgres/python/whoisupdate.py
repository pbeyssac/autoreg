#!/usr/local/bin/python
# $Id$

import getopt
import sys

import psycopg2

import autoreg.conf
import autoreg.whois.db as whoisdb

def usage(argv):
  print "Usage: %s [-e encoding] [-n]" % argv[0]

def main():
  encoding = 'ISO-8859-1'

  dbh = psycopg2.connect(autoreg.conf.dbstring)
  w = whoisdb.Main(dbh)

  try:
    optlist, args = getopt.getopt(sys.argv[1:], 'ne:')
  except getopt.GetoptError, err:
    print str(err)
    usage(sys.argv)
    sys.exit(2)

  commit = True
  for opt, val in optlist:
    if opt == '-n':
      # Dry run
      commit = False
    elif opt == '-e':
      encoding = val

  # to avoid deadlock, read everything on input first
  lines = sys.stdin.readlines()

  if w.parsefile(lines, encoding, commit):
    print "STATUS OK"
  else:
    print "STATUS ERR"

if __name__ == "__main__":
  main()
