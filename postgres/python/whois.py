#!/usr/local/bin/python

import psycopg
import os
import sys

import conf
import whoisdb

a = sys.argv[1]
dbh = psycopg.connect(conf.dbstring)
l = whoisdb.Lookup(dbh.cursor())

d = l.domain_by_name(a)
if d != None:
  dc = d.get_contacts()
  d.display()
  print
  pdone = []
  for k in ['technical', 'administrative', 'zone']:
    if not k in dc:
      continue
    for p in dc[k]:
      if not p.key in pdone:
        p.fetch()
        p.display()
        pdone.append(p.key)
        print
  sys.exit(0)

lp = l.persons_by_handle(a)
if not lp:
  lp = l.persons_by_name(a)
if not lp:
  print "Key not found"
  sys.exit(1)

for p in lp:
  p.fetch()
  p.display()
  print
