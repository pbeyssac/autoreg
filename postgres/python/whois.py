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
  d.get_contacts()
  d.display()
  print
for p in l.persons_by_handle(a):
  p.fetch()
  p.display()
  print
for p in l.persons_by_name(a):
  p.fetch()
  p.display()
  print
