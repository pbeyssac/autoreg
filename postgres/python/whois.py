#!/usr/local/bin/python

import psycopg
import os
import sys

import conf
import whoisdb

a = sys.argv[1]
dbh = psycopg.connect(conf.dbstring)
l = whoisdb.Lookup(dbh.cursor())
for p in l.persons_by_handle(a):
  p.fetch()
  p.display()
for p in l.persons_by_name(a):
  p.fetch()
  p.display()
