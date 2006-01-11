#!/usr/local/bin/python

import psycopg
import os
import sys

import conf
import whoisdb

def reloaddb(dbc, file):
  print "cleaning-up database"
  os.system('date')
  dbc.execute('DELETE FROM domain_contact')
  dbc.execute('DELETE FROM contacts')
  print "cleanup finished"
  os.system('date')
  w = whoisdb.Main(dbc)
  w.parsefile(file)

dbh = psycopg.connect(conf.dbstring)
reloaddb(dbh.cursor(), sys.stdin)
dbh.commit()
